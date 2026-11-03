"""Unit and integration tests for Phase 2-4 upgrades:
- New free OSINT adapters (RDAP, InternetDB, HackerTarget, Amass)
- Upgraded DNS posture (DKIM, MTA-STS, TLS-RPT, DMARC rua/pct, TLS cert)
- Upgraded Company Web extraction (title, description, social links, tech stack)
- A-F Security Posture Grading & Prioritized Exposures
- Workspace /api/settings and multi-entity (IP, username, phone, person) runs
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from neesha.adapters.amass import AmassAdapter
from neesha.adapters.base import RawResult, Request
from neesha.adapters.company_web import CompanyWebAdapter
from neesha.adapters.dns_posture import DnsPostureAdapter
from neesha.adapters.hackertarget import HackerTargetAdapter
from neesha.adapters.internetdb import InternetDbAdapter
from neesha.adapters.rdap import RdapAdapter
from neesha.harness.brief import build_brief, write_brief
from neesha.harness.gate import EngagementView, PolicyGate
from neesha.harness.run import execute_run
from neesha.harness.scoring import grade_brief_posture
from neesha.ledger.ledger import Ledger


def test_rdap_adapter_parses_domain_and_ip_registration():
    adapter = RdapAdapter()
    domain_payload = {
        "ldhName": "example.com",
        "status": ["client transfer prohibited", "server delete prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
        ],
        "nameservers": [{"ldhName": "a.iana-servers.net"}, {"ldhName": "b.iana-servers.net"}],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]],
            }
        ],
    }
    raw = RawResult(json.dumps(domain_payload).encode(), "https://rdap.org/domain/example.com")
    facts = adapter.parse(raw, Request("domain", "example.com"))
    by_attr = {(f.attribute, f.value) for f in facts}
    assert ("whois.registrar", "RESERVED-Internet Assigned Numbers Authority") in by_attr
    assert ("whois.created", "1995-08-14T04:00:00Z") in by_attr
    assert ("whois.expires", "2027-08-13T04:00:00Z") in by_attr
    assert ("whois.nameserver", "a.iana-servers.net") in by_attr
    assert ("whois.status", "client transfer prohibited") in by_attr

    ip_payload = {
        "name": "CLOUDFLARENET",
        "country": "US",
        "cidr0_cidrs": [{"v4prefix": "104.16.0.0", "length": 12}],
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc."]]],
            }
        ],
    }
    ip_facts = adapter.parse(
        RawResult(json.dumps(ip_payload).encode(), "https://rdap.org/ip/104.16.132.229"),
        Request("ip", "104.16.132.229"),
    )
    ip_attrs = {(f.attribute, f.value) for f in ip_facts}
    assert ("host.org", "Cloudflare, Inc.") in ip_attrs
    assert ("host.network_name", "CLOUDFLARENET") in ip_attrs
    assert ("host.cidr", "104.16.0.0/12") in ip_attrs
    assert ("host.country", "US") in ip_attrs


def test_internetdb_adapter_parses_ports_cpes_hostnames_and_vulns():
    adapter = InternetDbAdapter()
    payload = {
        "ip": "93.184.215.14",
        "ports": [80, 443, 3389],
        "cpes": ["cpe:/a:igor_sysoev:nginx:1.24.0"],
        "hostnames": ["edge.example.com"],
        "tags": ["cdn", "cloud"],
        "vulns": ["cve-2024-1234"],
    }
    raw = RawResult(json.dumps(payload).encode(), "https://internetdb.shodan.io/93.184.215.14", http_status=200)
    facts = adapter.parse(raw, Request("ip", "93.184.215.14"))
    by_attr = {(f.attribute, f.value) for f in facts}
    assert ("host.port", "80") in by_attr
    assert ("host.port", "3389") in by_attr
    assert ("host.cpe", "cpe:/a:igor_sysoev:nginx:1.24.0") in by_attr
    assert ("host.reverse_dns", "edge.example.com") in by_attr
    assert ("host.tag", "cdn") in by_attr
    assert ("host.vuln", "CVE-2024-1234") in by_attr


def test_hackertarget_and_amass_adapters_parse_subdomains_and_ips():
    ht = HackerTargetAdapter()
    csv_body = b"api.example.com,93.184.215.14\nvpn.example.com,93.184.215.15\nother.org,1.2.3.4\n"
    facts = ht.parse(RawResult(csv_body, "https://api.hackertarget.com/hostsearch/?q=example.com"), Request("domain", "example.com"))
    by_attr = {(f.attribute, f.value) for f in facts}
    assert ("dns.subdomain", "api.example.com") in by_attr
    assert ("dns.subdomain", "vpn.example.com") in by_attr
    assert ("dns.passive.ipv4", "93.184.215.14") in by_attr
    assert not any("other.org" in f.value for f in facts)

    amass = AmassAdapter()
    amass_body = b"dev.example.com\nstaging.example.com\nexample.com\n"
    afacts = amass.parse(RawResult(amass_body, "tool://amass/example.com"), Request("domain", "example.com"))
    assert {(f.attribute, f.value) for f in afacts} == {
        ("discovery.subdomain", "dev.example.com"),
        ("discovery.subdomain", "staging.example.com"),
    }


def test_dns_posture_parses_dkim_mtasts_tlsrpt_dnssec_and_tls():
    adapter = DnsPostureAdapter()
    payload = [
        {"name": "example.com", "type": "TXT", "status": "ok", "records": ["v=spf1 ~all"]},
        {"name": "_dmarc.example.com", "type": "TXT", "status": "ok", "records": ["v=DMARC1; p=none; pct=50; rua=mailto:dmarc@example.com"]},
        {"name": "example.com", "type": "DNSKEY", "status": "ok", "records": []},
        {"name": "_mta-sts.example.com", "type": "TXT", "status": "ok", "records": []},
        {"name": "_smtp._tls.example.com", "type": "TXT", "status": "ok", "records": ["v=TLSRPTv1; rua=mailto:tls@example.com"]},
        {"name": "google._domainkey.example.com", "type": "TXT", "status": "ok", "records": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqh"]},
        {"name": "example.com", "type": "_TLS", "status": "ok", "tls": {
            "issuer": "Let's Encrypt",
            "not_after": "2026-12-31T00:00:00+00:00",
            "days_remaining": 10,
            "san": ["example.com", "www.example.com"],
        }},
    ]
    facts = adapter.parse(RawResult(json.dumps(payload).encode(), "dns://example.com"), Request("domain", "example.com"))
    by_attr = {(f.attribute, f.value) for f in facts}
    assert ("email.dmarc.policy", "none") in by_attr
    assert ("email.dmarc.pct", "50") in by_attr
    assert ("email.dmarc.rua", "mailto:dmarc@example.com") in by_attr
    assert ("dnssec.status", "absent") in by_attr
    assert ("email.mtasts.present", "absent") in by_attr
    assert ("email.tlsrpt.present", "true") in by_attr
    assert ("email.dkim.selector", "google") in by_attr
    assert ("tls.issuer", "Let's Encrypt") in by_attr
    assert ("tls.days_remaining", "10") in by_attr


def test_company_web_extracts_title_description_socials_and_tech_stack():
    adapter = CompanyWebAdapter()
    payload = {
        "domain": "example.com",
        "pages": [
            {
                "url": "https://example.com/",
                "status": 200,
                "tls_validated": True,
                "security_headers": {"strict-transport-security": "max-age=31536000"},
                "tech_headers": {"server": "cloudflare", "x-powered-by": "Next.js", "cf-ray": "12345"},
                "html": (
                    "<html><head><title>Example Corp — Cloud Security</title>"
                    '<meta name="description" content="Enterprise cloud defense platform.">'
                    '<script src="/_next/static/chunks/main.js"></script>'
                    '<script src="https://www.googletagmanager.com/gtm.js"></script>'
                    "</head><body>"
                    '<a href="https://www.linkedin.com/company/example-corp">LinkedIn</a>'
                    '<a href="https://github.com/example-corp">GitHub</a>'
                    "</body></html>"
                ),
            }
        ],
    }
    facts = adapter.parse(RawResult(json.dumps(payload).encode(), "https://example.com/"), Request("domain", "example.com"))
    by_attr = {(f.attribute, f.value) for f in facts}
    assert ("web.title", "Example Corp — Cloud Security") in by_attr
    assert ("web.description", "Enterprise cloud defense platform.") in by_attr
    assert ("company.social_url", "https://www.linkedin.com/company/example-corp") in by_attr
    assert ("company.social_url", "https://github.com/example-corp") in by_attr
    assert ("tech.cdn", "Cloudflare") in by_attr
    assert ("tech.framework", "Next.js") in by_attr
    assert ("tech.analytics", "Google Tag Manager") in by_attr


def test_grade_brief_posture_computes_grades_and_prioritized_exposures():
    def f(fid, attr, val):
        return {
            "fact_id": fid,
            "source_record_id": "sr-" + fid,
            "subject": "example.com",
            "attribute": attr,
            "value": val,
            "confidence": "medium",
            "is_inference": False,
            "flags": [],
        }

    facts = [
        f("1", "email.dmarc.policy", "absent"),
        f("2", "email.spf.qualifier", "+all"),
        f("3", "dnssec.status", "absent"),
        f("4", "tls.days_remaining", "7"),
        f("5", "http.security_assessed", "true"),
        f("6", "host.vuln", "CVE-2024-9999"),
        f("7", "host.port", "3389"),
    ]
    posture = grade_brief_posture(facts)
    assert posture["overall"]["letter"] in ("D", "F")
    assert posture["overall"]["assessed_domains"] == 5
    severities = [e["severity"] for e in posture["exposures"]]
    assert "critical" in severities
    assert "high" in severities
    # Verify sorted order: critical before high before medium before low
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert [rank[s] for s in severities] == sorted(rank[s] for s in severities)


def test_parallel_run_and_dossier_markdown_export(engine, tmp_path):
    now = datetime.now(timezone.utc)
    engagement = EngagementView(
        id="eng-par",
        authority_basis="prospect_company",
        authorized_domains=("example.com",),
        starts_at=now - timedelta(days=1),
        expires_at=now + timedelta(days=1),
    )
    with engine.begin() as conn:
        from neesha.db import schema
        conn.execute(
            schema.engagement.insert().values(
                id=engagement.id,
                authority_basis=engagement.authority_basis,
                authorized_domains=["example.com"],
                permitted_techniques=[],
                authorized_by="test",
                starts_at=engagement.starts_at,
                expires_at=engagement.expires_at,
                created_at=now,
            )
        )

    class FakeDns(DnsPostureAdapter):
        def fetch(self, reference):
            return RawResult(
                json.dumps([
                    {"name": "example.com", "type": "TXT", "status": "ok", "records": ["v=spf1 ~all"]},
                    {"name": "_dmarc.example.com", "type": "TXT", "status": "ok", "records": ["v=DMARC1; p=none"]},
                ]).encode(),
                reference.url,
            )

    class FakeRdap(RdapAdapter):
        def fetch(self, reference):
            return RawResult(
                json.dumps({"status": ["client transfer prohibited"]}).encode(),
                reference.url,
            )

    ledger = Ledger(engine)
    gate = PolicyGate(engine, ledger)
    report = execute_run(
        engine=engine,
        ledger=ledger,
        gate=gate,
        company="example.com",
        engagement=engagement,
        analyst="test",
        pir_templates=("email-posture", "whois-registration"),
        sources={"dns-posture", "rdap"},
        adapters={"dns-posture": FakeDns(), "rdap": FakeRdap()},
        parallel=True,
    )
    assert report.status == "complete"
    assert report.facts_written >= 3

    brief = build_brief(engine, report.run_id)
    assert "posture" in brief
    assert "exposures" in brief
    assert len(brief["exposures"]) >= 1

    md_path, json_path = write_brief(engine, report.run_id, tmp_path)
    md_text = md_path.read_text()
    assert "## Security Posture Assessment (A–F)" in md_text
    assert "## Prioritized Exposures & Remediation Roadmap" in md_text
    assert "## What we know" in md_text


def test_email_osint_and_username_osint_adapters_parse():
    from neesha.adapters.email_osint import EmailOsintAdapter
    from neesha.adapters.username_osint import UsernameOsintAdapter

    email_adapter = EmailOsintAdapter()
    email_payload = {
        "email": "alice@gmail.com",
        "local_part": "alice",
        "base_local": "alice",
        "domain": "gmail.com",
        "dns": {
            "mx_hosts": ["gmail-smtp-in.l.google.com"],
            "spf_qualifier": "~all",
            "dmarc_policy": "none",
        },
        "probes": [
            {"service": "firefox.com", "checked": True, "found": True},
            {"service": "duolingo.com", "checked": True, "found": True, "url": "https://www.duolingo.com/profile/alice"},
            {"service": "wordpress.com", "checked": True, "found": False},
        ],
        "handle_matches": [
            {"platform": "github.com", "handle": "alice", "url": "https://github.com/alice", "name": "Alice Dev"},
        ],
    }
    email_facts = email_adapter.parse(
        RawResult(json.dumps(email_payload).encode(), "osint://email-osint/alice@gmail.com"),
        Request("email", "alice@gmail.com"),
    )
    email_attrs = {(f.attribute, f.value) for f in email_facts}
    assert ("public.email.provider", "Gmail / Google") in email_attrs
    assert ("public.email.deliverable_mx", "true") in email_attrs
    assert ("public.email.mx_host", "gmail-smtp-in.l.google.com") in email_attrs
    assert ("public.account.found", "firefox.com") in email_attrs
    assert ("public.account.found", "duolingo.com") in email_attrs
    assert ("public.account.summary.count", "2") in email_attrs
    assert ("public.email.handle_correlation", "github.com (alice) — Alice Dev") in email_attrs
    assert all(f.identity_key == "email:alice@gmail.com" for f in email_facts)

    user_adapter = UsernameOsintAdapter()
    user_payload = {
        "subject": "alicedev",
        "checked_platforms": ["github.com", "reddit.com"],
        "matches": [
            {"service": "github.com", "url": "https://github.com/alicedev", "handle": "alicedev"},
            {"service": "reddit.com", "url": "https://www.reddit.com/user/alicedev", "handle": "alicedev"},
        ],
    }
    user_facts = user_adapter.parse(
        RawResult(json.dumps(user_payload).encode(), "osint://username-osint/alicedev"),
        Request("username", "alicedev"),
    )
    user_attrs = {(f.attribute, f.value) for f in user_facts}
    assert ("public.account.summary.count", "2") in user_attrs
    assert ("public.account.found", "github.com") in user_attrs
    assert ("public.account.url", "https://github.com/alicedev") in user_attrs
    assert all(f.identity_key == "username:alicedev" for f in user_facts)


def test_vultr_ephemeral_ubuntu_vps_manager(tmp_path, monkeypatch):
    from neesha.cloud.vultr import VultrManager, build_ubuntu_cloud_init

    script = build_ubuntu_cloud_init()
    assert "apt-get install -y" in script
    assert "holehe socialscan maigret sherlock-project theHarvester" in script
    assert "subfinder" in script

    monkeypatch.setenv("VULTR_API_KEY", "test-vultr-key-123456")
    mgr = VultrManager(config_dir=tmp_path)
    monkeypatch.setattr(mgr, "ensure_local_ssh_keypair", lambda: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey ephemeral-worker")

    calls = []

    def fake_request(method, path, payload=None, timeout=20):
        calls.append((method, path, payload))
        if method == "GET" and path == "/ssh-keys":
            return 200, {"ssh_keys": [{"id": "ssh-1", "ssh_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey ephemeral-worker"}]}
        if method == "POST" and path == "/instances":
            return 202, {
                "instance": {
                    "id": "inst-999",
                    "label": payload["label"],
                    "region": payload["region"],
                    "main_ip": "203.0.113.42",
                    "status": "active",
                    "power_status": "running",
                    "server_status": "ok",
                }
            }
        if method == "DELETE" and path.startswith("/instances/"):
            return 204, {}
        return 200, {"instances": []}

    monkeypatch.setattr(mgr, "_request", fake_request)
    spun = mgr.spin_up_node(region="random", auto_select=True)
    assert spun["created"]["id"] == "inst-999"
    assert spun["created"]["ip"] == "203.0.113.42"
    assert spun["cloud"]["active_node_id"] == "inst-999"

    # Verify anonymous hostname & cloud-init user_data were sent
    post_call = [c for c in calls if c[0] == "POST" and c[1] == "/instances"][0]
    assert post_call[2]["hostname"].startswith("node-")
    assert post_call[2]["os_id"] == 2284
    assert post_call[2]["user_data"]

    destroyed = mgr.destroy_node("inst-999")
    assert destroyed["destroyed"] == ["inst-999"]
    assert destroyed["cloud"]["active_node_id"] == "local"


def test_cross_platform_preinstall_scripts():
    from neesha.adapters.tool_installer import detect_os_platform, generate_preinstall_script

    plat = detect_os_platform()
    assert plat["os"] in ("windows", "linux", "macos")
    assert plat["arch"] in ("arm64", "amd64")

    win_name, _, win_script = generate_preinstall_script("windows")
    assert win_name == "find3r-preinstall-windows.ps1"
    assert "holehe socialscan maigret sherlock-project theHarvester bbot" in win_script
    assert "Ollama.Ollama" in win_script
    assert "ollama pull" in win_script

    lin_name, _, lin_script = generate_preinstall_script("linux")
    assert lin_name == "find3r-preinstall-linux.sh"
    assert "apt-get install -y" in lin_script
    assert "https://ollama.com/install.sh" in lin_script
    assert "ollama pull" in lin_script

    mac_name, _, mac_script = generate_preinstall_script("macos")
    assert mac_name == "find3r-preinstall-macos.sh"
    assert "brew install subfinder amass sherlock theharvester ollama" in mac_script
    assert "ollama pull" in mac_script


def test_local_ollama_runtime_and_zero_cost_synthesis(engine, monkeypatch):
    from neesha.runtime import investigation as runtime
    from neesha.runtime import ollama as ol

    status = ol.ollama_status()
    catalog_ids = [m["id"] for m in status["catalog"]]
    assert "llama3.1:8b" in catalog_ids
    assert "qwen2.5:7b" in catalog_ids
    assert "deepseek-r1:8b" in catalog_ids
    assert ol.valid_ollama_model("ollama:qwen2.5:7b") == "qwen2.5:7b"
    for bad in ("", "../evil", "llama3;rm", "http://evil.com/model"):
        with pytest.raises(ValueError):
            ol.valid_ollama_model(bad)

    calls = []

    def fake_generate_ollama(model, system, payload, timeout=90):
        calls.append((model, payload["role"]))
        fid = payload["facts"][0]["fact_id"]
        return "<think>internal reasoning</think>\n" + json.dumps({
            "claims": [{"text": f"Local {model} synthesis for {payload['role']}.", "evidence_ids": [fid]}]
        })

    monkeypatch.setattr(runtime, "generate_ollama", fake_generate_ollama)
    sample_brief = {
        "run_id": "a" * 32,
        "company": "example.com",
        "facts": [
            {"fact_id": "f1", "source_record_id": "s1", "subject": "example.com", "attribute": "dns.subdomain", "value": "api.example.com", "confidence": "high"},
            {"fact_id": "f2", "source_record_id": "s2", "subject": "example.com", "attribute": "person.role", "value": "CISO", "confidence": "medium"},
        ],
    }
    single_res = runtime.analyze_brief(engine, sample_brief, "single", ["ollama:llama3.1:8b"])
    assert single_res["status"] == "complete"
    assert single_res["spend_usd"] == "0"
    assert single_res["claims"][0]["retrieved_by"] == {"provider": "ollama", "model": "llama3.1:8b"}

    multi_res = runtime.analyze_brief(engine, sample_brief, "multi", ["ollama:llama3.1:8b", "ollama:qwen2.5:7b"])
    assert multi_res["status"] == "complete"
    assert multi_res["spend_usd"] == "0"
    assert len(multi_res["reports"]) == 3


def test_security_hardening_adapter_validation_and_remote_bridge(engine, tmp_path, monkeypatch):
    import base64
    from neesha.adapters.amass import AmassAdapter
    from neesha.adapters.base import AdapterError, RawResult, Request
    from neesha.adapters.email_osint import EmailOsintAdapter
    from neesha.adapters.hackertarget import HackerTargetAdapter
    from neesha.adapters.internetdb import InternetDbAdapter
    from neesha.adapters.rdap import RdapAdapter
    from neesha.adapters.theharvester import TheHarvesterAdapter
    from neesha.adapters.username_osint import UsernameOsintAdapter
    from neesha.cloud.vultr import VultrError, VultrManager
    from neesha.db import schema

    # 1. Option injection and malformed domain rejection
    for adapter in (TheHarvesterAdapter(), AmassAdapter(), RdapAdapter(), InternetDbAdapter(), HackerTargetAdapter()):
        with pytest.raises(AdapterError):
            adapter.search(Request("domain", "-d evil.com"))
        with pytest.raises(AdapterError):
            adapter.search(Request("company", "Acme Corp With Spaces"))

    # 2. Private/loopback IP rejection on RDAP and InternetDB
    for adapter in (RdapAdapter(), InternetDbAdapter()):
        for bad_ip in ("127.0.0.1", "10.0.0.1", "169.254.169.254"):
            with pytest.raises(AdapterError):
                adapter.search(Request("ip", bad_ip))

    # 3. Non-http(s) account URL filtering in EmailOsintAdapter and UsernameOsintAdapter
    em_adapter = EmailOsintAdapter()
    raw_em = RawResult(
        payload=json.dumps({
            "email": "alice@example.com",
            "local_part": "alice",
            "base_local": "alice",
            "domain": "example.com",
            "dns": {"mx_hosts": ["mx.example.com"], "spf_qualifier": "-all", "dmarc_policy": "reject"},
            "probes": [{"service": "gravatar.com", "checked": True, "found": True, "url": "javascript:alert(1)"}],
            "handle_matches": [{"platform": "github.com", "handle": "alice", "url": "https://github.com/alice"}],
        }).encode("utf-8"),
        request_url="osint://email-osint/alice@example.com",
        origin_url="https://keys.openpgp.org/",
    )
    em_facts = em_adapter.parse(raw_em, Request("email", "alice@example.com"))
    em_urls = [f.value for f in em_facts if f.attribute == "public.account.url"]
    assert em_urls == ["https://github.com/alice"]

    u_adapter = UsernameOsintAdapter()
    raw_u = RawResult(
        payload=json.dumps({
            "subject": "alice_sec",
            "checked_platforms": ["github.com"],
            "matches": [
                {"service": "github.com", "url": "javascript:evil()", "handle": "alice_sec"},
                {"service": "gitlab.com", "url": "https://gitlab.com/alice_sec", "handle": "alice_sec"},
            ],
        }).encode("utf-8"),
        request_url="osint://username-osint/alice_sec",
        origin_url="https://api.github.com/",
    )
    u_facts = u_adapter.parse(raw_u, Request("username", "alice_sec"))
    u_urls = [f.value for f in u_facts if f.attribute == "public.account.url"]
    assert u_urls == ["https://gitlab.com/alice_sec"]

    # 4. Vultr path traversal rejection & remote SQLite schema import round-trip
    monkeypatch.setenv("VULTR_API_KEY", "test-vultr-key-123456")
    mgr = VultrManager(config_dir=tmp_path)
    with pytest.raises(VultrError):
        mgr.destroy_node("../ssh-keys/123")

    now = datetime.now(timezone.utc)
    eng_id = "e" * 32
    run_id = "a" * 32
    ent_id = "b" * 32
    sr_id = "c" * 32
    fact_id = "d" * 32
    pir_id = "f" * 32
    with engine.begin() as conn:
        conn.execute(schema.engagement.insert().values(
            id=eng_id,
            authority_basis="prospect_company",
            authorized_domains=["example.com"],
            authorized_emails=[],
            authorized_usernames=[],
            permitted_techniques=[],
            authorized_by="test",
            starts_at=now,
            expires_at=now + timedelta(days=1),
            created_at=now,
        ))

    mgr.ssh_dir.mkdir(parents=True, exist_ok=True)
    mgr.private_key_path.write_text("dummy-private-key")
    fake_remote_payload = (
        "===NEESHA_REMOTE_DUMP===\n"
        + json.dumps({
            "run_id": run_id,
            "company_id": ent_id,
            "facts_written": 1,
            "steps_count": 1,
            "skipped_count": 0,
            "entities": [{
                "id": ent_id,
                "kind": "domain",
                "canonical_name": "example.com",
                "company_id": None,
                "aliases": ["example.com"],
                "confidence": "high",
                "first_seen_at": now.isoformat(),
                "last_seen_at": now.isoformat(),
            }],
            "run": {
                "id": run_id,
                "engagement_id": eng_id,
                "company_id": ent_id,
                "analyst": "vultr-vps",
                "status": "complete",
                "stop_reason": "completed",
                "skipped": [],
                "max_steps": 30,
                "max_spend_usd": "1.0000",
                "max_wall_secs": 300,
                "started_at": now.isoformat(),
                "ended_at": now.isoformat(),
            },
            "source_records": [{
                "id": sr_id,
                "run_id": run_id,
                "adapter": "rdap",
                "tier": "A",
                "request_url": "https://rdap.org/domain/example.com",
                "origin_url": "https://rdap.org/",
                "collected_at": now.isoformat(),
                "collection_mode": "third_party_passive",
                "raw_payload_b64": base64.b64encode(b'{"ldhName":"example.com"}').decode("ascii"),
                "raw_sha256": "0" * 64,
                "http_status": 200,
                "retention_expires_at": (now + timedelta(days=30)).isoformat(),
            }],
            "facts": [{
                "id": fact_id,
                "run_id": run_id,
                "entity_id": ent_id,
                "attribute": "whois.registrar",
                "value": "RESERVED-Internet Assigned Numbers Authority",
                "value_type": "str",
                "unit": None,
                "observed_at": now.isoformat(),
                "source_record_id": sr_id,
                "confidence": "high",
                "is_inference": False,
                "admiralty_source": "A",
                "admiralty_claim": "1",
                "sensitivity": "business",
                "retention_expires_at": (now + timedelta(days=30)).isoformat(),
            }],
            "pirs": [{
                "id": pir_id,
                "run_id": run_id,
                "question": "Who is the registrar?",
                "template": "whois-registration",
                "answers_attributes": ["whois.registrar"],
                "status": "answered",
                "answer": "Observed.",
                "fact_ids": [fact_id],
                "gap_reason": None,
            }],
            "query_logs": [],
        })
    )

    class FakeProc:
        def __init__(self, stdout=""):
            self.returncode = 0
            self.stdout = stdout
            self.stderr = ""

    def fake_subproc_run(args, **kwargs):
        cmd_str = " ".join(str(a) for a in args)
        if "READY" in cmd_str:
            return FakeProc("READY\n")
        if "tar -xzf" in cmd_str:
            return FakeProc("")
        return FakeProc(fake_remote_payload)

    monkeypatch.setattr("neesha.cloud.vultr.subprocess.run", fake_subproc_run)
    res = mgr.execute_remote_investigation(
        engine=engine,
        node={"id": "inst-999", "ip": "203.0.113.42", "region_name": "Amsterdam (NL)"},
        target="example.com",
        subject_kind="domain",
        engagement_id=eng_id,
        run_id=run_id,
    )
    assert res["run_id"] == run_id
    assert res["facts_written"] == 1
    brief = build_brief(engine, run_id)
    assert any(f["attribute"] == "whois.registrar" for f in brief["facts"])




