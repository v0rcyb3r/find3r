"""Collector wiring test with faked resolvers and network (no real IO)."""
from datetime import datetime, timezone

import neesha.collectors.posture as posture_mod
from neesha.collectors.posture import PostureCollector, normalize_domain
from tests.helpers import make_store
from neesha.resolvers.dns import QueryResult, Record
from neesha.scope.engine import ScopeEngine
from neesha.scope.models import Scope


class FakeResolver:
    name = "system"

    def __init__(self, txt_by_name):
        self.txt_by_name = txt_by_name

    def query(self, domain, rtype):
        if rtype == "TXT" and domain in self.txt_by_name:
            return QueryResult(
                domain, rtype, self.name, status="ok",
                records=[Record(rtype, v) for v in self.txt_by_name[domain]],
            )
        if rtype == "A" and domain.startswith("neesha-"):
            return QueryResult(domain, rtype, self.name, status="nxdomain")
        if rtype == "A":
            return QueryResult(
                domain, rtype, self.name, status="ok",
                records=[Record(rtype, "192.0.2.1")],
            )
        return QueryResult(domain, rtype, self.name, status="noerror-nodata")


def test_collector_produces_graded_brief(tmp_path, monkeypatch):
    monkeypatch.setattr(
        posture_mod, "get_tls_cert",
        lambda host, port=443, timeout=8: {
            "issuer": "R3",
            "not_after": datetime(2099, 1, 1, tzinfo=timezone.utc),
            "san": ["acme.com"],
        },
    )
    monkeypatch.setattr(
        posture_mod, "fetch_http",
        lambda url, timeout=8: {
            "status": 200,
            "final_url": "https://acme.com/",
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "no-referrer",
                "permissions-policy": "geolocation=()",
            },
        },
    )
    monkeypatch.setattr(posture_mod, "dnssec_status", lambda resolvers, domain: ("validated", True, True))

    store = make_store(tmp_path / "e.db")
    scope = Scope(target="acme.com", target_type="domain", purpose="test", observer="target")
    collector = PostureCollector(ScopeEngine(scope), store, "acme.com")

    fake = FakeResolver({
        "acme.com": ["v=spf1 -all"],
        "_dmarc.acme.com": ["v=DMARC1; p=reject"],
        "google._domainkey.acme.com": ["v=DKIM1; k=rsa; p=test"],
    })
    collector.system = collector.cloudflare = collector.google = fake

    evidences, brief = collector.run()

    assert brief.overall.letter == "A"
    assert brief.evidence_count == len(evidences) > 0
    assert any(c.name == "SPF" for c in brief.checks)
    assert any(c.name == "DMARC" for c in brief.checks)
    # evidence is actually persisted
    assert store.count() == len(evidences)


def test_normalize_domain():
    assert normalize_domain("HTTPS://Acme.COM/path") == "acme.com"
    assert normalize_domain("www.example.com.") == "www.example.com"
