"""Account-enumeration adapters (Holehe, Socialscan): gated, aggregate-only."""
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from neesha.adapters import registry
from neesha.adapters.base import RawResult, Reference, Request
from neesha.adapters.holehe import HoleheAdapter
from neesha.adapters.socialscan import SocialscanAdapter
from neesha.harness.gate import AdapterSpec, EngagementView, PolicyGate, RunCaps, RunState
from neesha.harness.graph import build_graph
from neesha.ledger.ledger import Ledger

ADAPTERS = [HoleheAdapter, SocialscanAdapter]


@pytest.mark.parametrize("cls", ADAPTERS)
def test_contract_is_tier_c_gated_and_off_by_default(cls):
    assert cls.tier == "C"
    assert cls.default_enabled is False
    assert cls.requires_techniques == frozenset({"account_enumeration"})
    assert cls.accepts == frozenset({"email"})
    assert cls.collection_mode == "third_party_passive"


@pytest.mark.parametrize("cls", ADAPTERS)
def test_unavailable_when_binary_absent(cls, monkeypatch):
    monkeypatch.setattr(cls, "binary", classmethod(lambda c: None))
    status = cls().availability()
    assert status["available"] is False
    assert "not installed" in status["reason"]


def test_holehe_stdout_parse_keeps_only_used_and_drops_recovery_hints():
    out = (b"Twitter : email used\n"
           b"[+] github.com\n"
           b"[+] Instagram.com  recovery email: d***@gmail.com\n"
           b"[-] notused.com\n"
           b"[x] ratelimited.com\n")
    assert HoleheAdapter._parse_stdout(out) == ["github.com", "instagram.com"]


def test_socialscan_json_parse_keeps_only_registered_platforms():
    import json
    raw = json.dumps([
        {"platform": "GitHub", "available": False, "valid": True, "success": True},
        {"platform": "Instagram", "available": True, "valid": True, "success": True},
        {"platform": "Reddit", "available": False, "valid": True, "success": False},
    ]).encode()
    assert SocialscanAdapter._parse_json(raw) == ["github"]


def test_sanitized_payload_excludes_recovery_data_and_parse_yields_personal_facts():
    import json
    ref = Reference(url="tool://holehe/x", origin_url="tool://holehe/")
    raw = HoleheAdapter()._sanitized("dana@gmail.com", ["github.com", "github.com", "twitter.com"], ref)
    # The persisted payload holds only the subject, the tool, and the found
    # service names — no recovery addresses or per-service detail.
    stored = json.loads(raw.payload)
    assert set(stored) == {"subject", "tool", "found_services"}
    assert stored["found_services"] == ["github.com", "twitter.com"]
    facts = HoleheAdapter().parse(raw, Request("email", "dana@gmail.com"))
    by = {(f.attribute, f.value) for f in facts}
    assert ("public.account.summary.count", "2") in by
    assert ("public.account.found", "github.com") in by
    assert ("public.account.found", "twitter.com") in by
    assert all(f.sensitivity == "personal" and f.entity_kind == "email" for f in facts)


def test_parse_rejects_subject_mismatch():
    ref = Reference(url="tool://holehe/x", origin_url="tool://holehe/")
    raw = HoleheAdapter()._sanitized("someone@else.com", ["github.com"], ref)
    with pytest.raises(Exception):
        HoleheAdapter().parse(raw, Request("email", "dana@gmail.com"))


def _gate(engine):
    ledger = Ledger(engine)
    ledger.set_cap("100.00")
    return PolicyGate(engine, ledger, clock=lambda: datetime(2026, 11, 2, tzinfo=timezone.utc))


def _spec():
    return AdapterSpec(name="holehe", tier="C", collection_mode="third_party_passive",
                       requires_techniques=frozenset({"account_enumeration"}))


NOW = datetime(2026, 11, 2, tzinfo=timezone.utc)
CAPS = RunCaps(max_steps=25, max_spend_usd=Decimal("1"), max_wall_secs=600)


def test_gate_allows_account_enum_when_technique_permitted(engine):
    view = EngagementView(id="e", authority_basis="public_research",
                          authorized_emails=("dana@gmail.com",),
                          permitted_techniques=frozenset({"account_enumeration"}),
                          starts_at=NOW - timedelta(days=1), expires_at=NOW + timedelta(days=1))
    decision = _gate(engine).authorize(adapter=_spec(), target="dana@gmail.com", engagement=view,
                                       analyst="a", caps=CAPS, state=RunState(), approved=True)
    assert decision.outcome == "allowed"


def test_gate_denies_account_enum_without_the_technique(engine):
    view = EngagementView(id="e", authority_basis="client_engagement",
                          authorized_emails=("dana@gmail.com",), permitted_techniques=frozenset(),
                          starts_at=NOW - timedelta(days=1), expires_at=NOW + timedelta(days=1))
    decision = _gate(engine).authorize(adapter=_spec(), target="dana@gmail.com", engagement=view,
                                       analyst="a", caps=CAPS, state=RunState(), approved=True)
    assert decision.outcome == "denied"
    assert "account_enumeration" in decision.reason


def test_gate_pauses_when_approval_tiers_set_then_allows_once_approved(engine):
    view = EngagementView(id="e", authority_basis="client_engagement",
                          authorized_emails=("dana@gmail.com",),
                          permitted_techniques=frozenset({"account_enumeration"}),
                          starts_at=NOW - timedelta(days=1), expires_at=NOW + timedelta(days=1))
    ledger = Ledger(engine)
    ledger.set_cap("100.00")
    gate = PolicyGate(engine, ledger, approval_tiers=frozenset({"C"}),
                      clock=lambda: datetime(2026, 11, 2, tzinfo=timezone.utc))
    paused = gate.authorize(adapter=_spec(), target="dana@gmail.com", engagement=view,
                            analyst="a", caps=CAPS, state=RunState())
    assert paused.outcome == "paused"
    allowed = gate.authorize(adapter=_spec(), target="dana@gmail.com", engagement=view,
                             analyst="a", caps=CAPS, state=RunState(), approved=True)
    assert allowed.outcome == "allowed"


def test_graph_renders_account_nodes_from_evidence():
    facts = [{
        "fact_id": "f1", "source_record_id": "s1", "attribute": "public.account.found",
        "value": "github.com", "subject": "dana@gmail.com", "source": "holehe",
        "entity_id": "root", "sensitivity": "personal",
    }]
    graph = build_graph("dana@gmail.com", facts, subject_kind="email")
    accounts = [n for n in graph["nodes"] if n["kind"] == "account"]
    assert [n["label"] for n in accounts] == ["github.com"]
    assert any(e["kind"] == "account_observed" for e in graph["edges"])


# ---- username tools (Sherlock, Maigret) ---------------------------------

from neesha.adapters.sherlock import SherlockAdapter, parse_found_sites
from neesha.adapters.maigret import MaigretAdapter

USERNAME_ADAPTERS = [SherlockAdapter, MaigretAdapter]


@pytest.mark.parametrize("cls", USERNAME_ADAPTERS)
def test_username_tool_contract(cls):
    assert cls.tier == "C"
    assert cls.accepts == frozenset({"username"})
    assert cls.subject_entity_kind == "username"
    assert cls.requires_techniques == frozenset({"account_enumeration"})
    assert cls.default_enabled is False


def test_parse_found_sites_keeps_only_plus_site_names():
    out = (b"[*] Checking username jdoe on:\n"
           b"[+] GitHub: https://github.com/jdoe\n"
           b"[+] Reddit: https://reddit.com/user/jdoe\n"
           b"[-] Twitter: Not Found!\n")
    assert parse_found_sites(out, 50) == ["github", "reddit"]


def test_username_parse_yields_username_scoped_personal_facts():
    ref = Reference(url="tool://sherlock/jdoe", origin_url="tool://sherlock/")
    raw = SherlockAdapter()._sanitized("jdoe", ["github", "reddit"], ref)
    facts = SherlockAdapter().parse(raw, Request("username", "jdoe"))
    by = {(f.attribute, f.value) for f in facts}
    assert ("public.account.found", "github") in by
    assert all(f.entity_kind == "username" and f.sensitivity == "personal" for f in facts)
    assert all(f.identity_key == "username:jdoe" for f in facts)


def test_gate_covers_username_only_when_authorized(engine):
    allowed = EngagementView(id="e", authority_basis="client_engagement",
                             authorized_usernames=("jdoe",),
                             permitted_techniques=frozenset({"account_enumeration"}),
                             starts_at=NOW - timedelta(days=1), expires_at=NOW + timedelta(days=1))
    spec = AdapterSpec(name="sherlock", tier="C", collection_mode="third_party_passive",
                       requires_techniques=frozenset({"account_enumeration"}))
    gate = _gate(engine)
    ok = gate.authorize(adapter=spec, target="jdoe", engagement=allowed, analyst="a",
                        caps=CAPS, state=RunState(), approved=True, subject_kind="username")
    assert ok.outcome == "allowed"
    other = gate.authorize(adapter=spec, target="someoneelse", engagement=allowed, analyst="a",
                           caps=CAPS, state=RunState(), approved=True, subject_kind="username")
    assert other.outcome == "denied"


def test_username_run_end_to_end_under_a_client_engagement(engine):
    import json
    from datetime import datetime, timezone
    from neesha.db import schema
    from neesha.harness.run import execute_run
    from neesha.harness.brief import build_brief
    from neesha.ledger.ledger import Ledger
    now = datetime(2026, 11, 2, tzinfo=timezone.utc)
    view = EngagementView(id="ec", authority_basis="client_engagement",
                          authorized_usernames=("jdoe",),
                          permitted_techniques=frozenset({"account_enumeration"}),
                          starts_at=now - timedelta(days=1), expires_at=now + timedelta(days=1))
    with engine.begin() as conn:
        conn.execute(schema.engagement.insert().values(
            id="ec", authority_basis="client_engagement", client_name="Acme",
            authorized_domains=[], authorized_emails=[], authorized_usernames=["jdoe"],
            permitted_techniques=["account_enumeration"], authorized_by="a",
            starts_at=now - timedelta(days=1), expires_at=now + timedelta(days=1), created_at=now))
    ledger = Ledger(engine); ledger.set_cap("100.00", period="2026-11")
    gate = PolicyGate(engine, ledger, clock=lambda: now)

    class StubSherlock(SherlockAdapter):
        @classmethod
        def binary(cls):
            return "/usr/bin/true"

        def fetch(self, reference):
            return self._sanitized("jdoe", ["github", "reddit"], reference)

    report = execute_run(engine=engine, ledger=ledger, gate=gate, company="jdoe",
                         engagement=view, analyst="a", subject_kind="username",
                         pir_templates=("username-account-presence",),
                         sources={"sherlock"}, tiers={"C"},
                         adapters={"sherlock": StubSherlock()}, approve={"sherlock"})
    assert report.facts_written >= 2
    brief = build_brief(engine, report.run_id)
    assert brief["subject_kind"] == "username"
    accounts = [n for n in brief["graph"]["nodes"] if n["kind"] == "account"]
    assert {n["label"] for n in accounts} == {"github", "reddit"}
    assert any(f["attribute"] == "public.account.found" for f in brief["facts"])


def test_maigret_constrains_scope_and_sherlock_suppresses_reports(monkeypatch):
    captured = {}

    def fake_run(self, args, cwd):
        captured["args"] = args
        return b""

    monkeypatch.setattr(MaigretAdapter, "binary", classmethod(lambda c: "/usr/bin/true"))
    monkeypatch.setattr(MaigretAdapter, "_run", fake_run)
    MaigretAdapter().fetch(Reference(url="tool://maigret/jdoe", origin_url="tool://maigret/", label="jdoe"))
    assert "--no-recursion" in captured["args"] and "--no-extracting" in captured["args"]

    monkeypatch.setattr(SherlockAdapter, "binary", classmethod(lambda c: "/usr/bin/true"))
    monkeypatch.setattr(SherlockAdapter, "_run", fake_run)
    SherlockAdapter().fetch(Reference(url="tool://sherlock/jdoe", origin_url="tool://sherlock/", label="jdoe"))
    assert "--no-txt" in captured["args"]


def test_tool_working_directory_is_removed_after_fetch(monkeypatch):
    seen = {}

    def fake_run(self, args, cwd):
        # Simulate a tool persisting a report file next to its output.
        (cwd / "report_jdoe_simple.json").write_text("{}")
        seen["cwd"] = cwd
        return b""

    monkeypatch.setattr(MaigretAdapter, "binary", classmethod(lambda c: "/usr/bin/true"))
    monkeypatch.setattr(MaigretAdapter, "_run", fake_run)
    MaigretAdapter().fetch(Reference(url="tool://maigret/jdoe", origin_url="tool://maigret/", label="jdoe"))
    assert not seen["cwd"].exists()  # the throwaway dir and any report are gone
