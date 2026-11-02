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


def test_gate_denies_account_enum_without_client_engagement(engine):
    view = EngagementView(id="e", authority_basis="public_research",
                          authorized_emails=("dana@gmail.com",),
                          permitted_techniques=frozenset({"account_enumeration"}),
                          starts_at=NOW - timedelta(days=1), expires_at=NOW + timedelta(days=1))
    decision = _gate(engine).authorize(adapter=_spec(), target="dana@gmail.com", engagement=view,
                                       analyst="a", caps=CAPS, state=RunState(), approved=True)
    assert decision.outcome == "denied"
    assert "tier C" in decision.reason


def test_gate_denies_account_enum_without_the_technique(engine):
    view = EngagementView(id="e", authority_basis="client_engagement",
                          authorized_emails=("dana@gmail.com",), permitted_techniques=frozenset(),
                          starts_at=NOW - timedelta(days=1), expires_at=NOW + timedelta(days=1))
    decision = _gate(engine).authorize(adapter=_spec(), target="dana@gmail.com", engagement=view,
                                       analyst="a", caps=CAPS, state=RunState(), approved=True)
    assert decision.outcome == "denied"
    assert "account_enumeration" in decision.reason


def test_gate_pauses_then_allows_under_full_authorization(engine):
    view = EngagementView(id="e", authority_basis="client_engagement",
                          authorized_emails=("dana@gmail.com",),
                          permitted_techniques=frozenset({"account_enumeration"}),
                          starts_at=NOW - timedelta(days=1), expires_at=NOW + timedelta(days=1))
    gate = _gate(engine)
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
