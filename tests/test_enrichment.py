import neesha.collectors.enrichment as enrich_mod
from neesha.collectors.enrichment import (
    ApolloAdapter,
    EnrichmentRouter,
    HunterAdapter,
)
from neesha.evidence.models import AdmiraltyClaimGrade, AdmiraltySourceGrade, Confidence
from neesha.evidence.store import EvidenceStore
from neesha.scope.engine import ScopeEngine
from neesha.scope.models import Scope


def make_collector(cls, tmp_path, target="example.com"):
    store = EvidenceStore(tmp_path / "e.db")
    scope = Scope(target=target, target_type="domain", purpose="test", observer="target")
    return cls(ScopeEngine(scope), store, target), store


def test_hunter_parses_emails(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTER_API_KEY", "test-key")
    monkeypatch.setattr(enrich_mod, "http_get_json", lambda *a, **k: {
        "data": {"emails": [
            {"value": "jane@example.com", "type": "personal"},
            {"value": "john@example.com", "type": "personal"},
        ]}
    })
    collector, store = make_collector(HunterAdapter, tmp_path)
    evs = collector.run()
    assert len(evs) == 1
    assert "jane@example.com" in evs[0].claim
    assert evs[0].source_type == "commercial_api"
    assert evs[0].confidence == Confidence.MEDIUM
    assert evs[0].admiralty_source_grade == AdmiraltySourceGrade.C
    assert evs[0].admiralty_claim_grade == AdmiraltyClaimGrade.THREE
    assert store.count() == 1


def test_hunter_skips_without_key(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTER_API_KEY", raising=False)
    collector, store = make_collector(HunterAdapter, tmp_path)
    assert collector.run() == []
    assert store.count() == 0


def test_apollo_parses_people(tmp_path, monkeypatch):
    monkeypatch.setenv("APOLLO_API_KEY", "test-key")
    monkeypatch.setattr(enrich_mod, "http_post_json", lambda *a, **k: {
        "people": [
            {"first_name": "Jane", "last_name": "Doe"},
            {"first_name": "John", "last_name": "Smith"},
        ]
    })
    collector, store = make_collector(ApolloAdapter, tmp_path)
    evs = collector.run()
    assert "Jane Doe" in evs[0].claim
    assert store.count() == 1


def test_router_email_hunter_first():
    assert EnrichmentRouter.route("email")[0] == "hunter"


def test_router_enterprise_people_zoominfo_first():
    assert EnrichmentRouter.route("people", enterprise=True)[0] == "zoominfo"
    assert EnrichmentRouter.route("people", enterprise=False)[0] == "apollo"
