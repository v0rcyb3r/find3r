import pytest

import neesha.collectors.osint as osint_mod
from neesha.collectors.osint import (
    CrtShCollector,
    OtxCollector,
    WaybackCollector,
)
from neesha.evidence.models import AdmiraltyClaimGrade, AdmiraltySourceGrade
from tests.helpers import make_store
from neesha.scope.engine import ScopeEngine, ScopeViolation
from neesha.scope.models import Scope


def make_scope(target="example.com", **overrides):
    defaults = dict(target=target, target_type="domain", purpose="test", observer="target")
    defaults.update(overrides)
    return Scope(**defaults)


def make_collector(cls, tmp_path, target="example.com", **scope_overrides):
    store = make_store(tmp_path / "e.db")
    collector = cls(ScopeEngine(make_scope(target, **scope_overrides)), store, target)
    return collector, store


def test_crtsh_extracts_and_filters_subdomains(tmp_path, monkeypatch):
    monkeypatch.setattr(osint_mod, "http_get_json", lambda *a, **k: [
        {"name_value": "a.example.com\nb.example.com"},
        {"name_value": "*.example.com"},
        {"name_value": "c.other.com"},
    ])
    collector, store = make_collector(CrtShCollector, tmp_path)
    evs = collector.run()
    assert len(evs) == 1
    claim = evs[0].claim
    assert "a.example.com" in claim
    assert "b.example.com" in claim
    assert "example.com" in claim
    assert "c.other.com" not in claim
    assert store.count() == 1


def test_crtsh_extract_subs_static():
    data = [
        {"name_value": "x.example.com\n*.example.com"},
        {"name_value": "y.example.com"},
        {"name_value": "z.example.org"},
    ]
    assert CrtShCollector._extract_subs(data, "example.com") == ["example.com", "x.example.com", "y.example.com"]


def test_otx_parses_passive_dns(tmp_path, monkeypatch):
    monkeypatch.setattr(osint_mod, "http_get_json", lambda *a, **k: {
        "passive_dns": [
            {"hostname": "a.example.com", "address": "1.2.3.4"},
            {"hostname": "b.example.com", "address": "5.6.7.8"},
        ],
        "count": 2,
    })
    collector, store = make_collector(OtxCollector, tmp_path)
    evs = collector.run()
    assert "a.example.com" in evs[0].claim
    assert "1.2.3.4" in evs[0].claim
    assert store.count() == 1


def test_wayback_parses_cdx(tmp_path, monkeypatch):
    monkeypatch.setattr(osint_mod, "http_get_json", lambda *a, **k: [
        ["timestamp", "original", "statuscode"],
        ["20240101", "http://example.com/", "200"],
        ["20240102", "http://www.example.com/about", "200"],
    ])
    collector, _ = make_collector(WaybackCollector, tmp_path)
    evs = collector.run()
    assert "example.com" in evs[0].claim


def test_collector_error_returns_no_evidence(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise ConnectionError("network down")

    monkeypatch.setattr(osint_mod, "http_get_json", boom)
    collector, store = make_collector(CrtShCollector, tmp_path)
    assert collector.run() == []
    assert store.count() == 0


def test_scope_denies_collector(tmp_path, monkeypatch):
    called = {}
    monkeypatch.setattr(osint_mod, "http_get_json", lambda *a, **k: called.setdefault("hit", True) and [])
    collector, _ = make_collector(CrtShCollector, tmp_path, denied_sources=["crt.sh"])
    with pytest.raises(ScopeViolation):
        collector.run()
    assert "hit" not in called


def test_osint_evidence_is_graded_c3(tmp_path, monkeypatch):
    monkeypatch.setattr(osint_mod, "http_get_json", lambda *a, **k: [{"name_value": "a.example.com"}])
    collector, store = make_collector(CrtShCollector, tmp_path)
    evs = collector.run()
    evidence = evs[0]
    assert evidence.source_type == "osint"
    assert evidence.admiralty_source_grade == AdmiraltySourceGrade.C
    assert evidence.admiralty_claim_grade == AdmiraltyClaimGrade.THREE
