from neesha.evidence.models import CollectionMode, Confidence, Evidence
from neesha.guardrail.engine import Guardrail, _claim_key


def make_evidence(
    claim,
    source_type="dns",
    source_url=None,
    origin_url=None,
    confidence=Confidence.HIGH,
    is_inference=False,
) -> Evidence:
    return Evidence(
        target_id="acme.com",
        claim=claim,
        source_type=source_type,
        source_url=source_url,
        origin_url=origin_url,
        collection_mode=CollectionMode.PASSIVE,
        collector="test",
        agent="test",
        scope_id="s1",
        confidence=confidence,
        is_inference=is_inference,
    )


def verdicts_for(*items):
    report = Guardrail.apply(list(items))
    return {v.evidence_id: v for v in report.verdicts}, report


def test_unsourced_claim_dropped():
    e = make_evidence("no source anywhere", source_type="")
    _, report = verdicts_for(e)
    assert report.dropped == 1
    assert report.verdicts[0].action == "dropped"
    assert "unsourced" in report.verdicts[0].flags


def test_single_source_dns_kept_and_flagged():
    e = make_evidence("A records: 1.2.3.4", source_url="https://dns.google/resolve")
    v, report = verdicts_for(e)
    verdict = report.verdicts[0]
    assert verdict.action == "keep"
    assert "single-source" in verdict.flags
    assert verdict.grade == "B2"


def test_commercial_api_capped_at_medium():
    e = make_evidence(
        "Jane Doe is CISO at Acme", source_type="commercial_api",
        source_url="https://api.hunter.io/v2/domain-search", confidence=Confidence.HIGH,
    )
    v, report = verdicts_for(e)
    verdict = report.verdicts[0]
    assert verdict.action == "downgraded"
    assert verdict.confidence == Confidence.MEDIUM
    assert verdict.downgraded_from == Confidence.HIGH
    assert "confidence-capped" in verdict.flags


def test_commercial_api_corroborated_not_capped():
    a = make_evidence(
        "Jane Doe is CISO at Acme", source_type="commercial_api",
        source_url="https://api.hunter.io", confidence=Confidence.HIGH,
    )
    b = make_evidence(
        "Jane Doe is CISO at Acme", source_type="official",
        source_url="https://acme.com/team", confidence=Confidence.HIGH,
    )
    _, report = verdicts_for(a, b)
    assert all(v.confidence == Confidence.HIGH for v in report.verdicts)
    assert all("confidence-capped" not in v.flags for v in report.verdicts)
    assert all("single-source" not in v.flags for v in report.verdicts)


def test_press_single_source_capped():
    e = make_evidence(
        "Acme raised a Series B", source_type="press",
        source_url="https://news.example.com/acme", confidence=Confidence.HIGH,
    )
    _, report = verdicts_for(e)
    verdict = report.verdicts[0]
    assert verdict.action == "downgraded"
    assert verdict.confidence == Confidence.MEDIUM
    assert "confidence-capped" in verdict.flags


def test_circular_reporting_detected():
    origin = "https://acme.com/press/launch"
    a = make_evidence("Acme launched X", source_type="press", source_url="https://site1.com", origin_url=origin)
    b = make_evidence("Acme launched X", source_type="press", source_url="https://site2.com", origin_url=origin)
    c = make_evidence("Acme launched X", source_type="press", source_url="https://site3.com", origin_url=origin)
    _, report = verdicts_for(a, b, c)
    assert all("circular-reporting" in v.flags for v in report.verdicts)
    assert all("single-source" in v.flags for v in report.verdicts)


def test_weak_single_source_strict_drops():
    e = make_evidence(
        "CEO is unhappy", source_type="social",
        source_url="https://x.com/u/status/1", confidence=Confidence.MEDIUM,
    )
    report = Guardrail.apply([e], strict=True)
    assert report.verdicts[0].action == "dropped"
    assert "dropped-weak-single-source" in report.verdicts[0].flags


def test_weak_single_source_lenient_downgrades():
    e = make_evidence(
        "CEO is unhappy", source_type="social",
        source_url="https://x.com/u/status/1", confidence=Confidence.MEDIUM,
    )
    report = Guardrail.apply([e], strict=False)
    v = report.verdicts[0]
    assert v.action == "downgraded"
    assert v.confidence == Confidence.LOW
    assert "downgraded-weak-single-source" in v.flags


def test_corroborated_social_not_dropped():
    a = make_evidence("Acme uses FirewallX", source_type="social", source_url="https://x.com/1")
    b = make_evidence("Acme uses FirewallX", source_type="social", source_url="https://linkedin.com/2")
    _, report = verdicts_for(a, b)
    assert all(v.action == "keep" for v in report.verdicts)
    assert all("single-source" not in v.flags for v in report.verdicts)


def test_claim_key_normalizes():
    assert _claim_key("DMARC is p=none.") == _claim_key("dmarc is p none")
    assert _claim_key("A records: 1.2.3.4") == "a records 1 2 3 4"
