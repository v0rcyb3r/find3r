from neesha.evidence.models import CollectionMode, Confidence, Entity, Evidence
from neesha.resolve.resolver import EntityResolver


def make_evidence(claim, source_type="dns", source_url=None):
    return Evidence(
        target_id="example.com",
        claim=claim,
        source_type=source_type,
        source_url=source_url,
        collection_mode=CollectionMode.PASSIVE,
        collector="c",
        agent="a",
        scope_id="s",
    )


def test_resolve_extracts_domain_assets_ips():
    evidence = [
        make_evidence("A records for example.com: 104.20.23.154, 172.66.147.243"),
        make_evidence("crt.sh reports 2 subdomains for example.com: www.example.com, mail.example.com", source_type="osint"),
    ]
    result = EntityResolver().resolve("example.com", evidence)
    by_canon = {e.canonical_name: e for e in result.entities}

    assert by_canon["example.com"].type == "domain"
    assert by_canon["www.example.com"].type == "asset"
    assert by_canon["104.20.23.154"].type == "ip"
    # domain corroborated by dns + osint source types -> HIGH
    assert by_canon["example.com"].confidence == Confidence.HIGH


def test_resolve_seed_without_evidence_is_low():
    result = EntityResolver().resolve("example.com", [])
    assert result.entities[0].canonical_name == "example.com"
    assert result.entities[0].confidence == Confidence.LOW


def test_resolve_ignores_unrelated_domains():
    evidence = [make_evidence("urlscan mentions unrelated.com", source_type="osint")]
    result = EntityResolver().resolve("example.com", evidence)
    assert all("unrelated.com" != e.canonical_name for e in result.entities)


def test_merge_above_threshold():
    a = Entity(type="domain", canonical_name="acme.com")
    b = Entity(type="domain", canonical_name="acm.com")
    merged, flagged = EntityResolver(merge_high=0.9, merge_low=0.5).merge_candidates([a, b])
    assert len(merged) == 1
    assert merged[0].canonical_name == "acme.com"
    assert "acm.com" in merged[0].aliases
    assert len(merged[0].merge_history) == 1
    assert flagged == []


def test_flag_gray_zone_not_merged():
    a = Entity(type="domain", canonical_name="acme.com")
    b = Entity(type="domain", canonical_name="acme.org")
    merged, flagged = EntityResolver(merge_high=0.9, merge_low=0.5).merge_candidates([a, b])
    assert len(merged) == 2  # never silently merged
    assert len(flagged) == 1


def test_no_merge_below_threshold():
    a = Entity(type="domain", canonical_name="acme.com")
    b = Entity(type="domain", canonical_name="zzzzzzzz.io")
    merged, flagged = EntityResolver(merge_high=0.9, merge_low=0.5).merge_candidates([a, b])
    assert len(merged) == 2
    assert flagged == []


def test_ips_are_never_merged_by_similarity():
    a = Entity(type="ip", canonical_name="2606:4700:10::ac42:93f3")
    b = Entity(type="ip", canonical_name="2606:4700:10::6814:179a")
    merged, flagged = EntityResolver().merge_candidates([a, b])
    assert len(merged) == 2
    assert flagged == []
