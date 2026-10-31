from neesha.evidence.models import CollectionMode, Entity, Evidence, Relationship
from neesha.resolve.mapper import NetworkMapper, to_mermaid
from neesha.resolve.resolver import EntityResolver


def make_evidence(claim, source_type="dns"):
    return Evidence(
        target_id="example.com",
        claim=claim,
        source_type=source_type,
        collection_mode=CollectionMode.PASSIVE,
        collector="c",
        agent="a",
        scope_id="s",
    )


def test_map_relationships():
    evidence = [
        make_evidence("A records for example.com: 104.20.23.154"),
        make_evidence("crt.sh reports subdomains: www.example.com", source_type="osint"),
    ]
    result = EntityResolver().resolve("example.com", evidence)
    relationships = NetworkMapper().map(result.entities, evidence, seed="example.com")

    types = {r.relationship_type for r in relationships}
    assert "subdomain_of" in types
    assert "resolves_to" in types


def test_to_mermaid():
    a = Entity(type="domain", canonical_name="example.com")
    b = Entity(type="ip", canonical_name="1.2.3.4")
    rels = [Relationship(source_entity_id=a.entity_id, target_entity_id=b.entity_id, relationship_type="resolves_to")]
    output = to_mermaid([a, b], rels)
    assert output.startswith("graph TD")
    assert "resolves_to" in output
    assert "example.com" in output
