"""Tests for the interim local dashboard.

Narrow on purpose: this surface is scheduled for replacement, so these cover
the security-relevant behavior only.
"""
import neesha.web as web
from tests.helpers import make_store


def seed(tmp_path, target="acme.com"):
    store = make_store(tmp_path / "evidence.sqlite3")
    from neesha.evidence.models import CollectionMode, Evidence

    store.insert(
        Evidence(
            target_id=target,
            claim="DMARC p=none",
            source_type="dns",
            collection_mode=CollectionMode.PASSIVE,
            collector="posture",
            agent="posture",
            scope_id="s1",
        )
    )
    store.close()


def test_mermaid_initializes(tmp_path):
    """The init call used to emit literal doubled braces: invalid JS."""
    page = web._page("t", "<i>x</i>")
    assert "mermaid.initialize({startOnLoad:true" in page
    assert "{{" not in page


def test_traversal_target_is_not_in_known_targets(tmp_path):
    """AUDIT.md B2: the allowlist is what blocks path escape."""
    seed(tmp_path)
    store = make_store(tmp_path / "evidence.sqlite3")
    targets = store.list_targets()
    store.close()
    assert targets == ["acme.com"]
    for hostile in ("../secret", "..%2fsecret", "/etc", "acme.com/../../x"):
        assert hostile not in targets


def test_escape_blocks_html_injection():
    assert "<script>" not in web._escape("<script>alert(1)</script>")
