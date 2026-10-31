from datetime import datetime, timedelta, timezone

from neesha.evidence.models import CollectionMode
from neesha.scope.engine import ScopeEngine
from neesha.scope.models import Scope


def make_scope(**overrides):
    defaults = dict(
        target="acme.com",
        target_type="domain",
        purpose="test",
        observer="target",
    )
    defaults.update(overrides)
    return Scope(**defaults)


def test_passive_allowed_by_default():
    engine = ScopeEngine(make_scope())
    assert engine.authorize("crt.sh", CollectionMode.PASSIVE).allowed


def test_active_blocked_without_authorization():
    engine = ScopeEngine(make_scope())
    decision = engine.authorize("portscan", CollectionMode.ACTIVE)
    assert not decision.allowed
    assert "active collection" in decision.reason


def test_active_allowed_when_authorized():
    engine = ScopeEngine(make_scope(active_authorized=True))
    assert engine.authorize("portscan", CollectionMode.ACTIVE).allowed


def test_denied_source_blocked():
    engine = ScopeEngine(make_scope(denied_sources=["hunter.io"]))
    decision = engine.authorize("hunter.io", CollectionMode.PASSIVE)
    assert not decision.allowed


def test_allowlist_blocks_unlisted_source():
    engine = ScopeEngine(make_scope(allowed_sources=["crt.sh"]))
    assert not engine.authorize("hunter.io", CollectionMode.PASSIVE).allowed
    assert engine.authorize("crt.sh", CollectionMode.PASSIVE).allowed


def test_expired_scope_blocked():
    scope = make_scope(
        expires_at=datetime.now(timezone.utc) - timedelta(days=1)
    )
    decision = ScopeEngine(scope).authorize("crt.sh", CollectionMode.PASSIVE)
    assert not decision.allowed
    assert "expired" in decision.reason
