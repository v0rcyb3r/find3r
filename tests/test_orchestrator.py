import pytest

from neesha.orchestrator import Orchestrator
from neesha.preflight.gate import PreflightError
from neesha.scope.models import Scope


def write_scope(run_dir, target):
    run_dir.mkdir(parents=True, exist_ok=True)
    scope = Scope(
        target=target, target_type="domain", purpose="qualification", observer="ISP"
    )
    (run_dir / "scope.json").write_text(scope.model_dump_json())
    return scope


def test_require_scope_returns_scope(tmp_path):
    write_scope(tmp_path, "acme.com")
    assert Orchestrator(tmp_path).require_scope().target == "acme.com"


def test_require_scope_accepts_matching_target(tmp_path):
    write_scope(tmp_path, "acme.com")
    scope = Orchestrator(tmp_path).require_scope(expected_target="acme.com")
    assert scope.target == "acme.com"


def test_require_scope_rejects_a_different_target(tmp_path):
    """A scope authorizing one company must not license another."""
    write_scope(tmp_path, "acme.com")
    with pytest.raises(PreflightError, match="authorizes"):
        Orchestrator(tmp_path).require_scope(expected_target="othercorp.com")


def test_require_scope_target_comparison_ignores_case_and_trailing_dot(tmp_path):
    write_scope(tmp_path, "Acme.com.")
    assert Orchestrator(tmp_path).require_scope(expected_target="acme.com")


def test_missing_scope_is_refused(tmp_path):
    with pytest.raises(PreflightError, match="scope.json missing"):
        Orchestrator(tmp_path).require_scope()


def test_missing_preflight_is_refused(tmp_path):
    with pytest.raises(PreflightError, match="preflight.json missing"):
        Orchestrator(tmp_path).require_preflight()
