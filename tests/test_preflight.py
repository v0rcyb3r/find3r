import json
from datetime import datetime, timedelta, timezone

import pytest

from neesha.preflight.gate import Preflight, PreflightError, PreflightGate


def test_issue_and_verify_roundtrip(tmp_path):
    gate = PreflightGate(key=b"test-key")
    pf = Preflight(purpose="qualification", observer="ISP", deployment_mode="local")
    path = tmp_path / "preflight.json"
    path.write_text(json.dumps(gate.issue(pf)))

    verified = gate.verify(path)
    assert verified.preflight_id == pf.preflight_id


def test_tampered_signature_rejected(tmp_path):
    gate = PreflightGate(key=b"test-key")
    pf = Preflight(purpose="qualification", observer="ISP", deployment_mode="local")
    path = tmp_path / "preflight.json"
    path.write_text(json.dumps(gate.issue(pf)))

    data = json.loads(path.read_text())
    data["purpose"] = "tampered"
    path.write_text(json.dumps(data))

    with pytest.raises(PreflightError, match="signature mismatch"):
        gate.verify(path)


def test_expired_rejected(tmp_path):
    gate = PreflightGate(key=b"test-key")
    pf = Preflight(
        purpose="qualification",
        observer="ISP",
        deployment_mode="local",
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    path = tmp_path / "preflight.json"
    path.write_text(json.dumps(gate.issue(pf)))

    with pytest.raises(PreflightError, match="expired"):
        gate.verify(path)


def test_missing_rejected(tmp_path):
    gate = PreflightGate(key=b"test-key")
    with pytest.raises(PreflightError, match="not found"):
        gate.verify(tmp_path / "nope.json")


# ---- AUDIT.md G2: no hardcoded signing key -------------------------------


def test_no_key_in_env_is_refused(monkeypatch):
    monkeypatch.delenv("NEESHA_PREFLIGHT_KEY", raising=False)
    with pytest.raises(PreflightError, match="NEESHA_PREFLIGHT_KEY"):
        PreflightGate()


def test_env_key_is_used(monkeypatch, tmp_path):
    monkeypatch.setenv("NEESHA_PREFLIGHT_KEY", "a-shared-team-key")
    pf = Preflight(purpose="qualification", observer="ISP", deployment_mode="local")
    path = tmp_path / "preflight.json"
    path.write_text(json.dumps(PreflightGate().issue(pf)))
    assert PreflightGate().verify(path).preflight_id == pf.preflight_id


def test_signature_does_not_verify_under_a_different_key(monkeypatch, tmp_path):
    monkeypatch.setenv("NEESHA_PREFLIGHT_KEY", "team-a-key")
    pf = Preflight(purpose="qualification", observer="ISP", deployment_mode="local")
    path = tmp_path / "preflight.json"
    path.write_text(json.dumps(PreflightGate().issue(pf)))

    monkeypatch.setenv("NEESHA_PREFLIGHT_KEY", "team-b-key")
    with pytest.raises(PreflightError, match="signature mismatch"):
        PreflightGate().verify(path)
