"""Preflight gate.

Issues and verifies a signed ``preflight.json``. The orchestrator refuses to
run without a valid, unexpired file.

Phase 0 ships the signed-file + expiry gate. The individual checks (identity
separation, network path, inference isolation, etc.) are recorded in the file
but are not yet enforced — that hardening lands with Phase 11 (deployment).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from neesha.evidence.models import utcnow


class PreflightError(Exception):
    """Raised when a preflight file is missing, invalid, or expired."""


class Preflight(BaseModel):
    preflight_id: str = Field(default_factory=lambda: uuid4().hex)
    purpose: str
    observer: str
    deployment_mode: str  # local | vps | hybrid
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(days=1)
    )
    identity_separation: bool = False
    network_path_verified: bool = False
    dns_leak_test_passed: bool = False
    webrtc_disabled: bool = False
    inference_isolation: bool = False
    storage_encrypted: bool = False
    retention_policy_set: bool = False
    kill_switch_documented: bool = False
    local_mode_extras: bool = False  # clean VM, snapshot, ollama verified, no cloud fallback
    vps_mode_extras: bool = False


def _sign(payload: dict[str, Any], key: bytes) -> str:
    msg = json.dumps(payload, sort_keys=True, default=str).encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


class PreflightGate:
    def __init__(self, key: bytes | None = None):
        self.key = key or self._default_key()

    @staticmethod
    def _default_key() -> bytes:
        """Return the signing key, or refuse.

        There is deliberately no fallback. A hardcoded default key ships in
        the source, which means anyone holding the source can mint a valid
        preflight file and the signature proves nothing. AUDIT.md G2.
        """
        env = os.environ.get("NEESHA_PREFLIGHT_KEY")
        if not env:
            raise PreflightError(
                "NEESHA_PREFLIGHT_KEY is not set.\n\n"
                "The preflight gate signs authorization files with it, so there "
                "is no default: a key committed in the source would let anyone "
                "forge an authorization.\n\n"
                "  export NEESHA_PREFLIGHT_KEY=\"$(python3 -c "
                "'import secrets;print(secrets.token_urlsafe(32))')\"\n\n"
                "Use the same key across the team, and keep it out of the repo."
            )
        return env.encode()

    def issue(self, preflight: Preflight) -> dict[str, Any]:
        payload = preflight.model_dump(mode="json")
        payload["signature"] = _sign(payload, self.key)
        return payload

    def verify(self, path: Path) -> Preflight:
        try:
            data = json.loads(path.read_text())
        except FileNotFoundError:
            raise PreflightError(f"preflight file not found: {path}")
        except json.JSONDecodeError as exc:
            raise PreflightError(f"preflight file is not valid JSON: {path}") from exc

        signature = data.pop("signature", None)
        if not signature:
            raise PreflightError(f"{path}: missing signature")
        expected = _sign(data, self.key)
        if not hmac.compare_digest(signature, expected):
            raise PreflightError(f"{path}: signature mismatch")

        preflight = Preflight.model_validate(data)
        if preflight.expires_at <= utcnow():
            raise PreflightError(
                f"{path}: expired at {preflight.expires_at.isoformat()}"
            )
        return preflight
