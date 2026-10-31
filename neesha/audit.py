"""Append-only audit log.

Every collection action — evidence writes and denials — is appended as a
JSONL line with agent, target, source, mode, scope_id, and timestamp. The log
is append-only by construction; it is never rewritten or trimmed by Neesha.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from neesha.evidence.models import utcnow


class AuditLog:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: dict[str, Any]) -> None:
        record = {"timestamp": utcnow().isoformat(), **event}
        with self.path.open("a") as f:
            f.write(json.dumps(record, sort_keys=True, default=str) + "\n")
