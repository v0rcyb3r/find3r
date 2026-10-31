"""Evidence store: SQLite, provenance-first, encrypted-at-rest for sensitive columns.

Sensitive text columns (``claim``, ``source_url``) are encrypted with the
configured Cipher. Indexed fields (target, entity, mode, grades) stay
plaintext so later phases can query without decrypting everything.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from neesha.evidence.crypto import Cipher, PlaintextCipher, make_cipher
from neesha.evidence.models import (
    AdmiraltyClaimGrade,
    AdmiraltySourceGrade,
    CollectionMode,
    Confidence,
    Evidence,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    entity_id TEXT,
    claim TEXT NOT NULL,
    source_url TEXT,
    origin_url TEXT,
    source_type TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    collection_mode TEXT NOT NULL,
    collector TEXT NOT NULL,
    agent TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    confidence TEXT NOT NULL,
    admiralty_source_grade TEXT NOT NULL,
    admiralty_claim_grade TEXT NOT NULL,
    retention_expires_at TEXT NOT NULL,
    is_inference INTEGER NOT NULL DEFAULT 0,
    flags TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_evidence_target ON evidence(target_id);
CREATE INDEX IF NOT EXISTS idx_evidence_entity ON evidence(entity_id);
"""


def _parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


class EvidenceStore:
    def __init__(self, path: Path | str, cipher: Optional[Cipher] = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.cipher = cipher or make_cipher()
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "EvidenceStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def insert(self, evidence: Evidence) -> str:
        values = (
            evidence.evidence_id,
            evidence.target_id,
            evidence.entity_id,
            self.cipher.encrypt(evidence.claim),
            self.cipher.encrypt(evidence.source_url) if evidence.source_url else None,
            evidence.origin_url,
            evidence.source_type,
            evidence.collected_at.isoformat(),
            evidence.collection_mode.value,
            evidence.collector,
            evidence.agent,
            evidence.scope_id,
            evidence.confidence.value,
            evidence.admiralty_source_grade.value,
            evidence.admiralty_claim_grade.value,
            evidence.retention_expires_at.isoformat(),
            int(evidence.is_inference),
            json.dumps(evidence.flags),
        )
        self._conn.execute(
            """
            INSERT INTO evidence (
                evidence_id, target_id, entity_id, claim, source_url, origin_url, source_type,
                collected_at, collection_mode, collector, agent, scope_id, confidence,
                admiralty_source_grade, admiralty_claim_grade, retention_expires_at,
                is_inference, flags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        self._conn.commit()
        return evidence.evidence_id

    def _row_to_evidence(self, row: sqlite3.Row) -> Evidence:
        return Evidence(
            evidence_id=row["evidence_id"],
            target_id=row["target_id"],
            entity_id=row["entity_id"],
            claim=self.cipher.decrypt(row["claim"]),
            source_url=self.cipher.decrypt(row["source_url"]) if row["source_url"] else None,
            origin_url=row["origin_url"],
            source_type=row["source_type"],
            collected_at=_parse_dt(row["collected_at"]),
            collection_mode=CollectionMode(row["collection_mode"]),
            collector=row["collector"],
            agent=row["agent"],
            scope_id=row["scope_id"],
            confidence=Confidence(row["confidence"]),
            admiralty_source_grade=AdmiraltySourceGrade(row["admiralty_source_grade"]),
            admiralty_claim_grade=AdmiraltyClaimGrade(row["admiralty_claim_grade"]),
            retention_expires_at=_parse_dt(row["retention_expires_at"]),
            is_inference=bool(row["is_inference"]),
            flags=json.loads(row["flags"]),
        )

    def list_by_target(self, target_id: str) -> list[Evidence]:
        cur = self._conn.execute(
            "SELECT * FROM evidence WHERE target_id = ? ORDER BY collected_at",
            (target_id,),
        )
        return [self._row_to_evidence(r) for r in cur.fetchall()]

    def list_targets(self) -> list[str]:
        cur = self._conn.execute("SELECT DISTINCT target_id FROM evidence ORDER BY target_id")
        return [row["target_id"] for row in cur.fetchall()]

    def get(self, evidence_id: str) -> Optional[Evidence]:
        cur = self._conn.execute(
            "SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,)
        )
        row = cur.fetchone()
        return self._row_to_evidence(row) if row else None

    def count(self) -> int:
        cur = self._conn.execute("SELECT COUNT(*) AS n FROM evidence")
        return cur.fetchone()["n"]
