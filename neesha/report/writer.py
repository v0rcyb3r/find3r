"""Report writer: serializes evidence and briefs to Markdown/JSON/JSONL/CSV.

The per-claim block format ([CLAIM]/[GRADE]/[FLAGS]/[CONFIDENCE]) is the
output contract from spec section 4.6 and is produced here so it is available
as soon as evidence exists.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

from neesha.evidence.models import Evidence

EVIDENCE_CSV_HEADERS = [
    "evidence_id",
    "target_id",
    "entity_id",
    "claim",
    "source_url",
    "source_type",
    "collected_at",
    "collection_mode",
    "collector",
    "agent",
    "scope_id",
    "confidence",
    "admiralty_source_grade",
    "admiralty_claim_grade",
    "retention_expires_at",
    "is_inference",
    "flags",
]


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_jsonl(path: Path, evidence: Iterable[Evidence]) -> None:
    _ensure_parent(path)
    with path.open("w") as f:
        for e in evidence:
            f.write(json.dumps(e.model_dump(mode="json"), default=str) + "\n")


def write_json(path: Path, evidence: Iterable[Evidence]) -> None:
    _ensure_parent(path)
    data = [e.model_dump(mode="json") for e in evidence]
    path.write_text(json.dumps(data, default=str, indent=2))


def write_csv(path: Path, evidence: Iterable[Evidence]) -> None:
    _ensure_parent(path)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=EVIDENCE_CSV_HEADERS)
        writer.writeheader()
        for e in evidence:
            row = e.model_dump(mode="json")
            row["flags"] = ";".join(e.flags)
            writer.writerow({k: row.get(k, "") for k in EVIDENCE_CSV_HEADERS})


def format_claim_block(e: Evidence) -> str:
    grade = f"{e.admiralty_source_grade.value}{e.admiralty_claim_grade.value}"
    flags = ", ".join(e.flags) or "none"
    source = e.source_url or e.source_type
    label = "INFERENCE" if e.is_inference else "FACT"
    return (
        f"[CLAIM] {e.claim}\n"
        f"[GRADE] {grade}\n"
        f"[FLAGS] {flags}\n"
        f"[CONFIDENCE] {e.confidence.value}\n"
        f"[KIND] {label}\n"
        f"source: {source} | mode: {e.collection_mode.value} | "
        f"collected_at: {e.collected_at.isoformat()}"
    )


def write_markdown(
    path: Path, evidence: Iterable[Evidence], title: str = "Evidence Ledger"
) -> None:
    _ensure_parent(path)
    lines = [f"# {title}", ""]
    for e in evidence:
        lines.append(f"## {e.evidence_id}")
        lines.append(format_claim_block(e))
        lines.append("")
    path.write_text("\n".join(lines))
