"""Orchestrator: plans the task DAG and enforces the preflight gate.

Phase 0 ships the gate check and a static plan. Collector execution arrives
with Phases 1 and 3.
"""
from __future__ import annotations

from pathlib import Path

from neesha.preflight.gate import Preflight, PreflightError, PreflightGate
from neesha.scope.models import Scope

_STEPS_BY_TYPE = {
    "domain": [
        "TargetResolver",
        "PostureCollector(dns, email-auth, tls, headers)",
        "PassiveCollector(crt.sh, wayback, urlscan, otx)",
        "AccuracyGuardrail",
        "ReportWriter",
    ],
    "org": [
        "TargetResolver",
        "EnrichmentAdapter(hunter/zoominfo/apollo)",
        "SocialScanner(linkedin, x, github)",
        "VendorGraph",
        "AccuracyGuardrail",
        "ReportWriter",
    ],
    "person": [
        "TargetResolver",
        "SocialScanner(linkedin, x, github)",
        "EntityResolver",
        "AccuracyGuardrail",
        "ReportWriter",
    ],
    "email": ["TargetResolver", "EnrichmentAdapter(hunter)", "AccuracyGuardrail", "ReportWriter"],
    "phone": ["TargetResolver", "EnrichmentAdapter", "AccuracyGuardrail", "ReportWriter"],
    "ip": ["TargetResolver", "PassiveCollector(shodan-free, otx)", "AccuracyGuardrail", "ReportWriter"],
}


class Orchestrator:
    def __init__(self, run_dir: Path | str):
        self.run_dir = Path(run_dir)

    def require_preflight(self) -> Preflight:
        path = self.run_dir / "preflight.json"
        if not path.exists():
            raise PreflightError(
                "preflight.json missing — run `neesha preflight` first"
            )
        return PreflightGate().verify(path)

    def require_scope(self) -> Scope:
        path = self.run_dir / "scope.json"
        if not path.exists():
            raise PreflightError(
                "scope.json missing — run `neesha scope create` first"
            )
        return Scope.model_validate_json(path.read_text())

    def plan(self, seed: str, seed_type: str) -> list[str]:
        base = _STEPS_BY_TYPE.get(seed_type, ["TargetResolver", "AccuracyGuardrail", "ReportWriter"])
        return [f"{step} -> {seed}" for step in base]
