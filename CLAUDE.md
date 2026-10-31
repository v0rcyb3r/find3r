# Neesha

Open-source OSINT targeting assistant for a cybersecurity sales team.
Built in phases; see the project spec and `README.md` for the full roadmap.

## Non-negotiable principles (enforce in every change)

1. Provenance first: every claim carries evidence_id, source, collected_at,
   collection_mode, confidence, and producer agent.
2. Fact vs inference: inferences labeled; never present inference as fact.
3. Passive by default: active collection requires scope file + authorization;
   the scope engine blocks anything not allowed.
4. Accuracy guardrail is a gate: Admiralty grading before any report leaves.
5. Two surfaces, hard separation: sales surface never shows console jargon.

## Layout

- `neesha/evidence/` — `models.py` (Evidence/Entity/Signal, provenance contract),
  `store.py` (SQLite, encrypted-at-rest sensitive columns), `crypto.py`.
- `neesha/scope/` — `models.py` (Scope), `engine.py` (ScopeEngine.authorize).
- `neesha/preflight/gate.py` — signed `preflight.json` issue/verify.
- `neesha/orchestrator.py` — task-DAG planner + preflight gate.
- `neesha/resolvers/dns.py` — DNS backends (system + DoH), TXT normalization.
- `neesha/collectors/` — `base.py` (Collector contract), `posture.py`
  (posture collector), `network.py` (TLS/HTTP helpers), `osint.py` (passive
  OSINT collectors), `enrichment.py` (Hunter/Apollo/ZoomInfo adapters),
  `registry.py` (collector registry).
- `neesha/web.py` — minimal local read-only console dashboard (`neesha serve`).
- `neesha/audit.py` — append-only collection audit log.
- `neesha/posture/` — `facts.py` (parsed results), `parsers.py`,
  `grader.py` (A-F rubric), `brief.py` (Security Posture Brief).
- `neesha/resolve/` — `normalize.py` (canonicalization + indicator extraction),
  `resolver.py` (entity resolver; never silently merges), `mapper.py`
  (network mapper + Mermaid).
- `neesha/guardrail/admiralty.py` — Admiralty source/claim grading tables.
- `neesha/guardrail/engine.py` — the guardrail gate (single-source flag,
  circular-reporting detection, confidence ceilings, weak-source downgrade/drop,
  fact/inference enforcement) and `GuardrailReport`.
- `neesha/report/writer.py` — MD/JSON/JSONL/CSV + per-claim block format.
- `neesha/cli/main.py` — Typer CLI.

## Conventions

- Python 3.11+; Typer + pydantic v2 + rich + dnspython + cryptography + certifi.
- All datetimes are timezone-aware UTC.
- New collectors must go through `ScopeEngine.authorize(source, mode)` and
  write `Evidence` with full provenance; failures go to the audit log, never
  fabricated into evidence.
- Every report passes `Guardrail.apply(...)` before it leaves; dropped claims
  are excluded, downgraded claims carry a confidence cap.
- A grade is never shown without its underlying record (transparent drill-down).
- Run tests with `.venv/bin/pytest -q`.

## Current status: Phases 0–5 complete (scaffold, posture, guardrail, passive
collectors, entity resolution, enrichment APIs).
