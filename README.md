# Neesha

**Open-source OSINT targeting for the cybersecurity sales cycle.**

Neesha is an intelligence-targeting assistant for a cybersecurity services
sales team. Seed a domain, organization, person, email, phone, or IP and the
harness resolves entities, hunts passive and scoped-active signals, and
produces intelligence-style briefs for the sales cycle.

Two surfaces, hard separation:

- **Neesha for Sales** — rep-facing. Opportunity Cards, account search,
  CRM-embedded briefs. No CLI, no confidence scores, no infrastructure jargon.
- **Neesha Intelligence Console** — the full harness. CLI, evidence ledger,
  Admiralty grades, scope engine, preflight gate, deployment wizard.

## Principles

1. **Provenance first** — every claim carries evidence_id, source, collected_at,
   collection mode, confidence, and the agent that produced it.
2. **Fact vs inference** — inferences are labeled, never presented as fact.
3. **Passive by default** — active collection requires a scope file and
   authorization; the scope engine blocks anything not allowed.
4. **Accuracy guardrail is a gate** — no report leaves without Admiralty-style
   source/claim grading.
5. **Two surfaces, hard separation** — a Sales Translator converts console
   output into rep-facing language.

## Status

- **Phase 0 — Scaffold**: CLI, config, scope engine, evidence store
  (encrypted-at-rest for sensitive columns), report writer, preflight gate
  (signed file + expiry), containerized dev stack.
- **Phase 1 — Posture core**: DNS (A/AAAA/MX/NS/SOA/CAA), SPF/DMARC/DKIM,
  MTA-STS, TLS-RPT, DNSSEC, TLS certificate, HTTP security headers,
  cross-resolver validation (system + Cloudflare/Google DoH), wildcard-DNS
  detection, A–F grading with transparent record drill-down, and service
  mapping. Every fact is written as provenance-first Evidence.
- **Phase 2 — Accuracy guardrail**: Admiralty source (A–F) and claim (1–6)
  grading, single-source flag, circular-reporting detection, confidence
  ceilings (single secondary source → Medium), weak-single-source
  downgrade/drop, and enforced fact/inference labeling. No report leaves
  without passing the guardrail.
- **Phase 3 — Passive collectors**: crt.sh, AlienVault OTX, Wayback Machine,
  urlscan.io, HackerTarget, and a theHarvester adapter — each scope-gated,
  writing provenance-first Evidence, plus an append-only audit log and a
  collector registry.
- **Phase 4 — Entity resolution + network mapping**: indicator extraction,
  canonicalization, confidence-aware dedupe that flags (never silently merges)
  low-confidence matches, and infrastructure relationships (subdomain_of,
  resolves_to) with Mermaid export.
- **Phase 5 — Enrichment APIs**: Hunter, Apollo, and ZoomInfo adapters with
  multi-provider routing (Hunter-first for email, ZoomInfo for enterprise),
  `source_type=commercial_api`, and the Medium confidence ceiling.

Upcoming: Phase 6 (social + identity cards), Phase 7 (vendor graph), Phase 8
(analyst agents), Phase 9 (sales translator + cards), Phase 10 (model router),
Phase 11 (deployment), Phase 12 (web UI), Phase 13 (plugin SDKs).

## Quickstart

```bash
make install          # venv + editable install (adds [crypto] and [dev])
.venv/bin/neesha --help

.venv/bin/neesha init --mode local --out ./neesha.toml

.venv/bin/neesha preflight \
  --purpose "cybersecurity sales qualification for acme.com" \
  --observer "ISP" --out ./runs/acme

.venv/bin/neesha scope create \
  --target acme.com --type domain --purpose "posture qualification" \
  --allow crt.sh --out ./runs/acme

.venv/bin/neesha target acme.com --type domain --run-dir ./runs/acme

# Posture assessment (writes Evidence + a Security Posture Brief)
.venv/bin/neesha posture acme.com --grade --triggers \
  --run-dir ./runs/acme --out ./reports

.venv/bin/neesha evidence list acme.com
.venv/bin/neesha evidence export --target acme.com --format jsonl --out ./reports

# Accuracy guardrail (Admiralty grades + single-source/circular/ceiling rules)
.venv/bin/neesha guardrail verify --target acme.com --admiralty

# Passive OSINT collection
.venv/bin/neesha collectors
.venv/bin/neesha passive acme.com --sources crt.sh,otx,wayback,urlscan \
  --run-dir ./runs/acme --out ./reports

# Entity resolution + network map (from collected evidence)
.venv/bin/neesha resolve acme.com --store ./data/evidence.sqlite3 --out ./reports

# One command: full local pipeline + local web dashboard
.venv/bin/neesha run acme.com
.venv/bin/neesha serve   # -> http://127.0.0.1:8765
```

Docker dev stack:

```bash
docker compose build
docker compose run --rm neesha --help
```

## Configuration

- `NEESHA_STORE_KEY` — passphrase for evidence-store encryption (derives a
  Fernet key). Unset = plaintext (dev only).
- `NEESHA_PREFLIGHT_KEY` — key that HMAC-signs `preflight.json`.

See `.env.example`.

## Layout

```
neesha/
  cli/          Typer CLI (Intelligence Console)
  config.py     TOML config loader
  evidence/     models (Evidence/Entity/Signal), encrypted store
  scope/        scope model + enforcement engine
  preflight/    signed preflight.json gate
  resolvers/    DNS backends (system + DoH)
  collectors/   collector base + posture + passive OSINT + enrichment adapters
  posture/      parsers, grader, Security Posture Brief
  resolve/      entity resolver + network mapper (Mermaid export)
  web.py        local read-only console dashboard (`neesha serve`)
  orchestrator.py  task-DAG planner + preflight gate
  audit.py      append-only collection audit log
  guardrail/    Admiralty grading + guardrail gate (engine.py)
  report/       MD/JSON/JSONL/CSV writers
```

## Tests

```bash
.venv/bin/pytest -q
```
