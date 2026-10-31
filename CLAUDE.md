# Neesha

Internal, analyst-facing OSINT intelligence harness for a cybersecurity
company. An analyst names a company or domain and declares what they need to
know; the harness plans and runs reconnaissance across many sources,
correlates results into one entity graph, and produces a briefing a human
reviews.

It is an intelligence tool, not a CRM. It gathers and analyses; it does not
manage relationships and it does not send outreach.

See `AUDIT.md` for the Phase 0 audit, the recorded scope decisions (§6), and
the remediation order (§7).

## Non-negotiable principles (enforce in every change)

1. **Provenance first.** Every claim carries evidence_id, source,
   collected_at, collection_mode, confidence, Admiralty grade, and the
   producing agent. A grade is never shown without its underlying record.
2. **Fact vs inference.** Inferences are labeled and graded as such. Every
   power-map edge not taken from an org chart or a filing is an inference.
3. **The policy gate is the only path to an outbound call.** Adapters are
   never invoked directly; the executor is the sole caller and acts only on
   gate-approved steps. A pivot is a new gated call, not a shortcut.
4. **Passive by default.** Active techniques require an engagement whose
   scope permits them. Third-party-passive and direct-contact collection are
   distinguished, because direct contact appears in the target's own logs.
5. **Spend is capped before it is spent.** Reserve-then-settle through the
   ledger. No code path may reach a metered API without a reservation.
6. **The accuracy guardrail is a gate.** Admiralty grading, corroboration,
   and confidence ceilings run before any briefing leaves.
7. **Company-first.** People appear as business roles attached to an
   organization, with business contact fields only.

## The intelligence cycle

The build is organized around the cycle, not a fixed pipeline:

- **Direction** — engagement + Priority Intelligence Requirements. PIRs drive
  the collection plan and give the budget a priority order.
- **Collection** — tiered adapters, every call gated.
- **Processing** — typed facts, entity resolution, dedupe.
- **Analysis** — posture grading, exposure severity, power map, signals.
- **Dissemination** — briefing, ordered: what we know, what we infer, what we
  could not answer.
- **Feedback** — run snapshots diffed over time. Change is the signal.

## Dossiers and authority

The dossier is a first-class output, and what may populate it depends on the
authority basis of the run (`own_org`, `prospect_company`,
`client_engagement:<id>`):

- **Company dossier** — runs on any authority, including `prospect_company`.
  Infrastructure, attack surface, exposures, tech stack, business signals,
  people as business roles, power map. This is the default product.
- **Person-level detail** — business role, business email, business phone,
  office location. Also available on `prospect_company`.
- **Tier C inputs** (DeHashed, Intelligence X, Sherlock, Blackbird,
  WhatsMyName) — require `client_engagement:<id>` whose scope permits them.
  These enumerate an individual's personal footprint or breach records, which
  is legitimate assessment scope against a client's own staff under a signed
  engagement, and is not available for prospect research. Company-level
  breach aggregates are available on prospect authority; record-level
  contents are never exported.

The gate enforces this, not convention.

## Collector tiers

- **A** free, runs by default.
- **B** metered, named explicitly, drawn from the ledger.
- **C** authority-gated, never automatic, logged per query.
- **D** contract-gated, built but not runnable without credentials.

`neesha collectors` lists every collector and its tier. The default set is
computed from the tier, so a metered adapter cannot land in it by accident.

## Layout

- `neesha/evidence/` — `models.py` (Evidence/Entity/Signal/Relationship),
  `store.py` (SQLite, encrypted at rest, scrypt-derived key), `crypto.py`.
- `neesha/scope/` — `models.py` (Scope), `engine.py` (ScopeEngine.authorize).
- `neesha/preflight/gate.py` — signed `preflight.json` issue/verify.
- `neesha/orchestrator.py` — plan + preflight/scope gate.
- `neesha/resolvers/dns.py` — system + DoH backends, TXT normalization.
- `neesha/collectors/` — `base.py` (Collector contract, tier, declared mode),
  `posture.py`, `network.py` (TLS/HTTP + `redact_url`), `osint.py`,
  `enrichment.py`, `registry.py` (tiers and the free default set).
- `neesha/posture/` — `facts.py`, `parsers.py`, `grader.py`, `brief.py`.
- `neesha/resolve/` — `normalize.py`, `resolver.py` (never silently merges),
  `mapper.py`.
- `neesha/guardrail/` — `admiralty.py` tables, `engine.py` the gate.
- `neesha/report/writer.py` — MD/JSON/JSONL/CSV, per-claim block format.
- `neesha/web.py` — interim local dashboard; no auth, loopback only,
  scheduled for replacement.
- `neesha/audit.py` — append-only query log.
- `neesha/cli/main.py` — Typer CLI.

## Conventions

- Python 3.11+; Typer, pydantic v2, rich, dnspython, cryptography, certifi.
- All datetimes are timezone-aware UTC.
- New collectors declare `tier` and `collection_mode`, go through
  `ScopeEngine.authorize(source, mode)`, and write `Evidence` with full
  provenance. Failures go to the audit log and are never fabricated into
  evidence.
- Credentials never enter provenance. `Collector.record()` redacts
  `source_url`; keep it that way.
- Every briefing passes `Guardrail.apply(...)`.
- `NEESHA_STORE_KEY` is required. `NEESHA_ALLOW_PLAINTEXT=1` is for throwaway
  local experiments only. `NEESHA_PREFLIGHT_KEY` has no default.
- Run tests with `make test` (SQLite, fast). `make test-pg` additionally
  runs the budget concurrency proof, which needs `make db-up`; the row lock
  it exercises is a no-op on SQLite, so those tests skip rather than pass
  vacuously.
- Schema changes go through Alembic: edit `neesha/db/schema.py`, then
  `alembic revision --autogenerate`, then verify `alembic check` is clean on
  both backends.

## Layout, new layer

- `neesha/db/schema.py` — the 13-table schema (see `DATA_MODEL.md`).
- `neesha/adapters/base.py` — the adapter contract.
- `neesha/ledger/ledger.py` — reserve-then-settle budget ledger.
- `neesha/harness/gate.py` — the policy gate.
- `migrations/` — Alembic, reading `NEESHA_DATABASE_URL`.

## Status

- Phase 0 audit complete (`AUDIT.md`).
- Phase 1 safety pass complete: API key leak, store encryption, preflight
  gate bypass, scope-target binding, spend containment, collection-mode
  provenance, dashboard traversal, dead code.
- Step 2 complete: typed-fact schema, adapter contract, Alembic migrations
  verified on Postgres and SQLite.
- Step 3 complete: ledger and policy gate. The cap holds under concurrency,
  proven against real Postgres and verified to fail without the row lock.

The legacy `Evidence`/`EvidenceStore` path still runs untouched beside the
new layer; cutover happens with the first adapter.

Next: step 4 — the harness loop with crt.sh (free) and Hunter (metered)
end to end.
