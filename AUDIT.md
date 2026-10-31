# Recon Harness — Phase 0 Audit

**Audited:** 2026-10-31
**Repo:** `/Users/vorcyber/NEESHA` (project name in-tree: "Neesha")
**Spec:** Recon Harness — internal, analyst-facing OSINT aggregation tool
**Status:** audit only. No code changed. Awaiting review before Phase 1.

---

## 0. Executive summary

The repo contains ~4,600 lines of clean, well-documented, well-tested Python
(73 tests, all passing in 0.16s). The quality of what exists is genuinely good:
the provenance contract, the Admiralty grading tables, the posture collector,
and the DNS cross-resolver layer are all worth keeping. Nothing here is
abandoned scaffolding.

The problem is not quality, it is **identity**. The existing code is a
*sales-targeting assistant* that enriches **people** (Hunter, Apollo, ZoomInfo)
and produces rep-facing briefs. The spec describes an *analyst-facing,
company-first* recon tool that explicitly does not build dossiers on
individuals and does not do outreach. Roughly 60% of the existing code
transfers directly; the people-enrichment layer and the two-surface sales
framing do not.

Second, the spec's two load-bearing control systems **do not exist at all**:

- **Budget ledger** — zero occurrences of budget / cost / spend / cache / tier
  anywhere in the codebase. `neesha passive <domain>` with no `--sources`
  calls every registered adapter, Hunter and Apollo included, with no estimate,
  no reservation, no cap, and no caching.
- **Policy gate / authority basis** — zero occurrences of engagement /
  authority / tier. The only gate is a self-asserted boolean in a JSON file the
  analyst writes themselves, and the tool's own happy path (`neesha run`)
  bypasses it entirely.

Four findings are confirmed by execution, not by reading: an API key written
into exported reports, a plaintext-by-default evidence store, a path traversal
in the dashboard, and a guardrail whose corroboration logic can never fire.

**One decision is needed before Phase 1** — see §6.

---

## 1. Inventory

### Stack

| | |
|---|---|
| Language | Python 3.11+ |
| CLI | Typer + rich |
| Models | pydantic v2 (+ dataclasses in `config.py`, `scope/engine.py`, `resolvers/dns.py`) |
| Storage | SQLite, single file at `data/evidence.sqlite3` |
| Crypto | `cryptography` (Fernet) for two columns |
| DNS | dnspython (system) + DoH over `urllib` (Cloudflare, Google) |
| HTTP | `urllib.request` + certifi; no `requests`, no `httpx`, no async |
| Web | `http.server.BaseHTTPRequestHandler`, server-rendered HTML in a Python string |
| Deploy | Dockerfile (python:3.11-slim) + docker-compose; a Postgres service exists under an opt-in `team` profile but **nothing in the code connects to it** |
| Tests | pytest, 73 tests, all passing |
| Version control | **none — this is not a git repository** |

### Entry points

`neesha` → `neesha.cli.main:app`, with commands:
`version`, `init`, `preflight`, `scope create|check`, `evidence list|export`,
`target`, `posture`, `collectors`, `passive`, `resolve`, `run`, `serve`,
`guardrail verify`, `report` (stub).

### What actually works, end to end

Verified by running the suite and by inspecting committed output for
`example.com` (22 evidence records, posture brief, entity graph, Mermaid map):

- Signed preflight issue/verify with expiry and tamper rejection.
- Scope authorization for source + mode.
- Evidence insert/list/export in JSONL, JSON, CSV, Markdown.
- Posture collection: A/AAAA/MX/NS/SOA/CAA, SPF/DMARC/DKIM, MTA-STS, TLS-RPT,
  DNSSEC, TLS cert, six HTTP security headers, cross-resolver disagreement
  detection, wildcard-DNS detection, A–F grading with record-level drill-down.
- Five passive OSINT collectors (crt.sh, OTX, Wayback, urlscan, HackerTarget).
- Entity resolution with flag-don't-merge semantics, and `subdomain_of` /
  `resolves_to` relationship mapping with Mermaid export.
- Append-only JSONL audit log.
- Guardrail grading, single-source flagging, confidence ceilings.

### What is stubbed or broken

- `neesha report` — prints "not implemented."
- `neesha target` — prints a hardcoded list of step name strings. This is the
  "orchestrator"; there is no planner, no DAG, no execution.
- `ZoomInfoAdapter` — always returns an error, by design.
- `TheHarvesterCollector` — records a line count, not parsed indicators.
- `EnrichmentRouter` — dead code; only its own tests call it.
- `Config.allowed_sources` / `denied_sources` / `retention_days` — written to
  the TOML file, never read by any runtime path.
- `Scope.denied_techniques` — declared, never enforced.
- `Evidence.origin_url` — in the model and schema, never populated by any
  collector.
- `web.py` Mermaid rendering — broken (see B1).
- No retention purge job, despite every record carrying
  `retention_expires_at`.

---

## 2. Spec mapping

### Harness architecture

| Component | Verdict | Notes |
|---|---|---|
| Planner (LLM proposes plan) | **MISSING** | No LLM anywhere. `orchestrator.plan()` returns a static `dict`-keyed list of strings. |
| Tool registry (inputs/outputs/cost/tier) | **REFACTOR** | `collectors/registry.py` exists with name + description. Needs inputs, outputs, cost model, tier, retention policy. |
| Policy gate | **REFACTOR** | `ScopeEngine.authorize(source, mode)` is the right shape and is already called by every collector. Missing: budget check, tier, authority basis, per-run caps, active-technique scope check, and allow/deny/**pause-for-approval** (currently binary). |
| Executor | **REFACTOR** | Collectors run synchronously in a `for` loop in the CLI. No job queue, no retries, no idempotency keys. |
| Pivoting | **MISSING** | Collectors are one-shot per source. No findings-driven pivot, so nothing to gate. |
| Correlator | **KEEP + extend** | `resolve/resolver.py` + `resolve/mapper.py` are solid: never-silently-merge, confidence from distinct source-type count, flagged gray-zone merges. Needs Services and Exposures node types. |
| Reporter | **REFACTOR** | `report/writer.py` emits the per-claim block format and four serializations. Needs the spec's section structure and PDF. |
| Stop conditions | **MISSING** | No step cap, spend cap, wall-time cap, or cancel. No "what was skipped and why." |
| Query log | **REFACTOR** | `audit.py` is a good append-only JSONL log, but records no analyst, no cost, no authority — and `neesha posture` never passes it (B14). |
| LLM token metering | **MISSING** | No LLM. |
| Adapter interface (`search`/`estimate_cost`/`fetch`/`retention_policy`/`tier`) | **REFACTOR** | `Collector` has `run()` + `authorize()` + `record()`. The provenance plumbing in `record()` is worth preserving verbatim; the four other methods need adding. |
| Retention purge job | **MISSING** | Field written, never read. |
| MCP-wrappable adapters | **REFACTOR** | Shape is close; needs the interface above. |

### Source adapters

| Tier | Spec wants | Have | Verdict |
|---|---|---|---|
| A | crt.sh | `CrtShCollector` | **KEEP** |
| A | DNS, WHOIS/RDAP | DNS: full. WHOIS/RDAP: **MISSING** | REFACTOR |
| A | Wayback / CDX | `WaybackCollector` | **KEEP** |
| A | URLScan | `UrlscanCollector` | **KEEP** |
| A | SpiderFoot (self-hosted, API) | — | **MISSING** |
| A | Subfinder, Amass (passive), theHarvester, Recon-ng | theHarvester adapter only, and it only counts output lines | REFACTOR |
| A | Tech stack detection (webanalyze / Wappalyzer) | — | **MISSING** |
| A | GitHub code search | — | **MISSING** |
| A | VirusTotal, Censys (free tiers) | — | **MISSING** |
| A | SEC EDGAR, OpenCorporates, news/RSS | — | **MISSING** |
| A | Shodan InternetDB (free) | — | **MISSING** |
| A | *(extra)* AlienVault OTX, HackerTarget | present, work | **KEEP** — fold into Tier A |
| B | Shodan API | — | **MISSING** |
| B | Hunter (domain search / finder / verifier, cached) | `HunterAdapter`, domain-search only, **uncached, unmetered, key leaks into reports** | **REFACTOR** (see S1, P1) |
| B | HIBP domain search (verified domains only) | — | **MISSING** |
| C | DeHashed, Intelligence X | — | **MISSING** (and the gating machinery they'd need is also missing) |
| D | ZoomInfo, disabled by default | `ZoomInfoAdapter` exists, always errors, **but is registered in `PASSIVE_COLLECTORS` and runs by default** | **REFACTOR** — wrong default |
| — | Apollo.io people search | `ApolloAdapter` | **REPLACE** — not in any spec tier; `mixed_people/search` is a people-first endpoint at odds with company-first (see §6) |

### Budget ledger

Every line item below is **MISSING**. Nothing in this section exists in any
form: monthly cap, per-adapter sub-budgets, per-run caps, reserve-then-settle
with row locks, fixed-cost line items, nightly reconciliation, caching, 75%/90%
alerts, 100% hard stop.

### Data model

| Spec table | Have | Verdict |
|---|---|---|
| `company` | — (`Entity.type == "company"` only as a string) | REFACTOR |
| `domain`, `host` | `Entity.type` in `{domain, asset, ip}` | REFACTOR — untyped strings, no table |
| `service` | — | **MISSING** |
| `exposure` | — | **MISSING** (no severity concept anywhere) |
| `person` | `Entity.type == "person"`; in practice people land as **free text inside `claim`** | **REPLACE** (see P2) |
| `source_record` | `Evidence` — richer than the spec asks for | **KEEP** |
| `query_log` | `audit.py` JSONL | REFACTOR |
| `ledger` | — | **MISSING** |
| `engagement` | — (`Scope` is adjacent but is not an engagement) | **MISSING** |

### UI / design system

| | Verdict |
|---|---|
| `neesha/web.py` (177 lines, server-rendered HTML, blue/gray palette, inline `<style>` string, no tokens, no themes, no tabs, no keyboard nav, no accessibility work, broken Mermaid init, path traversal) | **REPLACE** |

Nothing in the current UI matches the spec: no monochrome token system, no
Inter/JetBrains Mono, no 8px grid, no light/dark from shared tokens, no tabs,
no progressive disclosure, no budget meter, no run view, no severity pills.
Recommend building the React + TS + Tailwind + shadcn/Radix app the spec
describes, and keeping `web.py` running untouched as a stopgap until the
Overview tab is live, then deleting it.

---

## 3. Flagged findings, ranked by severity

### CRITICAL

#### P1 — Hunter API key is written into the evidence DB and into exported reports
`collectors/enrichment.py:67` puts the key in the query string; `record_api()`
stores that URL as `source_url`; `report/writer.py:68` prints
`source: {source_url}` into exported Markdown, and CSV/JSON/JSONL dump the
field verbatim. **Confirmed by execution:**

```
[CLAIM] Hunter.io reports 1 email(s) for acme.com: jane@acme.com
...
source: https://api.hunter.io/v2/domain-search?domain=acme.com&api_key=sk-SUPERSECRET-123
```

Any report shared with a colleague or a client leaks the key.
**Fix:** send credentials in headers only; never store a credentialed URL —
store a redacted canonical URL. **Rotate the Hunter key** if one has ever been
set in this environment, and check `reports/` and any shared exports before
rotating.

*(Also: `URLSCAN_API_KEY` goes in a header — correct — and no hardcoded API key
or secret exists anywhere in the repo. A full grep for key/secret/token/password
literals returned nothing. That part is clean.)*

#### S1 — Spend is completely uncapped, and the default command path spends money
There is no ledger, no cap, no estimate, no reservation, no cache. `neesha
passive <domain>` with **no `--sources`** iterates all of `PASSIVE_COLLECTORS`
(`cli/main.py:327`), which includes `hunter`, `apollo`, and `zoominfo`. Running
`neesha run` twice on one domain pays twice; it is documented in the README as
the one-command happy path. There is nothing to bypass because there is nothing
to bypass *yet* — which makes this a greenfield build, not a repair.
**Fix:** Delivery step 3. Until it lands, strip metered adapters out of the
default source list (one-line change, worth doing in Phase 1).

#### G1 — The preflight gate is bypassed by the tool's own main command
`cli/main.py:429-438`: `neesha run` constructs a `Preflight` in-process,
asserts `storage_encrypted=True` and `retention_policy_set=True` **without
checking either**, signs it with the gate's own key, writes it to disk, and then
"verifies" it. It also writes a `Scope` with an empty `allowed_sources`, which
`ScopeEngine.authorize` treats as *allow every source*
(`scope/engine.py:40`). The gate is decorative on this path.
**Fix:** `run` must consume an existing human-authorized preflight + scope and
fail if absent, like `posture` and `passive` do.

#### G2 — The preflight signing key has a hardcoded fallback committed in the repo
`preflight/gate.py:66` returns `b"neesha-local-dev-key-do-not-use-in-prod"`
when `NEESHA_PREFLIGHT_KEY` is unset. Anyone with the source can mint a valid
preflight file, so the signature proves nothing. `test_tampered_signature_rejected`
passes, but only against that published key.
**Fix:** no fallback — refuse to issue or verify without an explicit key.

### HIGH

#### D1 — The evidence store is plaintext by default, silently
`crypto.py:50-58`: with `NEESHA_STORE_KEY` unset, `make_cipher()` returns
`PlaintextCipher` and nothing warns. The docstring says "the caller warns" —
no caller warns. **Confirmed:** the committed `data/evidence.sqlite3` holds
readable claims and URLs, and a fresh store written with a Hunter result
contains `jane@acme.com` in cleartext on disk. The
`except ImportError` fallback is also dead (`cryptography` is a hard
dependency) and will not catch a malformed-key `ValueError`.
**Fix:** refuse to open a store for real target data without a key; warn loudly
in dev; drop the dead except.

#### D2 — Key derivation is a single unsalted SHA-256
`crypto.py:44-47`. Not a KDF: no salt, no work factor, so the passphrase is
cheap to brute-force offline from a stolen DB file.
**Fix:** scrypt or PBKDF2-HMAC-SHA256 with a per-store random salt persisted
alongside the DB, and a key-version column for rotation.

#### A1 — The active-collection gate is self-asserted, with no engagement and no technique check
No active collector exists today, so **nothing is scanning anything
unauthorized right now** — but the gate that would permit them is not fit to
hold. `neesha scope create --active` sets `active_authorized=True` in a JSON
file the analyst writes for themselves; there is no engagement ID, no second
party, no expiry beyond 30 days, and no scope-permits-*this-technique* check.
`Scope.denied_techniques` is declared at `scope/models.py:33` and **read by
nothing**. `ScopeEngine.authorize` checks only source, mode, and expiry.
**Fix:** Delivery step 3 — authority basis
(`own_org | prospect_company | client_engagement:<id>`), an `engagement` table
with a permitted-technique list, and gate checks against both.

#### Q1 — Query logging is incomplete and misses the whole posture path
`cli/main.py:265` constructs `PostureCollector(...)` **without `audit=`**, so
the single largest evidence producer logs nothing. The log also records no
analyst identity, no cost, and no authority basis — three of the spec's six
required fields. Successful `authorize()` decisions are not logged either
(only denials), so there is no record of what was permitted.

#### B5 — `Collector.record()` hardcodes `collection_mode=PASSIVE`
`collectors/base.py:75`. Whatever mode was authorized, evidence and audit
entries both claim "passive." The moment an active adapter exists, the
provenance record and the audit trail will both be false — which is exactly the
record an engagement review would rely on.

#### B17 — The guardrail's corroboration logic can never fire
`guardrail/engine.py:120-122` groups evidence by normalized **free-text claim
string**. Every collector phrases its claim differently ("crt.sh reports 5
subdomains…", "OTX passive DNS for…"), so no two sources ever land in the same
group. Therefore `corroborated` is always `False`, the ceiling is never lifted,
and `circular-reporting` never fires. **Confirmed** against the committed
`reports/example.com/guardrail.json`: 22 records, **22 flagged
`single-source`**, 0 corroborated, 0 downgraded, 0 dropped.
Compounding it, `origin_url` — the field circular-reporting detection reads —
is **never set by any collector** (only by tests).
**Fix:** corroboration must key on the *resolved fact* (entity + attribute +
value), not on prose. This is the single most important refactor in the
guardrail, because right now the accuracy gate reports a clean pass while
doing almost nothing.

#### B2 — Path traversal in the console dashboard
`web.py:156` passes the URL path straight into `reports_dir / target`.
**Confirmed:** `_target_page(data, reports, "../secret")` reads
`posture.json` from outside the reports directory. Exploitability is limited —
only fixed filenames are read, and the server binds loopback — but it is
unvalidated, unauthenticated path input. The dashboard also has **no auth of
any kind** while rendering decrypted claims including business email addresses.

### MEDIUM

#### P2 — People arrive as free text inside `claim`, not as typed records
`HunterAdapter` writes `"Hunter.io reports 1 email(s) for acme.com:
jane@acme.com"`; `ApolloAdapter` writes people's names the same way. PII buried
in prose cannot be selectively redacted, excluded from an export, retention-
purged, or kept out of the Tier C panel. Every export format dumps it and the
unauthenticated dashboard renders it.
**Note:** there is **no breach/credential adapter at all** (no HIBP, DeHashed,
or Intelligence X), so **no credential or breach-record contents are stored or
displayed today** — the spec's most sensitive category is simply absent. That
is the good news; the bad news is the Tier C gating machinery that would be
required before such an adapter lands is equally absent.

#### B6 — Retention is recorded and never enforced
`Evidence.retention_expires_at` defaults to `utcnow()` (`models.py:71`) — i.e.
records default to *already expired* — and `Collector.record()` overrides it
correctly from the scope. Either way, **no purge job exists**. Zero occurrences
of "purge" in the codebase.

#### B13 — `PostureCollector.run()` violates the `Collector` contract
It returns `tuple[list, PostureBrief]` where the ABC declares
`run() -> list[Evidence]`. It cannot be held in the registry, and every caller
special-cases it.

#### B21 — No rate limiting, backoff, retries, or idempotency
Free-tier crt.sh / OTX / urlscan will 429 under any real workload, and a failed
run has no resumable state. The spec requires a durable queue with retries and
idempotency keys.

#### B24 — This is not a git repository
`git rev-parse` fails. There is no history, no branch, no diff, and no way to
reconstruct what a refactor changed. Given that the next phases rewrite the
gate, the data model, and the UI, **I recommend `git init` plus an initial
commit of the current tree as the very first action of Phase 1**, before any
edit.

### LOW — bugs, dead code, hygiene

| # | Finding |
|---|---|
| B1 | `web.py:59` — `mermaid.initialize({{startOnLoad:true…}})` is in a **non**-f-string, so the doubled braces render literally. Invalid JS; the entity graph has never rendered. Confirmed in output. |
| B3 | `web.py:64` — `_home()` opens an `EvidenceStore` without closing it. One leaked SQLite connection per request. |
| B4 | `web.py:128` — the Mermaid source is rendered twice (once as a diagram, once as `<pre class='muted'>`). Also pulls Mermaid from `cdn.jsdelivr.net`, an external request from a tool whose whole premise is a loopback-only, air-gappable console. |
| B9 | `resolvers/dns.py:143-144` — `keys_present = any(...)` is immediately overwritten by `keys_present = bool(result.records)`. Dead line. |
| B10 | Unused imports: `json` (`collectors/osint.py:11`), `PlaintextCipher` (`evidence/store.py:15`), `Optional` (`posture/brief.py:9`). |
| B11 | `EnrichmentRouter` (`enrichment.py:122`) — dead code; only its own two tests reference it. |
| B12 | `Config.allowed_sources` / `denied_sources` / `retention_days` — serialized to TOML, read by nothing. `Scope` carries its own copies. |
| B19 | `TheHarvesterCollector` records `"collected N lines"` with no parsed indicators and no per-source provenance, and runs `-b crtsh,otx`, duplicating two adapters we already have. Low-value evidence. |
| B20 | `origin_url` is stored plaintext while `source_url` is encrypted — inconsistent sensitivity model for two fields of the same kind. |
| B22 | `normalize.py:16` — the IPv6 candidate regex `[0-9a-fA-F:]{3,}` is very loose; `ipaddress` validation catches most false positives, but hex blobs in claim text can still mis-extract. |
| B23 | Test coverage is parser/unit-level only. Nothing covers `web.py`, any CLI command, the orchestrator, the default-cipher path, or concurrency. **73/73 pass — there are no failing tests.** |
| B25 | `data/`, `runs/`, `reports/` hold committed output. Contents are `example.com` only — **no sensitive target data**. All three are in `.gitignore` (which is moot without a git repo). |

---

## 4. Stack: keep vs. migrate

**Recommendation: keep Python, keep Docker Compose, migrate SQLite → Postgres,
replace `web.py` with the React app.** The existing stack diverges from the
spec's recommended backend in exactly two places that matter, and the compose
file already anticipates one of them.

| Decision | Recommendation | Why | Effort |
|---|---|---|---|
| Python harness + adapters | **Keep** | Already matches the spec. | — |
| SQLite → **Postgres** | **Migrate** | Non-negotiable for the ledger: reserve-then-settle needs `SELECT … FOR UPDATE` row locks, and SQLite's single-writer model cannot provide them under concurrent jobs. It is also the job queue (`SKIP LOCKED`). A compose service already exists under the `team` profile. | **2–3 days.** 22 evidence rows to migrate — trivial data volume. Cost is rewriting `store.py` and adding migrations (Alembic). |
| Job queue | **Add, on Postgres** | Spec's `SKIP LOCKED` approach. No separate service, no Redis. | 1–2 days |
| Typer CLI | **Keep** | Stays useful for ops and backfills alongside the web app. | — |
| `urllib` → `httpx` | **Migrate** | Needs connection pooling, timeouts, retries, and per-host rate limiting for Tier A adapters at volume. `urllib` gives none of it. | 1 day |
| `web.py` → React + TS + Tailwind + shadcn/Radix | **Replace** | Nothing in the current 177-line dashboard survives contact with the spec's design system. Keep it running untouched as a stopgap until the Overview tab is live, then delete. | Per delivery steps 5–6 |
| Docker Compose on one VPS | **Keep** | Already the spec's shape. Add containers for SpiderFoot, the OSINT CLI tools, the worker, and the web app. | 1–2 days |
| Auth for a small team | **Add** | None exists; the dashboard is unauthenticated. | 1–2 days |

**Hosting:** one VPS at ~$10–20/mo as the spec proposes. Everything here is
small — 22 rows today, and a realistic month of company-first recon is
megabytes, not gigabytes.

**On Supabase/managed:** I'd argue against it, and the reason is specific to
this tool. The long-running pieces — SpiderFoot, Amass, Subfinder,
theHarvester, Recon-ng — are self-hosted processes that need a persistent
container, a writable filesystem, and minutes-long runtimes. A managed Postgres
plus serverless functions does not run them; you would end up renting a VPS for
the workers *anyway* and paying for managed Postgres on top (~$25/mo Supabase
Pro + the VPS), for a tool with a $100/mo all-in cap. Managed backup and auth
are the real draw, but nightly `pg_dump` to encrypted object storage and a
small team auth table cover both at a fraction of the budget.

---

## 5. ToS and retention

The spec places the full ToS review in delivery step 2. Flagging now, because
three items may constrain the data model before it is written:

- **Hunter** — caching is contractually encouraged (and required by the spec's
  budget rules), but redistribution of contact data is restricted.
- **HIBP domain search** — permitted only for domains you or the client have
  **verified**. This has to be an enforced precondition in the gate, not a note
  in a doc.
- **Shodan, VirusTotal, Censys free tiers** — each restricts commercial use
  and redistribution; a report delivered to a prospect may be commercial use.
- **DeHashed / Intelligence X** — record-level breach data carries the
  strictest handling terms of anything in the spec, and the spec's own rule
  (never in exports) is tighter than theirs. Keep it that way.

---

## 6. Scope decision — resolved 2026-10-31

**This is an intelligence gathering tool, not a CRM.** Decided by the project
owner during Phase 0 review. The spec supersedes `CLAUDE.md`, whose
"two surfaces, hard separation" principle and rep-facing "Neesha for Sales"
surface are withdrawn.

`CLAUDE.md` is a checked-in instruction file that now contradicts the spec, so
rewriting it is the first substantive item of Phase 1 (see §7).

### Dropped

- The rep-facing surface in its entirety: Opportunity Cards, account search,
  CRM-embedded briefs, CRM sync.
- The Sales Translator layer and the two-representation field mapping it would
  have imposed on every future adapter.
- `ApolloAdapter` — `mixed_people/search` is a people-first endpoint, is in no
  spec tier, and is the most CRM-shaped thing in the repo.
- `Signal.suggested_action` as an outreach prompt. The field survives only as
  an analyst note, or is cut if nothing reads it.
- Any notion of outreach. The spec is explicit and so is the owner.

### Kept, and why it is not CRM

- **`posture/grader.py:97-180`, the finding → remediation mapping.** Reframed
  from "sales triggers / offerings" to exposure → recommended remediation.
  "DMARC at p=none, so spoofed mail is not blocked" is analytic output: it is
  the conclusion an analyst draws from the evidence, and it is the highest-value
  thing in the repo. Relationship management is what makes something a CRM, and
  this is not that.
- **The Overview tab's conversation angle**, because the spec asks for it by
  name — one analytic line, not a pitch.
- **A People & Org tab** limited to business role, business email, and business
  phone, per the spec's own wording. Company-first: people appear as roles
  attached to an organization, never as subjects of their own dossier.

### Consequence for the data model (delivery step 2)

The step-2 tables are the nine the spec names and nothing more: `company`,
`domain`, `host`, `service`, `exposure`, `person`, `source_record`,
`query_log`, `ledger`, `engagement`. No sales-signal tables, no opportunity or
pipeline tables, no CRM identifiers. `person` hangs off `company` and carries
business-contact fields only.

Report export (Markdown/PDF) is the only artifact that leaves the tool, and a
human reviews it before it does. That review is the jargon filter the withdrawn
translator layer was meant to provide, at no build cost and no ongoing tax.

---

## 7. Suggested Phase 1 order

Smallest-first, so each lands verifiably:

1. `git init` + commit the current tree **before touching anything** (B24),
   then rewrite `CLAUDE.md` to the §6 decision so no later change is made
   against withdrawn instructions.
2. P1 — stop the API key reaching storage and reports; rotate the Hunter key.
3. S1 — remove metered adapters from the default source list; move ZoomInfo out
   of `PASSIVE_COLLECTORS` (holds the line until step 3's real ledger).
4. G1, G2 — make `neesha run` consume a human-authorized preflight; delete the
   hardcoded signing key.
5. D1, D2 — refuse plaintext stores for real data; replace SHA-256 with scrypt.
6. B5, Q1 — record the authorized mode truthfully; wire audit into `posture`.
7. B2, B1, B3 — patch the dashboard traversal and the two rendering bugs, or
   delete `web.py` now if the React app starts immediately.
8. B17 — re-key guardrail corroboration onto resolved facts. The largest piece
   of the batch and the one that changes what the accuracy gate actually does.
9. Sweep the LOW table (B9–B22).

**Not touching in Phase 1,** deliberately: the posture collector, the
Admiralty tables, the DNS resolver layer, the entity resolver, and the report
writer's claim-block format. They match the spec, they are tested, and they are
the best code in the repo.
