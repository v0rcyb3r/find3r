# Step 2 — Data model, adapter interface, and ToS constraints

**Status:** for review. No schema has been implemented yet; this is the design
to approve or redirect before I write migrations.

Prerequisite reading: `AUDIT.md` §6 (scope decisions), `CLAUDE.md` (principles).

---

## 1. ToS and licensing constraints

Verified against primary sources on 2026-10-31. Two findings change the
adapter plan, and one changes the budget.

### Blocking: VirusTotal's free API cannot be used by this tool

From VirusTotal's own Public vs Premium documentation, verbatim:

> The Public API must not be used in commercial products or services.
>
> The Public API must not be used in business workflows that do not
> contribute new files.

Neesha is a commercial sales-intelligence workflow that contributes no files.
Both clauses are breached by the normal operation of the tool, and
registering extra accounts to widen the 500/day, 4/min limits is separately
prohibited. **Recommendation: drop VirusTotal from Tier A.** Premium API is
enterprise-priced and would consume the entire budget. Nothing else in the
stack depends on it, and crt.sh, URLScan, and Shodan cover the overlap.

### Budget-breaking: HIBP domain search on client domains is Pro-only

From haveibeenpwned.com/Subscription:

- Every domain search requires you to "prove ownership or control of the
  domain before you can search it."
- "Core plans don't permit domain search on behalf of third parties."
- Customer domain monitoring is a **Pro** feature. Pro 1 is **$379/mo**.

So the spec's "only for domains we or the client have verified" splits in two:

| Use | Plan | Cost |
|---|---|---|
| Our own domain | Core 1 | ~$4.39/mo |
| A client's domain under engagement | Pro 1+ | ~$379/mo |

**Pro 1 alone is nearly 4× the entire $100/mo cap.** Recommendation: build the
adapter, enable it on Core for our own domain only, and treat client-domain
monitoring as a separate commercial decision with its own budget line if a
client engagement ever justifies it. The gate must enforce the verified-domain
precondition regardless of plan — that is a licence condition, not a
nice-to-have.

### Hunter: we are the data controller, so retention is our duty

Hunter's Terms of Service are silent on caching, storage duration, and
redistribution; they defer personal-data handling to the Privacy Policy and
DPA. The operative clause for us is that for personal data obtained through
the API you "remain an independent Controller" under GDPR. Consequences:

- Caching is not prohibited, and the budget rules require it. Cache freely.
- The retention clock is **ours** to set and enforce, which makes the purge
  job a compliance control, not housekeeping.
- Section 8 bars building "a similar or competitive service." A dossier tool
  for internal sales use is not that; reselling the contact data would be.

### Remaining sources

| Source | Constraint | Retention |
|---|---|---|
| crt.sh | Public CT logs, no key. Be polite; no documented rate limit. | Indefinite — public record |
| DNS / RDAP | Public protocol | Indefinite |
| Wayback / CDX | Public archive, courtesy rate limits | 90d cache |
| URLScan | Free tier keyed; public scans only | 90d |
| Shodan InternetDB | Free, no key, host lookups | 30d |
| Shodan API | ~$49 one-time membership gives 100 query credits/mo; Freelancer ~$69/mo. **Official pricing page is stale — confirm at signup.** A credit covers up to 100 results; filters and paging past page 1 spend credits. | 30d |
| Censys | Free tier ~250 queries/mo, host/web-property/cert lookups only, concurrency 1. Verify on the token page. | 30d |
| GitHub code search | Token required; free. Secondary rate limits on search. | 30d, and **never store the secret value** — store the finding, location, and a fingerprint |
| SEC EDGAR | Public domain. Requires a descriptive User-Agent with contact details. | Indefinite |
| OpenCorporates | Free tier is restrictive; attribution and redistribution terms apply | 90d |
| Google Programmable Search | Metered. Scraping the HTML SERP violates ToS and gets IP-banned — API only. | 30d |
| Subfinder / theHarvester / SpiderFoot | Self-hosted; the ToS that matter are those of the upstream sources each queries | Per-source |
| HIBP | Verified domains only; see above | Aggregates 90d; **record-level never stored** |
| DeHashed / Intelligence X | Engagement-gated. Strictest handling terms in the stack. | Aggregates 30d; **record-level never persisted — fetched, displayed, discarded** |
| Sherlock / Blackbird / WhatsMyName | Self-hosted, but output is personal data. Engagement-gated. | 7d, engagement-scoped, purged at engagement close |

---

## 2. The pivot: typed facts

Today a claim is prose: `"A records for acme.com: 1.2.3.4, 5.6.7.8"`. You
cannot corroborate prose, diff it between runs, build a power map from it, or
redact one field of it. Everything in the redesign rests on replacing it.

```sql
CREATE TABLE fact (
    id              TEXT PRIMARY KEY,
    entity_id       TEXT NOT NULL REFERENCES entity(id),
    attribute       TEXT NOT NULL,      -- 'dns.a', 'email.dmarc.policy', 'tls.not_after'
    value           TEXT NOT NULL,      -- canonical string form
    value_type      TEXT NOT NULL,      -- str | int | bool | datetime | ipaddr | domain
    unit            TEXT,
    observed_at     TIMESTAMPTZ NOT NULL,
    run_id          TEXT NOT NULL REFERENCES run(id),
    source_record_id TEXT NOT NULL REFERENCES source_record(id),
    confidence      TEXT NOT NULL,      -- high | medium | low | unknown
    is_inference    BOOLEAN NOT NULL DEFAULT FALSE,
    admiralty_source CHAR(1) NOT NULL,
    admiralty_claim  CHAR(1) NOT NULL,
    sensitivity     TEXT NOT NULL DEFAULT 'business',
                    -- business | personal | restricted
    retention_expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE (entity_id, attribute, value, run_id)
);
CREATE INDEX idx_fact_attr  ON fact(entity_id, attribute);
CREATE INDEX idx_fact_corr  ON fact(attribute, value);
CREATE INDEX idx_fact_purge ON fact(retention_expires_at);
```

Four things this unlocks that the audit found broken or impossible:

1. **Corroboration becomes real.** Two source records asserting the same
   `(attribute, value)` from different origins corroborate. The guardrail bug
   where 22/22 records flagged `single-source` (B17) is a direct consequence
   of grouping on prose, and this fixes it at the root.
2. **Diffing becomes possible.** Same `(entity, attribute)`, different
   `value`, later `observed_at` = a change, which is the signal.
3. **The power map has a substrate.** `reports_to` is an edge between two
   person entities, not a sentence.
4. **Redaction becomes mechanical.** `sensitivity` is the column the exporter
   and the Tier C panel filter on. Prose cannot be filtered.

`claim` does not disappear — it becomes a *rendered view* of a fact, produced
at display time. The `[CLAIM]/[GRADE]/[FLAGS]/[CONFIDENCE]` block format in
`report/writer.py` is kept exactly as-is and fed from facts.

### Attribute namespace

Dotted, stable, and the contract between collectors and analysis:

```
dns.a  dns.aaaa  dns.mx  dns.ns  dns.caa  dns.soa  dns.wildcard
email.spf.record  email.spf.qualifier  email.dmarc.policy  email.dmarc.pct
email.dkim.selector  email.mtasts.present  email.tlsrpt.present
dnssec.status
tls.issuer  tls.not_after  tls.san  tls.days_remaining
http.header.hsts  http.header.csp  http.status  http.final_url
host.port  host.service.product  host.service.version  host.asn  host.provider
tech.cms  tech.framework  tech.cdn  tech.waf  tech.analytics
repo.url  repo.language  repo.secret_finding
person.role  person.function  person.seniority  person.business_email
person.business_phone  person.office_location
org.legal_name  org.subsidiary  org.filing.risk_factor  org.news.headline
breach.aggregate.count  breach.aggregate.most_recent
```

---

## 3. Entities

One `entity` table with a type discriminator plus per-type attribute tables
would normalize further, but the attribute data already lives in `fact`, so
entities stay thin and typed by `kind`:

```sql
CREATE TABLE entity (
    id             TEXT PRIMARY KEY,
    kind           TEXT NOT NULL,   -- company | domain | host | service
                                    -- | person | exposure | vendor
    canonical_name TEXT NOT NULL,
    company_id     TEXT REFERENCES entity(id),   -- company-first: everything
                                                 -- non-company hangs off one
    aliases        JSONB NOT NULL DEFAULT '[]',
    confidence     TEXT NOT NULL,
    resolved_by    TEXT,
    merge_history  JSONB NOT NULL DEFAULT '[]',
    first_seen_at  TIMESTAMPTZ NOT NULL,
    last_seen_at   TIMESTAMPTZ NOT NULL,
    UNIQUE (kind, canonical_name, company_id)
);
```

`company_id` is how "company-first" is enforced structurally rather than by
convention: a `person` with no company is rejected at write time, which makes
a standalone individual dossier unrepresentable in the schema.

`person` facts are restricted at the adapter contract: only the six
`person.*` attributes above may be written on `prospect_company` authority,
all at `sensitivity='business'`.

```sql
CREATE TABLE relationship (
    id            TEXT PRIMARY KEY,
    source_entity_id TEXT NOT NULL REFERENCES entity(id),
    target_entity_id TEXT NOT NULL REFERENCES entity(id),
    kind          TEXT NOT NULL,  -- subdomain_of | resolves_to | runs_service
                                  -- | reports_to | owns_budget_for
                                  -- | influences | incumbent_vendor_of
                                  -- | employee_of | same_as
    confidence    TEXT NOT NULL,
    is_inference  BOOLEAN NOT NULL DEFAULT FALSE,
    inferred_by   TEXT,           -- e.g. 'title-parse-v1' — show the method
    fact_ids      JSONB NOT NULL DEFAULT '[]',
    UNIQUE (source_entity_id, target_entity_id, kind)
);
```

`inferred_by` exists so a power-map edge can show *how* it was guessed. An
org chart the analyst cannot interrogate is worse than no org chart.

---

## 4. Direction

```sql
CREATE TABLE engagement (
    id              TEXT PRIMARY KEY,
    authority_basis TEXT NOT NULL,   -- own_org | prospect_company
                                     -- | client_engagement
    client_name     TEXT,
    permitted_techniques JSONB NOT NULL DEFAULT '[]',
                    -- 'active_scan','brute_subdomain','username_enum',
                    -- 'breach_records','amass_active'
    authorized_domains   JSONB NOT NULL DEFAULT '[]',
    authorized_by   TEXT NOT NULL,
    document_ref    TEXT,            -- signed SOW / authorization letter
    starts_at       TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL
);

CREATE TABLE pir (
    id          TEXT PRIMARY KEY,
    run_id      TEXT NOT NULL REFERENCES run(id),
    question    TEXT NOT NULL,
    template    TEXT,               -- 'email-security-fit', 'who-owns-budget'
    status      TEXT NOT NULL,      -- answered | partial | unanswerable | open
    answer      TEXT,
    fact_ids    JSONB NOT NULL DEFAULT '[]',
    gap_reason  TEXT                -- why it could not be answered
);

CREATE TABLE run (
    id            TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagement(id),
    company_id    TEXT NOT NULL REFERENCES entity(id),
    analyst       TEXT NOT NULL,
    status        TEXT NOT NULL,    -- planning | awaiting_approval | running
                                    -- | complete | stopped | failed
    stop_reason   TEXT,             -- budget | step_cap | wall_time
                                    -- | cancelled | complete
    skipped       JSONB NOT NULL DEFAULT '[]',   -- what and why
    max_steps     INTEGER NOT NULL,
    max_spend_usd NUMERIC(10,4) NOT NULL,
    max_wall_secs INTEGER NOT NULL,
    started_at    TIMESTAMPTZ NOT NULL,
    ended_at      TIMESTAMPTZ
);
```

`run.skipped` and `pir.gap_reason` are what make the briefing able to say
"PIR-2 partial: no org data collected" instead of silently under-delivering.

---

## 5. Analysis

```sql
CREATE TABLE exposure (
    id           TEXT PRIMARY KEY,
    company_id   TEXT NOT NULL REFERENCES entity(id),
    entity_id    TEXT REFERENCES entity(id),   -- the affected host/domain
    kind         TEXT NOT NULL,   -- 'email.dmarc.unenforced', 'tls.expiring'
    severity     TEXT NOT NULL,   -- critical | high | medium | low
    title        TEXT NOT NULL,
    consequence  TEXT NOT NULL,   -- the business consequence, in plain words
    remediation  TEXT NOT NULL,   -- the offering that addresses it
    stakeholder_function TEXT,    -- which role owns it  <-- the connective hop
    fact_ids     JSONB NOT NULL DEFAULT '[]',
    first_seen_at TIMESTAMPTZ NOT NULL,
    resolved_at  TIMESTAMPTZ      -- set when a later run no longer sees it
);

CREATE TABLE signal (
    id          TEXT PRIMARY KEY,
    company_id  TEXT NOT NULL REFERENCES entity(id),
    kind        TEXT NOT NULL,   -- leadership_change | vendor_displacement
                                 -- | funding | hiring | legal_event
                                 -- | infrastructure_change | cert_expiry
                                 -- | breach_disclosure | new_subdomain
    description TEXT NOT NULL,
    why_now     TEXT NOT NULL,
    score       NUMERIC(5,2) NOT NULL DEFAULT 0,
    confidence  TEXT NOT NULL,
    detected_in_run TEXT NOT NULL REFERENCES run(id),
    fact_ids    JSONB NOT NULL DEFAULT '[]'
);
```

`exposure.stakeholder_function` is the hop discussed in design: the
misconfiguration selects the role to approach. It is the join between the
posture half of the tool and the power-map half.

`exposure.resolved_at` plus `signal.detected_in_run` are the temporal
machinery: a second run closes exposures it no longer observes and raises
signals for what changed.

---

## 6. Control

```sql
CREATE TABLE source_record (
    id            TEXT PRIMARY KEY,
    run_id        TEXT NOT NULL REFERENCES run(id),
    adapter       TEXT NOT NULL,
    tier          CHAR(1) NOT NULL,
    request_url   TEXT,            -- REDACTED of credentials, always
    origin_url    TEXT,            -- canonical origin, for circular reporting
    collected_at  TIMESTAMPTZ NOT NULL,
    collection_mode TEXT NOT NULL, -- third_party_passive | direct_contact
                                   -- | active
    raw_payload   BYTEA,           -- encrypted; purged on adapter retention
    raw_sha256    CHAR(64) NOT NULL,
    http_status   INTEGER,
    retention_expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE query_log (        -- append-only; no UPDATE or DELETE grant
    id            BIGSERIAL PRIMARY KEY,
    occurred_at   TIMESTAMPTZ NOT NULL,
    analyst       TEXT NOT NULL,
    run_id        TEXT,
    engagement_id TEXT,
    authority_basis TEXT NOT NULL,
    adapter       TEXT NOT NULL,
    tier          CHAR(1) NOT NULL,
    target        TEXT NOT NULL,
    decision      TEXT NOT NULL,  -- allowed | denied | paused | settled
    decision_reason TEXT,
    estimated_usd NUMERIC(10,4),
    actual_usd    NUMERIC(10,4)
);

CREATE TABLE ledger (
    id            BIGSERIAL PRIMARY KEY,
    period        CHAR(7) NOT NULL,         -- '2026-10'
    adapter       TEXT NOT NULL,
    run_id        TEXT,
    kind          TEXT NOT NULL,  -- reservation | settlement | fixed_cost
                                  -- | llm_tokens | adjustment
    estimated_usd NUMERIC(10,4) NOT NULL DEFAULT 0,
    actual_usd    NUMERIC(10,4),
    state         TEXT NOT NULL,  -- reserved | settled | released
    created_at    TIMESTAMPTZ NOT NULL,
    settled_at    TIMESTAMPTZ
);
CREATE INDEX idx_ledger_period ON ledger(period, adapter, state);

CREATE TABLE budget (
    period        CHAR(7) NOT NULL,
    adapter       TEXT NOT NULL DEFAULT '*',  -- '*' = the monthly cap
    cap_usd       NUMERIC(10,2) NOT NULL,
    PRIMARY KEY (period, adapter)
);

CREATE TABLE cache (
    key           TEXT PRIMARY KEY,   -- sha256(adapter|method|canonical args)
    adapter       TEXT NOT NULL,
    payload       BYTEA NOT NULL,     -- encrypted
    created_at    TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL
);
```

**Note on `collection_mode`:** it gains a third value. The audit flagged that
a TLS handshake and an HTTP GET against a prospect's own site are not "active
scanning" but are not third-party-passive either — they appear in the
target's logs. `direct_contact` makes that visible, and the gate can be told
to refuse it where OPSEC matters.

Spend safety is one constraint, enforced in a transaction:

```sql
-- inside BEGIN; ... COMMIT;
SELECT cap_usd FROM budget WHERE period = $1 AND adapter = '*' FOR UPDATE;
-- sum reservations + settlements for the period, compare, then insert
```

The row lock on the `budget` row is what makes concurrent workers unable to
oversubscribe. This is the piece SQLite cannot do properly and the reason for
the Postgres migration.

---

## 7. Adapter interface

```python
class Adapter(Protocol):
    name: ClassVar[str]
    tier: ClassVar[str]                    # A | B | C | D
    collection_mode: ClassVar[CollectionMode]
    produces: ClassVar[frozenset[str]]     # attribute names it can emit
    accepts: ClassVar[frozenset[str]]      # entity kinds it takes as input
    requires_techniques: ClassVar[frozenset[str]] = frozenset()

    def estimate_cost(self, request: Request) -> Cost: ...
    def retention_policy(self) -> timedelta: ...
    def cache_key(self, request: Request) -> str: ...
    def search(self, request: Request) -> list[Reference]: ...
    def fetch(self, reference: Reference) -> RawResult: ...
    def parse(self, raw: RawResult) -> list[FactDraft]: ...
```

`produces` is what makes the deterministic planner work: a PIR declares the
attributes that would answer it, and the planner selects adapters whose
`produces` intersects that set, ordered by tier then cost. No LLM needed, and
it is a table test.

`parse()` returning `FactDraft` rather than writing directly keeps collection
and processing separable, which is what lets a cached payload be re-parsed
without re-paying for the call.

`requires_techniques` is checked against `engagement.permitted_techniques` by
the gate. Sherlock declares `{'username_enum'}` and therefore cannot run
without an engagement that permits it — enforced by the schema, not by
remembering.

Every adapter is wrappable as an MCP server: `search`/`fetch`/`parse` map
onto tool calls, and `estimate_cost`/`retention_policy` onto metadata.

---

## 8. Migration of existing data and code

| Existing | Plan |
|---|---|
| `Evidence` | Split: provenance → `source_record`, assertion → `fact`. Keep the pydantic model as the write-time DTO. |
| `data/evidence.sqlite3` (22 rows, example.com) | Not migrated. Test data; re-collect. |
| `posture/parsers.py`, `grader.py`, `brief.py` | **Keep unchanged.** Parsers already produce typed results — they become the first `parse()` implementations, which is the cleanest possible proof of the fact model. |
| `guardrail/admiralty.py` | Keep. Tables are sound. |
| `guardrail/engine.py` | Re-key corroboration from `_claim_key(prose)` to `(attribute, value)`. The single most valuable change in the batch. |
| `resolve/resolver.py`, `mapper.py` | Keep the never-silently-merge logic; feed from facts, add `runs_service` and the power-map edges. |
| `resolvers/dns.py`, `collectors/network.py` | Keep as-is. |
| `report/writer.py` | Keep the claim-block format; render from facts. |
| `scope/` | Subsumed by `engagement`. `ScopeEngine.authorize` becomes the gate's source-and-mode check, keeping its tests. |
| `collectors/base.py` | Becomes `adapters/base.py` with the interface above. `record()`'s redaction and audit plumbing carry over intact. |
| SQLite → Postgres | Alembic from the start. Keep the SQLite path for local single-user dev if cheap; drop it if it costs abstraction. |
| `web.py` | Delete when the Overview lands. |

---

## 9. Decisions — resolved 2026-10-31

Approved, with the stated preference for the leanest workable tool.

1. **VirusTotal: dropped.** Its public API terms prohibit this exact use.
   crt.sh, URLScan and Shodan cover the overlap.
2. **HIBP: own domain only, on Core (~$4.39/mo).** The adapter will be built
   with the verified-domain precondition enforced in the gate regardless of
   plan, since that is a licence condition. Client-domain monitoring stays a
   separate commercial decision at ~$379/mo.
3. **Postgres is the deployment target, with one portable schema.**
   SQLAlchemy Core plus Alembic, so the DDL is written once rather than
   twice. Postgres runs locally through the Compose file; SQLite remains the
   test backend because it is an order of magnitude faster to spin up.
   Maintaining two hand-written backends would have been the opposite of
   lean.
4. **Cap stays $100/mo**, inclusive of hosting and LLM tokens. Shodan
   membership is a one-time ~$49 recorded as a fixed-cost ledger line, not a
   recurring draw.

### Implementation status

Done in this pass:

- `neesha/db/schema.py` — 13 tables, 22 CHECK constraints, portable between
  SQLite and Postgres via `with_variant`.
- `neesha/adapters/base.py` — the adapter contract and its value types.
- `migrations/` — Alembic configured to read `NEESHA_DATABASE_URL`, with the
  initial revision. Verified: upgrade creates all 13 tables, `alembic check`
  reports no drift against the model, downgrade returns to base.
- `tests/test_schema.py`, `tests/test_adapters.py` — 34 new tests. 129 total.
- Compose now starts Postgres by default and refuses to start without the
  three required secrets, rather than falling back to a default password.

**One design bug the tests caught**, worth recording because it would have
been expensive later: the `fact` uniqueness constraint was originally keyed
on `(entity_id, attribute, value, run_id)`, which would have rejected the
second source asserting the same fact in a run — that is, it would have made
corroboration *unstorable*, reintroducing the exact failure the table exists
to fix. It is now keyed on `source_record_id`, which deduplicates a single
source repeating itself while letting independent sources agree.

### Not done, deliberately

- **Append-only enforcement on `query_log`** is a Postgres GRANT, not a
  schema object. It belongs in the deployment migration alongside the
  application role, and is noted in `schema.py`.
- **No data migrated** from `data/evidence.sqlite3`. 22 example.com rows of
  test data; it will be re-collected.
- **The existing `Evidence`/`EvidenceStore` path still runs.** Nothing is
  cut over yet, so the tool keeps working while the new layer is built
  beside it. The cutover happens with the first adapter.

Next: step 3, the ledger and policy gate, with the concurrency tests that
prove the cap cannot be exceeded. That is the piece that genuinely needs
Postgres, so it is also where the local Compose Postgres gets exercised.
