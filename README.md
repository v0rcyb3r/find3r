# NEESHA

NEESHA is an internal OSINT intelligence harness for cybersecurity analysts.
Investigations may start from a company domain or an independent exact email.
An analyst states Priority Intelligence
Requirements (PIRs), and reviews collected assertions, inferences, and gaps.
It does not manage a CRM or send outreach.

The workspace integrates six free collectors: **company website** (published
business contacts, explicit professional roles, actual homepage headers),
**DNS posture** (DNS, SPF, DMARC), **crt.sh**, **AlienVault OTX**, **Wayback CDX**,
and existing **urlscan** observations. **Hunter** is optional paid enrichment,
not a prerequisite for contacts. An optional **Subfinder** runner is implemented
but disabled until its home-directory configuration writes are approved. Certificate
transparency records describe historical certificate observations; they do not
prove a host is currently reachable or vulnerable.

## Run locally

Python 3.11+ is required. From the repository root:

```bash
make install
# Initialize the local SQLite harness database:
.venv/bin/alembic upgrade head

.venv/bin/neesha harness engagement create \
  --domain example.com --by analyst@example.org

# Free certificate-transparency collection, no API key required:
.venv/bin/neesha harness run example.com --pir attack-surface --out ./reports
```

## Local investigator workspace

```bash
.venv/bin/neesha harness serve --port 8766
# Open http://127.0.0.1:8766
```

The new workspace reads the harness database. Enter a domain or website and
select Investigate to collect passive public-source and website observations.
No authorization setup is required for public company research. Each run
automatically records a domain-scoped research context for provenance; it
does not grant permission for active testing. Free website contact extraction runs by default and can be turned off.
Optional paid enrichment uses Hunter and the configured monthly budget,
with a $1 per-run cap. The UI
shows recent runs, requirements and gaps, infrastructure, business contacts,
and source records, with JSON export. It does not invent a posture score or
power-map relationships when collection does not support them.

The server binds only to `127.0.0.1`, serves its assets locally, checks request
hosts, and requires an origin check and session token for writes. It has no
multi-user authentication and is intended for a trusted local machine only.
Names, phone numbers, and IPs are recognized but need further resolution.
Exact emails, including Gmail and other public-mailbox addresses, can run
independent public-source research. Email runs do not invent a company, person,
or mailbox-provider affiliation; scope covers only the exact address and never
authorizes research against the provider domain. Corporate email domains remain
optional separate research candidates. Reporting-line relationships remain a
future integration. Website research extracts only published business
contacts; named roles currently require explicit structured company affiliation. The legacy `neesha serve`
command still opens the older dashboard.

Each CLI run writes a Markdown briefing and a JSON equivalent to `reports/<run-id>`.
Briefings separate observations from inferences and unanswered requirements.
Each exported assertion includes the underlying fact and source-record IDs,
source URL, original collection time, collection mode, confidence, and Admiralty
grade. The accuracy gate runs before export. Company runs exclude expired and
non-business facts; independent email runs additionally allow only exact-root
`public.*` personal observations. Restricted facts and raw provider payloads
are never exported. Requirement statuses are adjusted when
their supporting records cannot be exported.

For optional paid enrichment, set `HUNTER_API_KEY` and a conservative positive
`HUNTER_ESTIMATED_USD_PER_SEARCH` in your environment, then configure the current
month's budget before collecting:

```bash
.venv/bin/neesha harness budget set 10
.venv/bin/neesha harness run example.com \
  --pir attack-surface --pir who-to-contact --max-spend 1
.venv/bin/neesha harness budget show
```

Additional options: `--engagement <id>`, `--analyst`, `--max-steps`,
`--max-seconds`, and repeatable `--pir`. The `email-security-fit` template exists,
and the CLI preserves its original narrow default collector set;
the workspace now uses the separate `email-posture` template to collect those records.

## Controls and limits

- Every harness adapter call and cache hit passes through the authority gate.
  Authorized domains, engagement dates, permitted techniques, run limits, and
  monthly budget reservations are checked before collection.
- Paid requests reserve budget before calling the provider. Collection failures
  release reservations; cache hits avoid a second provider charge.
- Facts carry source records and table-driven grades. Corroboration requires
  the same entity, attribute, and value from a different origin, with live
  retention and an observed supporting fact.
- An authoritative DNS negative answer (NXDOMAIN / NODATA) for an SPF or DMARC
  record is recorded as an observed `absent` fact and scored as a need signal.
  A lookup that times out stays unknown, and a malformed record is unknown, not
  absent — a failed collection is never turned into a claim of absence.
- People appear as business roles attached to a company. Tier C adapters need
  a client engagement and analyst approval; Tier D is disabled. The IntelX
  aggregate connector is implemented behind Tier C and is not enabled in
  ordinary prospect collection.
- SQLite is the local development backend. Use PostgreSQL for concurrent
  budget enforcement: its row locks are part of the cap guarantee.
- The new harness stores source payloads, facts, and cache entries in its SQL
  database. The legacy evidence-store encryption key does **not** encrypt these
  tables. Secure the database and storage accordingly before deployment.
- The wall-time limit is checked between steps, not a hard interruption of an
  in-flight provider request. Provider costs currently settle at the estimate;
  live provider usage reconciliation is not implemented.

## Database and tests

`NEESHA_DATABASE_URL` selects the database; the default is
`sqlite:///./data/neesha.sqlite3`. Alembic reads the same variable.
For PostgreSQL, configure `.env` from `.env.example`, then:

```bash
make db-up
make migrate
# Set NEESHA_DATABASE_URL for CLI commands to the same PostgreSQL database.
make test-pg
```

```bash
make test
```

The default suite uses fixtures without external collection. PostgreSQL-only
concurrency tests skip unless `NEESHA_TEST_DATABASE_URL` is configured.

## Existing legacy surface

`neesha posture`, `passive`, `resolve`, `run`, and `serve` still use a separate
Evidence/SQLite pipeline. It has more collectors and posture analysis, but it
is not connected to the harness's engagement, typed facts, or budget ledger.
`serve` is a local legacy dashboard, not a UI for harness runs. Use
`neesha harness` for the workflow above.

The legacy evidence store requires `NEESHA_STORE_KEY`; plaintext experiments
require explicit `NEESHA_ALLOW_PLAINTEXT=1`. Legacy preflight signatures require
`NEESHA_PREFLIGHT_KEY`. See `.env.example` for configuration.

## Layout and next work

- `neesha/harness/`: planning, policy gate, executor, repository, run loop, briefing.
- `neesha/adapters/`: free collectors, optional Hunter/Subfinder, and capability registry.
- `neesha/ledger/`: monthly and per-adapter reservations and settlement.
- `neesha/console/`: local UI and same-origin session-protected API.
- `neesha/runtime/`: server-side provider clients and bounded analyst orchestration.
- `neesha/db/`, `migrations/`: typed SQL schema and Alembic migrations.
- `neesha/collectors/`, `posture/`, `evidence/`, `resolve/`: legacy pipeline.
- `CLAUDE.md`: current product direction and development principles.
- `DATA_MODEL.md`: schema rationale. `AUDIT.md`: historical October 31 audit,
  including findings that subsequent changes have addressed.

The workspace routes six domain collectors and two keyless email sources through the harness gate.
Remaining work includes more identifier types, richer professional-role
extraction, entity relationships, change tracking, and isolated external tools. The broad adapter catalog and a
complete company dossier are not implemented yet.

## Source readiness and external tools

Expand **Collection network** in the workspace for configured source readiness.
Each completed investigation shows per-source outcomes and exportable counts;
provider errors are recorded as gaps. No result is not evidence of absence.
Public website reads and DNS queries are distinguished from third-party passive
sources. Website collection pins public IPs, validates TLS, rejects private or
out-of-scope redirects, and limits pages, response sizes, and elapsed time.

Subfinder, theHarvester, and Amass were found on this machine. Only Subfinder
has a typed runner in this build, and it stays disabled by default: its Go
libraries may initialize home-directory configuration outside the repository.
Do not set `NEESHA_ALLOW_TOOL_HOME_WRITES=1` without the operator's explicit
approval for those writes. The runner uses keyless sources only, bounded output,
local config overrides, no shell, and no inherited provider credentials.
Aggregate Subfinder results use a separate namespace so replayed upstream data
does not falsely corroborate native source adapters.

theHarvester and Amass are listed as installed but not connected. SpiderFoot,
BBOT and Recon-ng are catalog entries, not implemented adapters. IntelX
metadata collection is fixture-tested and authority-gated; DeHashed remains
unavailable pending contract verification. Personal username/breach enumeration is not a default company-research
capability. No global installations or machine settings were changed.

## Architecture and implementation phases

NEESHA keeps its Python/SQLAlchemy evidence, gate, ledger, and test foundations.
The architecture is **typed seed intake → resolution candidates → gated
collectors → guarded facts → evidence graph → explained scores → optional
bounded model analysis → cited report**. Retrieved pages and provider responses
are untrusted data, not agent instructions. Runtime models cannot invoke tools,
change scope, read files, or certify their own findings.

1. **Working vertical slice:** domain/website and independent exact-email research,
   six domain collectors and two keyless email sources, graph projection, evidence-backed role hypotheses, two
   explained scores, JSON/Markdown reports, local workspace, and tests.
2. **Resolution and connectors:** investigate candidate organizations for names,
   phones, and IPs; analyst-reviewed identity links; deeper professional-role
   extraction; live authenticated validation of optional providers; isolated tools.
3. **Agent-directed investigation:** controlled model-proposed collection plans
   and new gated pivots. The current single/multi runtime modes analyze collected
   facts; they do not autonomously conduct new collection.
4. **Operational deployment:** monitoring and snapshot
   diffs, authentication, database encryption/key management, and concurrent
   PostgreSQL budget validation.

Seed intake (`POST /api/resolve`) recognizes company/person names, email, phone,
IP, domain, and website inputs. Domains/websites and exact-email seeds can start
automatic collection. Names, phones, and IP ownership remain explicitly
unresolved. Email-root records have their own entity type and public-research
scope; a provider domain never establishes an organization. Public profile/hash
matches and commit metadata are observations, not proof of registration, legal
identity, employment, or exclusive account ownership. Company scoring and
professional buying-role mapping do not apply to independent email subjects.
People use explicit identifier keys or remain separate observations. Name-only
matches never merge new person records. Graph edges retain their supporting
fact IDs, source records, retrieval actor, timestamps, confidence, and source URL.
The graph's organization label is the research seed, not verified legal ownership.

## Scores and service configuration

Commercial fit and evidence of potential security needs are separate weighted
signals. Both expose criterion weights, contributions, coverage, source IDs, and
unknowns. Missing evidence does not become a vulnerability or zero commercial fit.
The security score uses observed SPF/DMARC policies and observed header presence;
it is not a calibrated risk rating or a claim of exploitability.

Commercial fit remains null until a profile is provided. The local session API
accepts `POST /api/profile` with `name`, `services`, and `criteria`; it validates
and saves to `config/service-profile.json` inside NEESHA. Criteria contain `id`,
`attribute`, `weight`, optional `label`/`service`, and exactly one `equals` or
`contains` string. Only observed attributes can be assessed. No services or ideal
customer have been assumed for this firm. Local write APIs require the session
token and same-origin check; keys never belong in a profile.

## Runtime models and verification status

OpenAI, Anthropic, Google, and DeepSeek text clients have fixture-tested request,
authentication, bounded response, and citation-validation contracts. No runtime
credentials were configured during this build, so **authenticated model calls
have not been live-tested**. Environment configuration names are in `.env.example`;
keys and explicit model IDs stay server-side. The application never borrows a
coding assistant's session or credentials. Environment files are examples only;
export variables into the server process using your normal secret-management method.

Single mode runs one bounded synthesis. Multi mode runs infrastructure and
company specialists (or email publication and profile specialists for email research)
followed by a reviewer, with separate fact subsets and
citation boundaries. A complete plan is reserved against the monthly ledger
before the first call. Configure conservative per-call USD charges explicitly;
provider usage reconciliation and a guarantee of actual external billing are
not claimed. Every model conclusion remains an inference for human review.
The Agent Harness controls on the home screen select deterministic collection,
single-model analysis, or multi-model analysis after collection. Selected models
receive allowlisted facts, including exact-subject public personal-email evidence
when investigating an email. They never receive raw pages or provider bodies.
Reports persist in `reports/runtime/<run-id>.json` and load with the investigation.
No provider calls run unless explicitly selected and configured server-side.

## Independent email research and deletion

Any valid supported email, including a public mailbox address, starts an exact-email
investigation without a company association. Two keyless source adapters are enabled:

- [GitHub public commit search](https://docs.github.com/en/rest/search/search#search-commits):
  exact email matches in public commit metadata, bounded to twenty results.
  User-supplied author metadata does not establish current mailbox ownership or registration.
- [Gravatar public profiles](https://docs.gravatar.com/rest/api-data-specifications/):
  email-hash matched public profile metadata and explicitly visible linked profiles.
  No public result can mean absent or private; it is not proof of no account.
- [EmailRep](https://docs.sublime.security/reference/emailrep-introduction): optional
  existing-key metadata. Unauthenticated access is disabled and new keys are not
  issued. Without an existing `EMAILREP_API_KEY`, this source is unavailable.

These are native source adapters, not claims that external CLI tools were installed.
[Holehe](https://github.com/megadose/holehe) and
[Socialscan](https://github.com/iojw/socialscan) were reviewed but use signup or
recovery endpoints; they are not part of passive collection. Registration coverage
is explicitly distinguished from public appearances. The two keyless adapters were
live-checked with a reserved example.com address and correctly returned no public
matches. Positive matching and Gmail routing are covered with fixture-based tests.

Each recent investigation and detail view has **Delete investigation**. It removes
that run's facts, source payloads, query records, matching cache envelopes, and exact
run-ID reports inside NEESHA's reports folder. Shared evidence owned by other runs
remains; spent-budget charges are retained without the run link. Active collection,
model analysis, and unsettled reservations block deletion. SQLite secure-delete and
journal checkpointing are used, but independent backups, downloaded exports, and
forensic SSD erasure are outside this operation. Cleanup failures are shown explicitly.

Verified primary contracts:

- [OpenAI Responses/text](https://developers.openai.com/api/docs/guides/text)
- [Anthropic Messages](https://platform.claude.com/docs/en/api/messages/create)
- [Google generateContent](https://ai.google.dev/api/rest/v1beta/models/generateContent)
- [DeepSeek Chat Completions](https://api-docs.deepseek.com/api/create-chat-completion/)
- [Hunter domain search](https://hunter.io/api-documentation): header credentials,
  bounded result count, configured result-based cost estimate, business-field
  allowlist before caching. Authenticated collection not live-tested here.
- [Intelligence X official SDK](https://github.com/IntelligenceX/SDK/blob/master/Python/intelx/intelxapi.py):
  metadata-only aggregates, no document retrieval, no passwords/hashes/record
  contents persisted. Requires the existing scoped client-engagement gate,
  explicit approval, permission, credentials, and budget. Fixture-tested only.
- [DeHashed official documentation](https://app.dehashed.com/documentation/api):
  current contract could not be verified from accessible official documentation;
  the adapter is explicitly unavailable, with no guessed API calls.

A bounded live check against the reserved example.com domain returned 18
observations from its website, DNS, and existing urlscan records. crt.sh timed
out; OTX and Wayback were unavailable in that check. Those outcomes are gaps,
not fabricated successful integrations. No live paid/model calls were made.
