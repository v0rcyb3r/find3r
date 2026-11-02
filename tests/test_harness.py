"""End-to-end harness tests: adapters, executor, and the run loop.

No network. The real adapter code runs against fixture payloads, so the
parsing, the provenance and the money all behave as they would in a live run.
"""
import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
import sqlalchemy as sa

from neesha.adapters.base import AdapterError, Request
from neesha.adapters.crtsh import CrtShAdapter
from neesha.adapters.hunter import HunterAdapter
from neesha.db import schema
from neesha.harness.executor import Executor
from neesha.harness.gate import EngagementView, PolicyGate, RunCaps
from neesha.harness.repository import Repository
from neesha.harness.run import execute_run
from neesha.ledger.ledger import Ledger

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)
PERIOD = "2026-10"
CAPS = RunCaps(max_steps=25, max_spend_usd=Decimal("1.00"), max_wall_secs=600)

CRTSH_BODY = json.dumps(
    [
        {"name_value": "mail.acme.com\n*.acme.com", "issuer_name": "C=US, O=Let's Encrypt"},
        {"name_value": "vpn.acme.com", "issuer_name": "C=US, O=Let's Encrypt"},
        {"name_value": "jira.acme.com", "issuer_name": "C=BE, O=GlobalSign"},
        # A shared certificate carrying someone else's name: not our target's
        # attack surface and must not be recorded as such.
        {"name_value": "unrelated.othercorp.com", "issuer_name": "C=US, O=Other"},
        {"name_value": "acme.com", "issuer_name": "C=US, O=Let's Encrypt"},
    ]
)

HUNTER_BODY = json.dumps(
    {
        "data": {
            "domain": "acme.com",
            "pattern": "{first}.{last}",
            "emails": [
                {
                    "value": "dana.ops@acme.com",
                    "first_name": "Dana",
                    "last_name": "Ops",
                    "position": "Head of IT Operations",
                    "seniority": "senior",
                },
                {"value": "noname@acme.com"},
                {"value": "", "first_name": "Broken"},
            ],
        }
    }
)


@pytest.fixture
def ledger(engine):
    led = Ledger(engine)
    led.set_cap("100.00", period=PERIOD)
    return led


@pytest.fixture
def gate(engine, ledger):
    return PolicyGate(engine, ledger, clock=lambda: NOW)


@pytest.fixture
def engagement():
    return EngagementView(
        id="eng-1",
        authority_basis="prospect_company",
        authorized_domains=("acme.com",),
        starts_at=NOW - timedelta(days=1),
        expires_at=NOW + timedelta(days=29),
    )


@pytest.fixture
def seeded_engagement(engine, engagement):
    with engine.begin() as conn:
        conn.execute(
            schema.engagement.insert().values(
                id=engagement.id,
                authority_basis=engagement.authority_basis,
                authorized_domains=list(engagement.authorized_domains),
                permitted_techniques=[],
                authorized_by="analyst@vorcyber",
                starts_at=engagement.starts_at,
                expires_at=engagement.expires_at,
                created_at=NOW,
            )
        )
    return engagement


@pytest.fixture
def no_network(monkeypatch):
    """Serve fixture bodies, and record every URL the adapters requested."""
    calls: list[str] = []

    def fake_get(url, headers=None, timeout=20):
        calls.append(url)
        if "crt.sh" in url:
            return CRTSH_BODY
        if "hunter.io" in url:
            return HUNTER_BODY
        raise AssertionError(f"unexpected request to {url}")

    monkeypatch.setattr("neesha.adapters.crtsh.http_get", fake_get)
    monkeypatch.setattr("neesha.adapters.hunter.http_get", fake_get)
    return calls


# ---- adapters -----------------------------------------------------------


def test_crtsh_extracts_subdomains_and_issuers(no_network):
    adapter = CrtShAdapter()
    request = Request("domain", "acme.com")
    raw = adapter.fetch(adapter.search(request)[0])
    drafts = adapter.parse(raw, request)

    subdomains = {d.value for d in drafts if d.attribute == "dns.subdomain"}
    assert subdomains == {"mail.acme.com", "vpn.acme.com", "jira.acme.com"}
    assert {d.attribute for d in drafts} == {"dns.subdomain", "tls.ct.issuer"}


def test_crtsh_drops_names_belonging_to_other_companies(no_network):
    """Shared certificates carry foreign SANs; those are not our surface."""
    adapter = CrtShAdapter()
    request = Request("domain", "acme.com")
    drafts = adapter.parse(adapter.fetch(adapter.search(request)[0]), request)
    assert not any("othercorp" in d.value for d in drafts)


def test_crtsh_does_not_report_the_apex_as_its_own_subdomain(no_network):
    adapter = CrtShAdapter()
    request = Request("domain", "acme.com")
    drafts = adapter.parse(adapter.fetch(adapter.search(request)[0]), request)
    assert "acme.com" not in {d.value for d in drafts if d.attribute == "dns.subdomain"}


def test_crtsh_facts_are_about_the_subject_domain(no_network):
    """Attaching to the subject is what makes facts corroboratable: another
    source asserting the same subdomain agrees on the same attribute/value."""
    adapter = CrtShAdapter()
    request = Request("domain", "acme.com")
    drafts = adapter.parse(adapter.fetch(adapter.search(request)[0]), request)
    assert {d.entity_name for d in drafts} == {"acme.com"}


def test_crtsh_raises_on_unparseable_body(monkeypatch):
    monkeypatch.setattr(
        "neesha.adapters.crtsh.http_get", lambda *a, **k: "<html>down</html>"
    )
    adapter = CrtShAdapter()
    request = Request("domain", "acme.com")
    raw = adapter.fetch(adapter.search(request)[0])
    with pytest.raises(AdapterError, match="unparseable"):
        adapter.parse(raw, request)


def test_hunter_never_puts_the_key_in_provenance(no_network, monkeypatch):
    """AUDIT.md P1, at the point of origin."""
    monkeypatch.setenv("HUNTER_API_KEY", "sk-SUPERSECRET-123")
    adapter = HunterAdapter()
    request = Request("domain", "acme.com")
    reference = adapter.search(request)[0]
    raw = adapter.fetch(reference)

    assert "sk-SUPERSECRET-123" not in reference.url, "credentials belong in headers"
    assert "SUPERSECRET" not in raw.request_url, "what we store must not have it"
    assert "api_key" not in raw.request_url


def test_hunter_scrubs_the_key_from_error_text(monkeypatch):
    import urllib.error

    monkeypatch.setenv("HUNTER_API_KEY", "sk-SUPERSECRET-123")

    def boom(url, headers=None, timeout=20):
        raise urllib.error.HTTPError(url, 401, "Unauthorized", {}, None)

    monkeypatch.setattr("neesha.adapters.hunter.http_get", boom)
    adapter = HunterAdapter()
    with pytest.raises(AdapterError) as exc:
        adapter.fetch(adapter.search(Request("domain", "acme.com"))[0])
    assert "SUPERSECRET" not in str(exc.value)


def test_hunter_parses_people_and_pattern(no_network, monkeypatch):
    monkeypatch.setenv("HUNTER_API_KEY", "k")
    adapter = HunterAdapter()
    request = Request("domain", "acme.com")
    drafts = adapter.parse(adapter.fetch(adapter.search(request)[0]), request)

    by_attr = {}
    for d in drafts:
        by_attr.setdefault(d.attribute, []).append(d)
    assert by_attr["email.pattern"][0].value == "{first}.{last}"
    assert "dana.ops@acme.com" in {d.value for d in by_attr["person.business_email"]}
    assert by_attr["person.role"][0].value == "Head of IT Operations"
    # The malformed record is dropped rather than stored as an empty person.
    assert len(by_attr["person.business_email"]) == 2


def test_hunter_requires_a_key(monkeypatch):
    monkeypatch.delenv("HUNTER_API_KEY", raising=False)
    with pytest.raises(AdapterError, match="HUNTER_API_KEY"):
        HunterAdapter().search(Request("domain", "acme.com"))


def test_hunter_is_metered_and_crtsh_is_not():
    request = Request("domain", "acme.com")
    assert not CrtShAdapter().estimate_cost(request).is_metered
    assert HunterAdapter().estimate_cost(request).is_metered


# ---- executor -----------------------------------------------------------


def executor_for(engine, gate, ledger, engagement, company="acme.com"):
    company_id = Repository.ensure_company(engine, company)
    run_id = "run-1"
    with engine.begin() as conn:
        conn.execute(
            schema.engagement.insert().values(
                id=engagement.id,
                authority_basis=engagement.authority_basis,
                authorized_domains=list(engagement.authorized_domains),
                permitted_techniques=[],
                authorized_by="a",
                starts_at=engagement.starts_at,
                expires_at=engagement.expires_at,
                created_at=NOW,
            )
        )
        conn.execute(
            schema.run.insert().values(
                id=run_id,
                engagement_id=engagement.id,
                company_id=company_id,
                analyst="analyst@vorcyber",
                status="running",
                max_steps=CAPS.max_steps,
                max_spend_usd=CAPS.max_spend_usd,
                max_wall_secs=CAPS.max_wall_secs,
                started_at=NOW,
            )
        )
    repo = Repository(engine, company_id=company_id, run_id=run_id)
    return (
        Executor(
            gate=gate,
            ledger=ledger,
            repository=repo,
            engagement=engagement,
            analyst="analyst@vorcyber",
            caps=CAPS,
        ),
        repo,
    )


def test_executor_collects_and_writes_facts(engine, gate, ledger, engagement, no_network):
    ex, _ = executor_for(engine, gate, ledger, engagement)
    result = ex.execute(CrtShAdapter(), Request("domain", "acme.com"))
    assert result.outcome == "collected"
    assert result.facts_written > 0
    assert result.source_record_id


def test_a_cache_hit_costs_nothing_and_makes_no_second_call(
    engine, gate, ledger, engagement, no_network, monkeypatch
):
    """Never pay twice for the same lookup in a period."""
    monkeypatch.setenv("HUNTER_API_KEY", "k")
    ex, _ = executor_for(engine, gate, ledger, engagement)

    first = ex.execute(HunterAdapter(), Request("domain", "acme.com"))
    assert first.outcome == "collected"
    assert first.cost_usd > 0
    calls_after_first = len(no_network)

    second = ex.execute(HunterAdapter(), Request("domain", "acme.com"))
    assert second.outcome == "cached"
    assert second.cost_usd == Decimal("0")
    assert len(no_network) == calls_after_first, "cache must not re-call"
    # Only the first call is on the books.
    assert ledger.summary(PERIOD).committed_usd == first.cost_usd


def test_a_cached_result_is_still_gated(engine, gate, ledger, engagement, no_network):
    """Holding a copy does not confer authority over the target."""
    ex, repo = executor_for(engine, gate, ledger, engagement)
    ex.execute(CrtShAdapter(), Request("domain", "acme.com"))
    denied = ex.execute(CrtShAdapter(), Request("domain", "othercorp.com"))
    assert denied.outcome == "denied"


def test_a_failed_call_releases_its_reservation(
    engine, gate, ledger, engagement, monkeypatch
):
    """A flaky source must not silently consume the month."""
    monkeypatch.setenv("HUNTER_API_KEY", "k")
    monkeypatch.setattr(
        "neesha.adapters.hunter.http_get",
        lambda *a, **k: (_ for _ in ()).throw(OSError("connection reset")),
    )
    ex, _ = executor_for(engine, gate, ledger, engagement)
    result = ex.execute(HunterAdapter(), Request("domain", "acme.com"))
    assert result.outcome == "failed"
    assert ledger.summary(PERIOD).committed_usd == Decimal("0.0000")


def test_a_denied_step_writes_no_facts(engine, gate, ledger, engagement, no_network):
    ex, _ = executor_for(engine, gate, ledger, engagement)
    ex.execute(CrtShAdapter(), Request("domain", "othercorp.com"))
    with engine.connect() as conn:
        assert conn.execute(sa.select(sa.func.count()).select_from(schema.fact)).scalar() == 0


def test_people_are_attached_to_the_company(
    engine, gate, ledger, engagement, no_network, monkeypatch
):
    """Company-first: a person is a role at an organization, never a
    free-standing subject."""
    monkeypatch.setenv("HUNTER_API_KEY", "k")
    ex, repo = executor_for(engine, gate, ledger, engagement)
    ex.execute(HunterAdapter(), Request("domain", "acme.com"))
    with engine.connect() as conn:
        rows = conn.execute(
            sa.select(schema.entity.c.canonical_name, schema.entity.c.company_id).where(
                schema.entity.c.kind == "person"
            )
        ).all()
    assert rows
    assert all(company_id == repo.company_id for _, company_id in rows)


def test_commercial_api_facts_are_capped_at_medium(
    engine, gate, ledger, engagement, no_network, monkeypatch
):
    """A single uncorroborated commercial source may not claim high."""
    monkeypatch.setenv("HUNTER_API_KEY", "k")
    ex, _ = executor_for(engine, gate, ledger, engagement)
    ex.execute(HunterAdapter(), Request("domain", "acme.com"))
    with engine.connect() as conn:
        confidences = set(
            conn.execute(sa.select(schema.fact.c.confidence)).scalars()
        )
    assert confidences == {"medium"}


def test_independent_corroboration_improves_the_claim_grade(
    engine, gate, ledger, engagement, no_network
):
    """AUDIT.md B17: the thing prose-keyed claims made impossible."""
    ex, repo = executor_for(engine, gate, ledger, engagement)
    ex.execute(CrtShAdapter(), Request("domain", "acme.com"))

    # A second, independent source asserting one of the same subdomains.
    from neesha.adapters.base import FactDraft, RawResult

    other = repo.write_source_record(
        adapter="otx",
        tier="A",
        collection_mode="third_party_passive",
        raw=RawResult(
            payload=b"{}",
            request_url="https://otx.example/acme.com",
            origin_url="https://otx.example/",
        ),
        retention=timedelta(days=30),
    )
    written = repo.write_facts(
        [FactDraft(attribute="dns.subdomain", value="mail.acme.com")],
        source_record_id=other,
        source_type="osint",
        subject_name="acme.com",
        retention=timedelta(days=30),
    )
    assert written[0].admiralty == "C2", "corroborated osint improves 3 -> 2"
    assert written[0].confidence == "high"


# ---- the run loop -------------------------------------------------------


def test_run_end_to_end_answers_and_reports_gaps(
    engine, ledger, gate, seeded_engagement, no_network, monkeypatch
):
    monkeypatch.setenv("HUNTER_API_KEY", "k")
    report = execute_run(
        engine=engine,
        ledger=ledger,
        gate=gate,
        company="acme.com",
        engagement=seeded_engagement,
        analyst="analyst@vorcyber",
        pir_templates=("attack-surface", "who-to-contact", "email-security-fit"),
        caps=CAPS,
    )

    assert report.status == "complete"
    assert report.stop_reason == "complete"
    assert report.facts_written > 0
    assert {s.adapter for s in report.steps} == {"crt.sh", "hunter"}

    answered = {p.question for p in report.answered}
    assert "What hostnames does this company expose?" in answered

    # The email-auth requirement cannot be met yet: no adapter in the
    # registry produces it. The run says so instead of under-delivering.
    gaps = {p.question: p.gap_reason for p in report.gaps}
    assert any("email authentication" in q for q in gaps)
    assert any("no adapter in the registry produces" in (r or "") for r in gaps.values())


def test_run_persists_pirs_with_their_status(
    engine, ledger, gate, seeded_engagement, no_network
):
    report = execute_run(
        engine=engine,
        ledger=ledger,
        gate=gate,
        company="acme.com",
        engagement=seeded_engagement,
        analyst="a",
        pir_templates=("attack-surface",),
        caps=CAPS,
    )
    with engine.connect() as conn:
        rows = conn.execute(
            sa.select(schema.pir.c.status, schema.pir.c.run_id)
        ).all()
    assert rows
    assert all(run_id == report.run_id for _, run_id in rows)
    assert "answered" in {status for status, _ in rows}


def test_run_stops_when_the_run_spend_cap_is_reached(
    engine, ledger, gate, seeded_engagement, no_network, monkeypatch
):
    monkeypatch.setenv("HUNTER_API_KEY", "k")
    tiny = RunCaps(
        max_steps=25, max_spend_usd=Decimal("0.001"), max_wall_secs=600
    )
    report = execute_run(
        engine=engine,
        ledger=ledger,
        gate=gate,
        company="acme.com",
        engagement=seeded_engagement,
        analyst="a",
        pir_templates=("who-to-contact",),
        caps=tiny,
    )
    # Hunter's estimate exceeds the run cap, so it is refused by the gate and
    # recorded as skipped with a reason rather than silently omitted.
    assert any("run spend cap" in s["reason"] for s in report.skipped)
    assert report.spend_usd == Decimal("0")


def test_run_records_free_sources_even_when_the_month_is_exhausted(
    engine, ledger, gate, seeded_engagement, no_network
):
    ledger.reserve("other", "100.00", period=PERIOD)
    report = execute_run(
        engine=engine,
        ledger=ledger,
        gate=gate,
        company="acme.com",
        engagement=seeded_engagement,
        analyst="a",
        pir_templates=("attack-surface",),
        caps=CAPS,
    )
    assert report.facts_written > 0


def test_run_logs_every_step_to_the_query_log(
    engine, ledger, gate, seeded_engagement, no_network, monkeypatch
):
    monkeypatch.setenv("HUNTER_API_KEY", "k")
    execute_run(
        engine=engine,
        ledger=ledger,
        gate=gate,
        company="acme.com",
        engagement=seeded_engagement,
        analyst="analyst@vorcyber",
        pir_templates=("attack-surface", "who-to-contact"),
        caps=CAPS,
    )
    with engine.connect() as conn:
        rows = conn.execute(
            sa.select(
                schema.query_log.c.adapter,
                schema.query_log.c.decision,
                schema.query_log.c.analyst,
            )
        ).all()
    assert {r.adapter for r in rows} == {"crt.sh", "hunter"}
    assert all(r.analyst == "analyst@vorcyber" for r in rows)


# ---- retention ----------------------------------------------------------


def test_purge_removes_expired_facts_and_sources(
    engine, gate, ledger, engagement, no_network
):
    """Retention is a compliance control, not housekeeping: under Hunter's
    terms we are an independent controller for what we retrieve."""
    ex, repo = executor_for(engine, gate, ledger, engagement)
    ex.execute(CrtShAdapter(), Request("domain", "acme.com"))

    with engine.connect() as conn:
        before = conn.execute(
            sa.select(sa.func.count()).select_from(schema.fact)
        ).scalar()
    assert before > 0

    counts = repo.purge_expired(now=NOW + timedelta(days=365))
    assert counts["fact"] == before
    with engine.connect() as conn:
        assert conn.execute(
            sa.select(sa.func.count()).select_from(schema.fact)
        ).scalar() == 0


def test_purge_leaves_live_data_alone(engine, gate, ledger, engagement, no_network):
    ex, repo = executor_for(engine, gate, ledger, engagement)
    ex.execute(CrtShAdapter(), Request("domain", "acme.com"))
    counts = repo.purge_expired(now=NOW)
    assert counts["fact"] == 0


def test_corroboration_requires_same_entity_and_live_observation(
    engine, gate, ledger, engagement
):
    from neesha.adapters.base import FactDraft, RawResult

    _, repo = executor_for(engine, gate, ledger, engagement)

    def record(origin, name, inference=False):
        source = repo.write_source_record(
            adapter='fixture', tier='A', collection_mode='third_party_passive',
            raw=RawResult(payload=b'{}', request_url=origin),
            retention=timedelta(days=30),
        )
        return repo.write_facts(
            [FactDraft(attribute='person.role', value='CTO', entity_kind='person',
                       entity_name=name, is_inference=inference, identity_key='fixture-person:'+name)],
            source_record_id=source, source_type='osint', subject_name='acme.com',
            retention=timedelta(days=30),
        )[0]

    first = record('https://first.example/', 'Alice')
    assert first.confidence == 'medium'
    unrelated = record('https://second.example/', 'Bob')
    assert unrelated.confidence == 'medium'
    with engine.begin() as conn:
        conn.execute(schema.fact.update().values(
            retention_expires_at=NOW - timedelta(days=1)))
    expired_support = record('https://third.example/', 'Alice')
    assert expired_support.confidence == 'medium'
    record('https://inferred.example/', 'Carol', inference=True)
    assert record('https://observed.example/', 'Carol').confidence == 'medium'
    assert record('https://fourth.example/', 'Alice').confidence == 'high'


def test_pir_evidence_links_only_current_run_and_exact_namespace(
    engine, gate, ledger, engagement
):
    from neesha.adapters.base import FactDraft, RawResult
    from neesha.harness.run import _fact_ids_for

    _, repo = executor_for(engine, gate, ledger, engagement)
    source = repo.write_source_record(
        adapter='fixture', tier='A', collection_mode='third_party_passive',
        raw=RawResult(payload=b'{}', request_url='https://example.test/'),
        retention=timedelta(days=30),
    )
    facts = repo.write_facts(
        [FactDraft(attribute='person.role', value='CTO'),
         FactDraft(attribute='person.roles_other', value='unrelated')],
        source_record_id=source, source_type='osint', subject_name='acme.com',
        retention=timedelta(days=30),
    )
    assert _fact_ids_for(engine, repo.company_id, repo.run_id,
                         frozenset({'person.role'})) == [facts[0].id]
    assert _fact_ids_for(engine, repo.company_id, 'another-run',
                         frozenset({'person.role'})) == []


def test_invalid_pir_does_not_leave_a_running_record(
    engine, ledger, gate, seeded_engagement
):
    with pytest.raises(KeyError, match='unknown PIR'):
        execute_run(engine=engine, ledger=ledger, gate=gate, company='acme.com',
                    engagement=seeded_engagement, analyst='a',
                    pir_templates=('typo',))
    with engine.connect() as conn:
        assert conn.execute(sa.select(sa.func.count()).select_from(schema.run)).scalar() == 0


def test_repeated_fact_does_not_discard_other_facts(
    engine, gate, ledger, engagement
):
    from neesha.adapters.base import FactDraft, RawResult

    _, repo = executor_for(engine, gate, ledger, engagement)
    source = repo.write_source_record(
        adapter='fixture', tier='A', collection_mode='third_party_passive',
        raw=RawResult(payload=b'{}', request_url='https://example.test/'),
        retention=timedelta(days=30),
    )
    first = FactDraft(attribute='dns.subdomain', value='mail.acme.com')
    written = repo.write_facts(
        [first, first, FactDraft(attribute='dns.subdomain', value='vpn.acme.com')],
        source_record_id=source, source_type='osint', subject_name='acme.com',
        retention=timedelta(days=30),
    )
    assert {f.value for f in written} == {'mail.acme.com', 'vpn.acme.com'}


def test_brief_contains_guarded_claims_and_original_provenance(
    engine, ledger, gate, seeded_engagement, no_network, tmp_path
):
    from neesha.harness.brief import build_brief, write_brief

    report = execute_run(
        engine=engine, ledger=ledger, gate=gate, company='acme.com',
        engagement=seeded_engagement, analyst='a',
        pir_templates=('attack-surface', 'email-security-fit'), caps=CAPS,
    )
    brief = build_brief(engine, report.run_id)
    assert brief['facts']
    assert not brief['inferences']
    for fact in brief['facts']:
        assert fact['admiralty'] == 'C3'
        assert fact['confidence'] == 'medium'
        assert fact['source_record_id']
        assert fact['collected_at']
        assert fact['collection_mode'] == 'third_party_passive'
        assert 'single-source' in fact['flags']
    md_path, json_path = write_brief(engine, report.run_id, tmp_path)
    assert 'What we could not answer' in md_path.read_text()
    assert json.loads(json_path.read_text()) == brief
    assert 'raw_payload' not in json_path.read_text()


def test_brief_withholds_restricted_and_expired_facts_and_reopens_gaps(
    engine, ledger, gate, seeded_engagement, no_network
):
    from neesha.harness.brief import build_brief

    report = execute_run(
        engine=engine, ledger=ledger, gate=gate, company='acme.com',
        engagement=seeded_engagement, analyst='a', caps=CAPS,
    )
    with engine.begin() as conn:
        conn.execute(schema.fact.update().where(
            schema.fact.c.attribute == 'dns.subdomain'
        ).values(sensitivity='restricted'))
        conn.execute(schema.fact.update().where(
            schema.fact.c.attribute == 'tls.ct.issuer'
        ).values(retention_expires_at=NOW - timedelta(days=1)))
    brief = build_brief(engine, report.run_id)
    assert brief['facts'] == []
    assert all(pir['status'] == 'unanswerable' for pir in brief['requirements'])
    assert all(not pir['fact_ids'] for pir in brief['requirements'])


def test_harness_cli_writes_both_briefing_formats(
    engine, seeded_engagement, no_network, monkeypatch, tmp_path
):
    from typer.testing import CliRunner
    from neesha.cli.harness_cli import harness_app

    monkeypatch.setenv('NEESHA_DATABASE_URL', str(engine.url))
    output = tmp_path / 'briefs'
    result = CliRunner().invoke(harness_app, [
        'run', 'acme.com', '--engagement', seeded_engagement.id,
        '--out', str(output),
    ])
    assert result.exit_code == 0, result.output
    (json_path,) = output.glob('*.json')
    (md_path,) = output.glob('*.md')
    assert json.loads(json_path.read_text())['facts']
    assert 'What we know' in md_path.read_text()


def test_requirement_cannot_be_answered_by_a_less_specific_attribute(engine):
    from neesha.harness.executor import StepResult
    from neesha.harness.plan import PIR, Plan
    from neesha.harness.run import _resolve_pirs

    requirement = PIR('Is DMARC enforced?', frozenset({'email.dmarc.policy'}))
    plan = Plan(pirs=[requirement])
    _resolve_pirs(engine, plan, 'company', 'run', [
        StepResult('fixture', 'collected', attributes=['email.dmarc'])
    ])
    assert requirement.status == 'unanswerable'


# ---- step 2 hardening: crashes, gap attribution, tier-C approval --------


def test_an_unexpected_adapter_crash_is_a_gap_and_releases_budget(
    engine, gate, ledger, engagement, no_network, monkeypatch
):
    """A non-AdapterError from a paid source must be a recorded gap, not a
    run-ender, and must not leak its reservation into the month's spend."""
    monkeypatch.setenv("HUNTER_API_KEY", "k")

    class Boom(HunterAdapter):
        def fetch(self, reference):
            raise RuntimeError("socket blew up mid-fetch")

    ex, _ = executor_for(engine, gate, ledger, engagement)
    result = ex.execute(Boom(), Request("domain", "acme.com"))

    assert result.outcome == "failed"
    assert "unexpected adapter error" in result.reason
    # The crash message is never echoed into the gap reason.
    assert "socket blew up" not in result.reason
    assert result.cost_usd == Decimal("0")
    assert result.facts_written == 0
    assert ledger.summary().committed_usd == Decimal("0")


def test_a_crash_in_the_run_loop_marks_the_run_failed_not_running(
    engine, ledger, gate, seeded_engagement, no_network
):
    """An unexpected error mid-loop must not wedge the run at 'running'
    forever — it is recorded as failed so an operator and deletion can see it."""

    def boom(update):
        raise RuntimeError("telemetry down")

    with pytest.raises(RuntimeError):
        execute_run(
            engine=engine, ledger=ledger, gate=gate, company="acme.com",
            engagement=seeded_engagement, analyst="a",
            pir_templates=("attack-surface",), caps=CAPS, progress=boom,
        )
    with engine.connect() as conn:
        row = conn.execute(
            sa.select(schema.run.c.status, schema.run.c.stop_reason)
        ).one()
    assert row.status == "failed"
    assert row.stop_reason == "internal_error"


def test_a_failing_source_is_blamed_only_for_requirements_it_served(
    engine, ledger, gate, seeded_engagement
):
    """One source timing out must not be reported as the reason an unrelated
    requirement went unanswered."""
    from neesha.adapters.base import RawResult
    from neesha.adapters.dns_posture import DnsPostureAdapter

    class FailCrt(CrtShAdapter):
        def search(self, request):
            raise AdapterError("crt.sh timed out")

    class EmptyDns(DnsPostureAdapter):
        def fetch(self, reference):
            return RawResult(payload=b"[]", request_url=reference.url,
                             origin_url=reference.url)

    report = execute_run(
        engine=engine, ledger=ledger, gate=gate, company="acme.com",
        engagement=seeded_engagement, analyst="a",
        pir_templates=("email-posture", "attack-surface"),
        sources={"crt.sh", "dns-posture"}, tiers={"A"},
        adapters={"crt.sh": FailCrt(), "dns-posture": EmptyDns()}, caps=CAPS,
    )
    gaps = {p.question: (p.gap_reason or "") for p in report.pirs}
    dns_question = "What SPF and DMARC policies are published?"
    surface_question = "What hostnames does this company expose?"
    assert "crt.sh" not in gaps[dns_question]
    assert "crt.sh" in gaps[surface_question]


def test_tier_c_source_pauses_until_an_analyst_approves(engine, ledger, gate):
    """Tier C is never automatic: the gate pauses it, and only an explicit
    analyst approval lets the same step through."""
    from neesha.adapters.base import BaseAdapter, Cost, FactDraft, RawResult, Reference

    class FakeTierC(BaseAdapter):
        name = "fake-tierc"
        tier = "C"
        source_type = "commercial_api"
        produces = frozenset({"breach.aggregate"})
        accepts = frozenset({"domain"})

        def estimate_cost(self, request):
            return Cost()  # free, so this isolates the approval gate from budget

        def search(self, request):
            return [Reference(url="test://x", origin_url="test://x")]

        def fetch(self, reference):
            return RawResult(payload=b"{}", request_url="test://x",
                             origin_url="test://x")

        def parse(self, raw, request):
            return [FactDraft(attribute="breach.aggregate", value="0",
                              entity_kind="company", entity_name=request.value)]

    client = EngagementView(
        id="eng-c", authority_basis="client_engagement",
        authorized_domains=("acme.com",),
        starts_at=NOW - timedelta(days=1), expires_at=NOW + timedelta(days=29),
    )
    company_id = Repository.ensure_company(engine, "acme.com")
    with engine.begin() as conn:
        conn.execute(schema.engagement.insert().values(
            id=client.id, authority_basis="client_engagement", client_name="Acme Inc",
            authorized_domains=["acme.com"], permitted_techniques=[], authorized_by="a",
            starts_at=client.starts_at, expires_at=client.expires_at, created_at=NOW,
        ))
        conn.execute(schema.run.insert().values(
            id="run-c", engagement_id=client.id, company_id=company_id, analyst="a",
            status="running", max_steps=CAPS.max_steps, max_spend_usd=CAPS.max_spend_usd,
            max_wall_secs=CAPS.max_wall_secs, started_at=NOW,
        ))
    repo = Repository(engine, company_id=company_id, run_id="run-c")
    ex = Executor(gate=gate, ledger=ledger, repository=repo, engagement=client,
                  analyst="a", caps=CAPS)

    paused = ex.execute(FakeTierC(), Request("domain", "acme.com"))
    assert paused.outcome == "paused"
    assert paused.facts_written == 0

    approved = ex.execute(FakeTierC(), Request("domain", "acme.com"), approved=True)
    assert approved.outcome == "collected"
    assert approved.facts_written == 1


def test_repository_purge_classmethod_removes_expired_without_run_context(
    engine, gate, ledger, engagement, no_network
):
    """The cron/CLI entry point purges engine-wide with no company or run id."""
    ex, _ = executor_for(engine, gate, ledger, engagement)
    ex.execute(CrtShAdapter(), Request("domain", "acme.com"))
    with engine.connect() as conn:
        assert conn.execute(sa.select(sa.func.count()).select_from(schema.fact)).scalar() > 0

    counts = Repository.purge(engine, now=NOW + timedelta(days=3650))
    assert counts["fact"] > 0
    with engine.connect() as conn:
        assert conn.execute(sa.select(sa.func.count()).select_from(schema.fact)).scalar() == 0
        assert conn.execute(sa.select(sa.func.count()).select_from(schema.source_record)).scalar() == 0


def test_harness_cli_self_authorizes_a_target_with_no_engagement(
    engine, no_network, monkeypatch, tmp_path
):
    """With no engagement in force, the CLI records a scoped operator
    engagement for the target and proceeds, rather than refusing. The
    self-authorization is prospect authority and is itself on the record."""
    from typer.testing import CliRunner
    from neesha.cli.harness_cli import harness_app

    monkeypatch.setenv('NEESHA_DATABASE_URL', str(engine.url))
    output = tmp_path / 'briefs'
    result = CliRunner().invoke(harness_app, ['run', 'acme.com', '--out', str(output)])
    assert result.exit_code == 0, result.output
    assert 'self-authorized' in result.output

    with engine.connect() as conn:
        rows = conn.execute(sa.select(
            schema.engagement.c.authority_basis, schema.engagement.c.authorized_by,
            schema.engagement.c.authorized_domains,
        )).all()
    assert len(rows) == 1
    assert rows[0].authority_basis == 'prospect_company'
    assert rows[0].authorized_by.startswith('operator-self-authorized:')
    assert rows[0].authorized_domains == ['acme.com']
    (json_path,) = output.glob('*.json')
    assert json.loads(json_path.read_text())['facts']


def test_harness_cli_self_authorization_is_not_client_authority(
    engine, no_network, monkeypatch, tmp_path
):
    """Self-authorization must never grant the client-engagement authority the
    tier-C person-enumeration sources require, so those stay gated."""
    from typer.testing import CliRunner
    from neesha.cli.harness_cli import harness_app

    monkeypatch.setenv('NEESHA_DATABASE_URL', str(engine.url))
    CliRunner().invoke(harness_app, ['run', 'acme.com', '--out', str(tmp_path / 'b')])
    with engine.connect() as conn:
        bases = set(conn.execute(sa.select(schema.engagement.c.authority_basis)).scalars())
    assert 'client_engagement' not in bases


def test_harness_cli_refuses_self_authorization_when_disabled(
    engine, no_network, monkeypatch, tmp_path
):
    from typer.testing import CliRunner
    from neesha.cli.harness_cli import harness_app

    monkeypatch.setenv('NEESHA_DATABASE_URL', str(engine.url))
    result = CliRunner().invoke(
        harness_app, ['run', 'acme.com', '--no-self-authorize', '--out', str(tmp_path / 'b')]
    )
    assert result.exit_code == 1
    assert 'no engagement covers this target' in result.output
    with engine.connect() as conn:
        assert conn.execute(sa.select(sa.func.count()).select_from(schema.engagement)).scalar() == 0
