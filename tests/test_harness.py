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

    assert "sk-SUPERSECRET-123" in reference.url, "the live call needs the key"
    assert "SUPERSECRET" not in raw.request_url, "what we store must not have it"
    assert "api_key=REDACTED" in raw.request_url


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
