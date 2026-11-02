"""Independent public email research never becomes provider-company research."""
import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
import sqlalchemy as sa

from neesha.adapters import registry
from neesha.adapters.base import BaseAdapter, FactDraft, RawResult, Reference
from neesha.db import schema
from neesha.harness.brief import build_brief
from neesha.harness.gate import AdapterSpec, EngagementView, PolicyGate, RunCaps
from neesha.harness.repository import Repository
from neesha.harness.run import execute_run
from neesha.ledger.ledger import Ledger


class PublicEmailFixture(BaseAdapter):
    name='public-email-fixture'
    source_type='osint'
    accepts=frozenset({'email'})
    produces=frozenset({'public.email.github'})
    def search(self,request):
        assert request.entity_kind=='email'
        assert request.value=='Dana@gmail.com'
        return [Reference('https://api.github.com/search/commits?q=author-email:Dana@gmail.com')]
    def fetch(self,reference):
        return RawResult(b'{}',reference.url,origin_url='https://github.com/')
    def parse(self,raw,request):
        return [FactDraft(attribute='public.email.github.commit_url',
            value='https://github.com/example/project/commit/abc',entity_kind='email',
            entity_name=request.value,sensitivity='personal'),
            FactDraft(attribute='public.email.github.author_name',value='A Public Label',
                entity_kind='email',entity_name=request.value,sensitivity='personal')]


@pytest.fixture
def email_engagement(engine):
    now=datetime.now(timezone.utc)
    with engine.begin() as conn:
        conn.execute(schema.engagement.insert().values(
            id='email-context',authority_basis='public_research',authorized_domains=[],
            authorized_emails=['Dana@gmail.com'],authorized_by='test-research',
            permitted_techniques=[],starts_at=now-timedelta(days=1),
            expires_at=now+timedelta(days=1),created_at=now))
    return EngagementView(id='email-context',authority_basis='public_research',
        authorized_emails=('Dana@gmail.com',),starts_at=now-timedelta(days=1),
        expires_at=now+timedelta(days=1))


def test_email_scope_is_exact_and_never_authorizes_provider(email_engagement,engine):
    assert email_engagement.covers('Dana@GMAIL.COM')
    for target in ('Other@gmail.com','dana@gmail.com','gmail.com','sub.gmail.com'):
        assert not email_engagement.covers(target)
    ledger=Ledger(engine)
    gate=PolicyGate(engine,ledger)
    caps=RunCaps(10,Decimal('1'),60)
    passive=gate.authorize(adapter=AdapterSpec('public-email-fixture','A'),
        target='Dana@gmail.com',engagement=email_engagement,analyst='test',caps=caps)
    assert passive.allowed
    active=gate.authorize(adapter=AdapterSpec('direct-fixture','A',collection_mode='direct_contact'),
        target='Dana@gmail.com',engagement=email_engagement,analyst='test',caps=caps)
    assert active.outcome=='denied'
    assert 'passive' in active.reason


def test_company_domain_scope_does_not_authorize_emails():
    engagement=EngagementView('company','prospect_company',authorized_domains=('gmail.com',))
    assert not engagement.covers('Dana@gmail.com')


def test_public_email_run_exports_personal_public_observations_without_company(
    engine,email_engagement,monkeypatch
):
    monkeypatch.setitem(registry.ADAPTERS,PublicEmailFixture.name,PublicEmailFixture)
    ledger=Ledger(engine)
    report=execute_run(engine=engine,ledger=ledger,gate=PolicyGate(engine,ledger),
        company='Dana@gmail.com',subject_kind='email',engagement=email_engagement,
        analyst='test',sources={'public-email-fixture'})
    assert report.subject_kind=='email'
    assert report.facts_written==2
    brief=build_brief(engine,report.run_id)
    assert brief['subject_kind']=='email'
    assert brief['seed']['normalized']=='Dana@gmail.com'
    assert brief['seed']['domain'] is None
    assert len(brief['facts'])==2
    assert all(f['subject']=='Dana@gmail.com' for f in brief['facts'])
    assert all(f['admiralty']=='C3' for f in brief['facts'])
    assert all(f['source_record_id'] for f in brief['facts'])
    assert brief['scores']['commercial_fit']['score'] is None
    assert brief['scores']['security_needs']['score'] is None
    assert brief['power_map']==[]
    assert not any(n['kind'] in ('organization','person','domain') for n in brief['graph']['nodes'])
    assert any(n['kind']=='email' for n in brief['graph']['nodes'])
    with engine.connect() as conn:
        assert conn.execute(sa.select(sa.func.count()).select_from(schema.entity).where(
            schema.entity.c.kind=='company')).scalar()==0
        root=conn.execute(sa.select(schema.entity).where(schema.entity.c.id==report.company_id)).mappings().one()
        assert root['kind']=='email'
        assert root['company_id'] is None


def test_email_root_cannot_create_named_people_companies_or_other_emails(engine):
    root=Repository.ensure_email(engine,'Dana@gmail.com')
    repo=Repository(engine,root,'email-run',subject_kind='email')
    with engine.begin() as conn:
        assert repo.ensure_entity(conn,'email','Dana@gmail.com')==root
        for kind,value in [('company','gmail.com'),('person','Dana'),('email','other@gmail.com')]:
            with pytest.raises(ValueError):
                repo.ensure_entity(conn,kind,value)


def test_email_root_exact_localpart_kept_separate(engine):
    assert Repository.ensure_email(engine,'Dana@gmail.com')!=Repository.ensure_email(engine,'dana@gmail.com')
    assert Repository.ensure_email(engine,'Dana@gmail.com')==Repository.ensure_email(engine,'Dana@GMAIL.COM')


def test_email_brief_never_exports_unrelated_personal_or_restricted_fact(engine,email_engagement,monkeypatch):
    monkeypatch.setitem(registry.ADAPTERS,PublicEmailFixture.name,PublicEmailFixture)
    ledger=Ledger(engine)
    report=execute_run(engine=engine,ledger=ledger,gate=PolicyGate(engine,ledger),
        company='Dana@gmail.com',subject_kind='email',engagement=email_engagement,
        analyst='test',sources={'public-email-fixture'})
    with engine.begin() as conn:
        rows=conn.execute(sa.select(schema.fact).where(schema.fact.c.run_id==report.run_id)).mappings().all()
        conn.execute(schema.fact.update().where(schema.fact.c.id==rows[0]['id']).values(
            attribute='private.email.notes'))
        conn.execute(schema.fact.update().where(schema.fact.c.id==rows[1]['id']).values(
            sensitivity='restricted'))
    assert build_brief(engine,report.run_id)['facts']==[]
