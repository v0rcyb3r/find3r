"""Run deletion removes content, retains spend, and respects shared evidence."""
import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
import sqlalchemy as sa

from neesha.console.server import Workspace
from neesha.db import schema
from neesha.harness.gate import EngagementView
from neesha.harness.deletion import delete_investigation
from neesha.ledger.ledger import Ledger


def investigated(engine, tmp_path, monkeypatch, domain='example.com'):
    monkeypatch.setattr('neesha.adapters.crtsh.http_get', lambda *a, **kw: json.dumps([
        {'name_value': 'mail.example.com', 'issuer_name': 'Example CA'}]))
    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        conn.execute(schema.engagement.insert().values(
            id='context', authority_basis='prospect_company', authorized_domains=[domain],
            authorized_by='test', starts_at=now-timedelta(days=1),
            expires_at=now+timedelta(days=1), created_at=now))
    workspace = Workspace(engine, {'crt.sh'}, tmp_path/'profile.json', tmp_path/'reports')
    engagement = EngagementView('context', 'prospect_company', authorized_domains=(domain,),
                               starts_at=now-timedelta(days=1), expires_at=now+timedelta(days=1))
    workspace._run(domain, engagement, False)
    assert workspace.job['state'] == 'complete'
    return workspace, engagement


def test_delete_removes_run_payload_cache_entities_reports_but_retains_spend(engine, tmp_path, monkeypatch):
    workspace, _ = investigated(engine, tmp_path, monkeypatch)
    run_id = workspace.job['run_id']
    ledger = Ledger(engine)
    ledger.set_cap(Decimal('10'))
    reservation = ledger.reserve('example', Decimal('1'), run_id=run_id)
    ledger.settle(reservation.id, Decimal('1'))
    folder = workspace.reports_root/'runtime'
    folder.mkdir(parents=True)
    report = folder/(run_id+'.json')
    report.write_text('{"claims":[]}')
    unrelated = folder/'keep.json'
    unrelated.write_text('{}')
    result = workspace.delete(run_id)
    assert result['deleted'] and result['reports_removed'] == 1
    assert not report.exists() and unrelated.exists()
    assert workspace.job == {'state': 'idle'}
    with engine.connect() as conn:
        for table in (schema.run, schema.fact, schema.source_record, schema.cache,
                      schema.entity, schema.engagement, schema.pir, schema.query_log):
            assert conn.execute(sa.select(sa.func.count()).select_from(table)).scalar() == 0
        row = conn.execute(sa.select(schema.ledger)).mappings().one()
        assert row['run_id'] is None and row['actual_usd'] == Decimal('1')
    assert ledger.summary().committed_usd == Decimal('1')


def test_other_runs_keep_their_facts_and_shared_entities(engine, tmp_path, monkeypatch):
    workspace, engagement = investigated(engine, tmp_path, monkeypatch)
    first = workspace.job['run_id']
    workspace._run('example.com', engagement, False)
    second = workspace.job['run_id']
    workspace.delete(first)
    assert workspace.brief(second)['facts']
    assert workspace.snapshot()['runs'][0]['id'] == second
    with engine.connect() as conn:
        assert not conn.execute(sa.select(schema.source_record).where(schema.source_record.c.run_id==first)).first()
        assert conn.execute(sa.select(schema.engagement)).first()


def test_deletion_refuses_busy_workspace_and_unsettled_charges(engine, tmp_path, monkeypatch):
    workspace, _ = investigated(engine, tmp_path, monkeypatch)
    run_id = workspace.job['run_id']
    workspace.analyzing.add(run_id)
    with pytest.raises(ValueError, match='finish'):
        workspace.delete(run_id)
    workspace.analyzing.clear()
    ledger = Ledger(engine)
    ledger.set_cap(Decimal('10'))
    ledger.reserve('example', Decimal('1'), run_id=run_id)
    with pytest.raises(ValueError, match='unsettled'):
        workspace.delete(run_id)
    assert workspace.brief(run_id)['facts']


def test_deletion_rejects_report_symlink_without_following_it(engine, tmp_path, monkeypatch):
    workspace, _ = investigated(engine, tmp_path, monkeypatch)
    run_id = workspace.job['run_id']
    workspace.reports_root.mkdir()
    actual = tmp_path/'keep.json'
    actual.write_text('keep')
    (workspace.reports_root/(run_id+'.json')).symlink_to(actual)
    with pytest.raises(ValueError, match='symbolic'):
        workspace.delete(run_id)
    assert actual.read_text() == 'keep'
    assert workspace.brief(run_id)['facts']
