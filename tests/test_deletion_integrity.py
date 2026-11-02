"""Deletion remains sound with FK enforcement and shared email roots."""
import pytest
import sqlalchemy as sa

from neesha.adapters import registry
from neesha.db import schema
from neesha.harness.deletion import delete_investigation
from neesha.harness.gate import PolicyGate
from neesha.harness.run import execute_run
from neesha.ledger.ledger import Ledger
from tests.test_email_harness import PublicEmailFixture, email_engagement


@pytest.fixture
def foreign_keys(engine):
    engine.dispose()
    def enforce(dbapi_conn, connection_record):
        dbapi_conn.execute('PRAGMA foreign_keys=ON')
    sa.event.listen(engine,'connect',enforce)
    yield engine
    sa.event.remove(engine,'connect',enforce)


def test_delete_email_run_preserves_shared_root_then_removes_last_root(
    foreign_keys,email_engagement,monkeypatch,tmp_path
):
    engine=foreign_keys
    monkeypatch.setitem(registry.ADAPTERS,PublicEmailFixture.name,PublicEmailFixture)
    ledger=Ledger(engine)
    reports=[execute_run(engine=engine,ledger=ledger,gate=PolicyGate(engine,ledger),
        company='Dana@gmail.com',subject_kind='email',engagement=email_engagement,
        analyst='test',sources={'public-email-fixture'}) for _ in range(2)]
    assert reports[0].company_id==reports[1].company_id
    result=delete_investigation(engine,reports[0].run_id,tmp_path/'reports')
    assert result['deleted']
    with engine.connect() as conn:
        assert conn.exec_driver_sql('PRAGMA foreign_keys').scalar()==1
        assert conn.execute(sa.select(schema.entity.c.id).where(schema.entity.c.id==reports[1].company_id)).scalar()
        assert conn.execute(sa.select(sa.func.count()).select_from(schema.fact).where(
            schema.fact.c.run_id==reports[1].run_id)).scalar()==2
        assert conn.execute(sa.select(sa.func.count()).select_from(schema.cache)).scalar()==0
    assert delete_investigation(engine,reports[1].run_id,tmp_path/'reports')['deleted']
    with engine.connect() as conn:
        assert conn.exec_driver_sql('PRAGMA foreign_key_check').all()==[]
        assert conn.execute(sa.select(sa.func.count()).select_from(schema.entity)).scalar()==0
        assert conn.execute(sa.select(sa.func.count()).select_from(schema.engagement)).scalar()==0
