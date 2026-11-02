"""Shared fixtures.

Two database backends are available to tests. SQLite is the default because
it is fast and needs nothing running. Postgres is used where the behaviour
under test is specifically a Postgres guarantee — row locks for the budget
cap — and those tests skip when it is not reachable rather than passing
vacuously against a backend that cannot provide the guarantee.

To run the Postgres-backed tests:

    docker compose up -d postgres
    NEESHA_TEST_DATABASE_URL=postgresql+psycopg://neesha:<pw>@127.0.0.1:5433/neesha \\
        .venv/bin/pytest -q
"""
import os

import pytest
import sqlalchemy as sa

from neesha.db import schema


@pytest.fixture
def engine(tmp_path):
    """A file-backed SQLite engine; file-backed so threads share state."""
    eng = sa.create_engine(f"sqlite:///{tmp_path / 'test.sqlite3'}")
    schema.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def pg_engine():
    """A real Postgres engine, or a skip.

    The schema is recreated per test so cases cannot leak spend into each
    other through the ledger.
    """
    url = os.environ.get("NEESHA_TEST_DATABASE_URL")
    if not url:
        pytest.skip(
            "NEESHA_TEST_DATABASE_URL is not set; Postgres-backed tests skipped"
        )
    eng = sa.create_engine(url, pool_size=32, max_overflow=32)
    try:
        with eng.connect() as conn:
            conn.execute(sa.text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Postgres not reachable at the configured URL: {exc}")
    schema.metadata.drop_all(eng)
    schema.metadata.create_all(eng)
    yield eng
    schema.metadata.drop_all(eng)
    eng.dispose()


@pytest.fixture(autouse=True)
def configured_hunter_test_cost(monkeypatch):
    # Tests use an explicit fixture price, never an assumed live provider rate.
    monkeypatch.setenv('HUNTER_ESTIMATED_USD_PER_SEARCH', '0.01')
