.PHONY: install test test-pg db-up db-down migrate lint

install:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev,postgres]"

# Fast path: SQLite. Postgres-only tests (the budget concurrency proof) skip.
test:
	.venv/bin/pytest -q

# Full path: includes the concurrency tests that prove the spend cap holds.
# Needs `make db-up` first. The row lock those tests exercise is a no-op on
# SQLite, so running them there would prove nothing.
test-pg: db-up
	NEESHA_TEST_DATABASE_URL="postgresql+psycopg://neesha:$$(grep NEESHA_PG_PASSWORD .env | cut -d= -f2)@127.0.0.1:$${NEESHA_PG_PORT:-5433}/neesha" \
		.venv/bin/pytest -q

db-up:
	docker compose up -d postgres
	@until docker compose exec -T postgres pg_isready -U neesha -d neesha >/dev/null 2>&1; do sleep 1; done
	@echo "postgres ready on 127.0.0.1:$${NEESHA_PG_PORT:-5433}"

db-down:
	docker compose down

migrate:
	NEESHA_DATABASE_URL="postgresql+psycopg://neesha:$$(grep NEESHA_PG_PASSWORD .env | cut -d= -f2)@127.0.0.1:$${NEESHA_PG_PORT:-5433}/neesha" \
		.venv/bin/alembic upgrade head

run:
	.venv/bin/neesha --help
