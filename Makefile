.PHONY: install test run smoke

install:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"

test:
	.venv/bin/pytest -q

run:
	.venv/bin/neesha --help

smoke: install
	.venv/bin/neesha --help
	.venv/bin/neesha init --out ./neesha.toml
	.venv/bin/neesha preflight --purpose "smoke test" --observer "ISP" --out ./runs/smoke
