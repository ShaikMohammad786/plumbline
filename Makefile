.PHONY: install lint type test bench scan docs demo

PYTHON ?= python

install:
	pip install -e ".[dev]"

lint:
	ruff check .
	ruff format --check .

type:
	mypy src tests

test:
	pytest --cov=plumbline/ingest --cov=plumbline/ucm --cov-report=term-missing tests/

bench:
	plumb scan .

scan:
	plumb scan .

docs:
	@echo "Rules documentation will be generated in Phase 2"

demo:
	@echo "Demo generator will run in Phase 7"
