# Fuzzing targets. Run these from this directory: `cd fuzz && make <target>`.
#
# Everything goes through `uv run`, which resolves the pinned interpreter and creates .venv
# from uv.lock on first use, so `make fuzz` works on a fresh checkout with no setup step.

ARGS ?= -max_total_time=60

# --project . rather than discovery, so the targets survive `make -C fuzz` too.
UV_RUN := uv run --project .

.PHONY: help
help:
	@echo "make env        build .venv from uv.lock (needs clang, cargo, dev headers)"
	@echo "make fuzz       fuzz for 60s; ARGS='-max_total_time=3600 -jobs=4' to extend"
	@echo "make check      self-test, no fuzzing"
	@echo "make report     list recorded findings"
	@echo "make test       unit tests for the harness itself"
	@echo "make coverage   HTML report of what the corpus reaches in fickling"
	@echo "make lint       ruff over the harness"
	@echo "make clean      drop corpus, findings and coverage output"

.PHONY: env
env:
# Optional: the first `uv run` would do this anyway. Both deps compile from source, so it
# needs clang, cargo and the dev headers; uv fetches the interpreter itself.
	CC=clang CXX=clang++ uv sync --project .
	@echo "fuzz: ready on $$($(UV_RUN) python -V)"

corpus:
	$(UV_RUN) python harness.py --write-corpus corpus

.PHONY: fuzz
fuzz: corpus
	$(UV_RUN) python harness.py corpus $(ARGS)

.PHONY: check
check:
	$(UV_RUN) python harness.py --check

.PHONY: report
report:
	$(UV_RUN) python harness.py --summary

.PHONY: test
test:
	$(UV_RUN) pytest -q tests/

.PHONY: coverage
coverage: corpus
# Runs the oracles without atheris, which would otherwise rewrite fickling's bytecode out
# from under coverage.py.
	$(UV_RUN) coverage run corpus_coverage.py corpus
	$(UV_RUN) coverage html
	@$(UV_RUN) coverage report | tail -1
	@echo "coverage: file://$(CURDIR)/htmlcov/index.html"

.PHONY: lint
lint:
# Ruff comes from the parent project, where it is a dev dependency; the config for these
# files still comes from fuzz/pyproject.toml.
	uv run --project .. ruff format --check .
	uv run --project .. ruff check .

.PHONY: clean
clean:
	rm -rf artifacts corpus htmlcov .coverage
