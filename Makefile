PY_MODULE := fickling

ALL_PY_SRCS := $(shell find $(PY_MODULE) -name '*.py') \
	$(shell find test -name '*.py') \
	$(shell find example -name '*.py')

.PHONY: all
all:
	@echo "Run my targets individually!"

.PHONY: dev
dev:
	uv sync --all-extras

.PHONY: lint
lint:
	uv run ruff format --check $(ALL_PY_SRCS)
	uv run ruff check $(PY_MODULE)
	uv run mypy $(PY_MODULE)

.PHONY: format
format:
	uv run ruff check --fix $(PY_MODULE)
	uv run ruff format $(ALL_PY_SRCS)

.PHONY: test
test:
	uv run pytest --cov=$(PY_MODULE) test/
	uv run coverage report

.PHONY: test-quick
test-quick:
	uv run pytest -q test/

.PHONY: typecheck
typecheck:
	uv run mypy $(PY_MODULE)

.PHONY: dist
dist:
	uv build

.PHONY: clean
clean:
	rm -rf dist/ build/ *.egg-info .coverage .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

.PHONY: install
install:
	uv pip install -e .

.PHONY: install-dev
install-dev:
	uv pip install -e ".[dev]"

.PHONY: pre-commit-install
pre-commit-install:
	uv run pre-commit install

.PHONY: pre-commit
pre-commit:
	uv run pre-commit run --all-files
