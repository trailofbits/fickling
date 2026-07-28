PY_MODULE := fickling

.PHONY: all
all:
	@echo "Run my targets individually!"

.PHONY: dev
dev:
	uv sync --all-extras

.PHONY: lint
lint:
	uv run ruff format --check .
	uv run ruff check $(PY_MODULE)
	# advisory until the annotations are fixed, matching lint.yml
	-uv run ty check $(PY_MODULE)

.PHONY: format
format:
	uv run ruff check --fix $(PY_MODULE)
	uv run ruff format .

.PHONY: test
test:
	uv run pytest --cov=$(PY_MODULE) test/
	uv run coverage report

.PHONY: test-quick
test-quick:
	uv run pytest -q test/

.PHONY: typecheck
typecheck:
	uv run ty check $(PY_MODULE)

.PHONY: dist
dist:
	uv build

.PHONY: clean
clean:
	rm -rf dist/ build/ *.egg-info .coverage .pytest_cache .ty_cache .ruff_cache
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
