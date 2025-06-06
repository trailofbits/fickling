PY_MODULE := fickling

# Optionally overriden by the user, if they're using a virtual environment manager.
VENV ?= env
VENV_EXISTS := $(VENV)/pyvenv.cfg

# On Windows, venv scripts/shims are under `Scripts` instead of `bin`.
VENV_BIN := $(VENV)/bin
ifeq ($(OS),Windows_NT)
	VENV_BIN := $(VENV)/Scripts
endif

# Optionally overridden by the user/CI, to limit the installation to a specific
# subset of development dependencies.
INSTALL_EXTRA := dev

ALL_PY_SRCS := $(shell find $(PY_MODULE) -name '*.py') \
	$(shell find test -name '*.py') \
	$(shell find example -name '*.py') \

.PHONY: all
all:
	@echo "Run my targets individually!"

$(VENV)/pyvenv.cfg: pyproject.toml
	python -m venv env
	. $(VENV_BIN)/activate && \
		pip install --upgrade pip setuptools && \
		pip install -e .[$(INSTALL_EXTRA)]

.PHONY: dev
dev: $(VENV)/pyvenv.cfg

.PHONY: lint
lint: $(VENV_EXISTS)
	. $(VENV_BIN)/activate && \
		ruff format --check $(ALL_PY_SRCS) && \
		ruff check $(PY_MODULE)

.PHONY: format
format: $(VENV_EXISTS)
	. $(VENV_BIN)/activate && \
		ruff check --fix $(PY_MODULE) && \
		ruff format $(ALL_PY_SRCS)

.PHONY: test
test: $(VENV_EXISTS)
	. $(VENV_BIN)/activate && \
		pytest --cov=$(PY_MODULE) test/ && \
		python -m coverage report

.PHONY: dist
dist: $(VENV_EXISTS)
	. $(VENV_BIN)/activate && \
		python -m build

.PHONY: edit
edit:
	$(EDITOR) $(ALL_PY_SRCS)
