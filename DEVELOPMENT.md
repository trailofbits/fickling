# Development Guide

This guide covers the development workflow for Fickling using modern Python tooling.

## Prerequisites

- Python 3.9 or higher
- [uv](https://github.com/astral-sh/uv) - Fast Python package installer and resolver

### Installing uv

```bash
# On macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# On Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

# Or via pip
pip install uv
```

## Setting up the Development Environment

1. Clone the repository:
```bash
git clone https://github.com/trailofbits/fickling.git
cd fickling
```

2. Install development dependencies:
```bash
# Install all dependencies including dev, test, and torch extras
make dev
# OR
uv sync --all-extras
```

3. Install pre-commit hooks (optional but recommended):
```bash
make pre-commit-install
# OR
uv run pre-commit install
```

## Development Workflow

### Running Tests

```bash
# Run full test suite with coverage
make test

# Run tests quickly without coverage
make test-quick

# Run specific test file
uv run pytest test/test_pickle.py

# Run tests with specific Python version
uv run --python 3.11 pytest test/
```

### Code Quality Tools

#### Formatting Code

```bash
# Auto-format code
make format
# OR
uv run ruff format .
```

#### Linting

```bash
# Check code style and common issues
make lint
# OR
uv run ruff check fickling
```

#### Type Checking

```bash
# Run mypy type checker
make typecheck
# OR
uv run mypy fickling
```

### Pre-commit Checks

Run all pre-commit checks manually:
```bash
make pre-commit
# OR
uv run pre-commit run --all-files
```

## Code Style Guide

We use [Ruff](https://github.com/astral-sh/ruff) for both linting and formatting with the following configuration:

- **Line length**: 100 characters
- **Quote style**: Double quotes
- **Target Python version**: 3.9+

Key linting rules enforced:
- pycodestyle errors and warnings (E, W)
- pyflakes (F)
- isort import sorting (I)
- pep8-naming conventions (N)
- pyupgrade for modern Python syntax (UP)
- flake8-bugbear for common bugs (B)
- flake8-simplify for code simplification (SIM)
- Performance anti-patterns (PERF)

## Building and Publishing

### Building the Package

```bash
# Build source distribution and wheel
make dist
# OR
uv build
```

Built artifacts will be in the `dist/` directory.

### Cleaning Build Artifacts

```bash
# Remove all build artifacts and caches
make clean
```

## Project Structure

```
fickling/
├── fickling/          # Main package source code
│   ├── __init__.py    # Package initialization and version
│   ├── cli.py         # Command-line interface
│   ├── analysis.py    # Static analysis functionality
│   ├── fickle.py      # Core pickle handling
│   ├── loader.py      # Safe loading utilities
│   ├── pytorch.py     # PyTorch-specific functionality
│   └── ...
├── test/              # Test files
├── example/           # Example scripts and PoCs
├── pyproject.toml     # Project configuration and dependencies
├── Makefile           # Development task automation
└── .pre-commit-config.yaml  # Pre-commit hook configuration
```

## Continuous Integration

The project uses GitHub Actions for CI/CD:

- **tests.yml**: Runs tests across Python 3.9-3.13
- **lint.yml**: Runs linting and type checking
- **pip-audit.yml**: Security vulnerability scanning

All CI workflows use `uv` for fast, reliable dependency management.

## Troubleshooting

### Common Issues

1. **Import errors with torch**: The PyTorch functionality is optional. Install with:
   ```bash
   uv pip install -e ".[torch]"
   ```

2. **Type checking errors**: Ensure you have the latest mypy and type stubs:
   ```bash
   uv sync --extra lint
   ```

3. **Pre-commit hook failures**: Update pre-commit hooks:
   ```bash
   uv run pre-commit autoupdate
   ```

## Contributing

1. Create a feature branch from `master`
2. Make your changes
3. Run tests and linting: `make test lint`
4. Commit with descriptive messages
5. Push and create a pull request

All pull requests must pass CI checks before merging.