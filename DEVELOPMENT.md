# Development Guide

## Setup

Install [uv](https://github.com/astral-sh/uv):
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh  # macOS/Linux
# OR
pip install uv
```

Clone and install:
```bash
git clone https://github.com/trailofbits/fickling.git
cd fickling
make dev  # or: uv sync --all-extras
```

## Common Tasks

```bash
make test           # Run tests with coverage
make test-quick     # Run tests without coverage
make lint           # Check code style
make format         # Auto-format code
make typecheck      # Run type checker
make dist           # Build package
make clean          # Remove build artifacts
```

## Code Style

- Ruff for linting and formatting
- Line length: 100 characters
- Double quotes
- Python 3.9+ syntax

## Project Structure

```
fickling/
├── fickling/       # Source code
├── test/           # Tests
├── example/        # Examples
├── pyproject.toml  # Dependencies
└── Makefile        # Task automation
```

## Contributing

1. Branch from `master`
2. Make changes
3. Run `make test lint`
4. Create pull request

CI runs tests on Python 3.9-3.13.