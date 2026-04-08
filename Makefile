# llm-sneak — Makefile
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: install install-dev poetry test test-fast lint format clean uninstall help

PYTHON ?= python3
PIP    ?= pip3

# ── Install ───────────────────────────────────────────────────────────────────

install:                        ## Install globally — adds `llm-sneak` command
	@echo "Installing llm-sneak..."
	$(PIP) install . || $(PIP) install . --break-system-packages
	@echo ""
	@echo "✓  Done!  Run: llm-sneak --help"

install-dev:                    ## Install with dev tools (pytest, ruff, mypy)
	@echo "Installing llm-sneak (dev mode)..."
	$(PIP) install -e ".[dev]" || $(PIP) install -e ".[dev]" --break-system-packages
	@echo "✓  Dev install done.  Run: make test"

poetry:                         ## Install via Poetry
	@which poetry >/dev/null 2>&1 || \
		(echo "Installing Poetry..." && \
		curl -sSL https://install.python-poetry.org | $(PYTHON) -)
	poetry install
	@echo ""
	@echo "✓  Done! Activate venv:  poetry shell"
	@echo "   Then run:             llm-sneak --help"

# ── Testing ───────────────────────────────────────────────────────────────────

test:                           ## Run full test suite
	$(PYTHON) -m pytest tests/ -v --tb=short

test-fast:                      ## Run tests, stop on first failure
	$(PYTHON) -m pytest tests/ -x -q

# ── Code quality ──────────────────────────────────────────────────────────────

lint:                           ## Lint with ruff
	$(PYTHON) -m ruff check llmsneak/

format:                         ## Format with black
	$(PYTHON) -m black llmsneak/ tests/

typecheck:                      ## Type check with mypy
	$(PYTHON) -m mypy llmsneak/ --ignore-missing-imports

check: lint typecheck           ## Run lint + typecheck

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:                          ## Remove build artifacts and caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc"     -delete  2>/dev/null || true
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .mypy_cache/ .ruff_cache/
	@echo "✓  Cleaned"

uninstall:                      ## Uninstall llm-sneak
	$(PIP) uninstall llm-sneak -y
	@echo "✓  Uninstalled"

# ── Help ──────────────────────────────────────────────────────────────────────

help:                           ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""

.DEFAULT_GOAL := help
