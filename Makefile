.DEFAULT_GOAL := help
PY ?= python3
NOW ?= 2026-10-17T23:00:00Z

help: ## Show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

setup: ## Create .venv and install dev dependencies
	$(PY) -m venv .venv
	.venv/bin/pip install -r requirements-dev.txt

test: ## Run unit tests
	$(PY) -m pytest

lint: ## Lint Python and YAML
	ruff check .
	yamllint .

demo: ## Run the simulated incident (deterministic, writes demo-audit.jsonl)
	rm -f demo-audit.jsonl
	$(PY) -m netops_agent run --samples samples/incident.json --audit demo-audit.jsonl --now $(NOW)

verify: ## Check the demo audit log's hash chain
	$(PY) -m netops_agent verify --audit demo-audit.jsonl

ci: test lint ## Everything CI runs

.PHONY: help setup test lint demo verify ci
