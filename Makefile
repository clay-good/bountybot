# BountyBot Makefile
# Provides convenient commands for development, testing, and deployment

.PHONY: help install install-dev test test-unit test-integration test-coverage lint format security clean build docker-build docker-run docs

# Default target
.DEFAULT_GOAL := help

# Variables
PYTHON := python3
PIP := $(PYTHON) -m pip
PYTEST := $(PYTHON) -m pytest
BLACK := $(PYTHON) -m black
ISORT := $(PYTHON) -m isort
FLAKE8 := $(PYTHON) -m flake8
PYLINT := $(PYTHON) -m pylint
MYPY := $(PYTHON) -m mypy
BANDIT := $(PYTHON) -m bandit
DOCKER := docker
DOCKER_IMAGE := bountybot
DOCKER_TAG := latest

help: ## Show this help message
	@echo "BountyBot - Development Commands"
	@echo "================================="
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Installation targets
install: ## Install production dependencies
	$(PIP) install --upgrade pip
	$(PIP) install -e .

install-dev: ## Install development dependencies
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev,docs]"
	$(PIP) install pre-commit
	pre-commit install

# Testing targets
test: ## Run all tests
	$(PYTEST) tests/ -v

test-unit: ## Run unit tests only
	$(PYTEST) tests/ -v -m "not integration and not performance"

test-integration: ## Run integration tests only
	$(PYTEST) tests/ -v -m integration

test-performance: ## Run performance tests
	$(PYTEST) tests/ -v -m performance --benchmark-only

test-coverage: ## Run tests with coverage report
	$(PYTEST) tests/ -v --cov=bountybot --cov-report=html --cov-report=term --cov-report=xml
	@echo "Coverage report generated in htmlcov/index.html"

test-watch: ## Run tests in watch mode
	$(PYTEST) tests/ -v --looponfail

# Code quality targets
lint: ## Run all linters
	@echo "Running Black..."
	$(BLACK) --check bountybot/ tests/
	@echo "Running isort..."
	$(ISORT) --check-only bountybot/ tests/
	@echo "Running Flake8..."
	$(FLAKE8) bountybot/ tests/
	@echo "Running Pylint..."
	$(PYLINT) bountybot/ --exit-zero
	@echo "Running MyPy..."
	$(MYPY) bountybot/ --ignore-missing-imports

format: ## Format code with Black and isort
	@echo "Formatting with Black..."
	$(BLACK) bountybot/ tests/
	@echo "Sorting imports with isort..."
	$(ISORT) bountybot/ tests/
	@echo "Code formatted successfully!"

security: ## Run security checks
	@echo "Running Bandit security scanner..."
	$(BANDIT) -r bountybot/ -ll
	@echo "Checking dependencies for vulnerabilities..."
	$(PIP) install safety
	safety check --json || true

# Cleaning targets
clean: ## Clean build artifacts and cache files
	@echo "Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	@echo "Clean complete!"

clean-all: clean ## Clean everything including virtual environment
	rm -rf venv/
	rm -rf .venv/
	rm -rf node_modules/

# Build targets
build: clean ## Build distribution packages
	@echo "Building distribution packages..."
	$(PYTHON) -m build
	@echo "Build complete! Packages in dist/"

build-check: build ## Build and check distribution packages
	$(PYTHON) -m twine check dist/*

# Docker targets
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	$(DOCKER) build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@echo "Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)"

docker-build-no-cache: ## Build Docker image without cache
	@echo "Building Docker image (no cache)..."
	$(DOCKER) build --no-cache -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

docker-run: ## Run Docker container
	$(DOCKER) run -it --rm \
		-e ANTHROPIC_API_KEY=$(ANTHROPIC_API_KEY) \
		-v $(PWD)/reports:/app/reports \
		$(DOCKER_IMAGE):$(DOCKER_TAG)

docker-run-api: ## Run API server in Docker
	$(DOCKER) run -d \
		-p 8000:8000 \
		-e ANTHROPIC_API_KEY=$(ANTHROPIC_API_KEY) \
		--name bountybot-api \
		$(DOCKER_IMAGE):$(DOCKER_TAG) \
		python3 -m bountybot.api.cli --host 0.0.0.0 --port 8000

docker-stop: ## Stop Docker container
	$(DOCKER) stop bountybot-api || true
	$(DOCKER) rm bountybot-api || true

docker-logs: ## View Docker container logs
	$(DOCKER) logs -f bountybot-api

docker-shell: ## Open shell in Docker container
	$(DOCKER) run -it --rm \
		-e ANTHROPIC_API_KEY=$(ANTHROPIC_API_KEY) \
		$(DOCKER_IMAGE):$(DOCKER_TAG) \
		/bin/bash

docker-scan: ## Scan Docker image for vulnerabilities
	$(DOCKER) scan $(DOCKER_IMAGE):$(DOCKER_TAG) || true

# Documentation targets
docs: ## Build documentation
	@echo "Building documentation..."
	cd docs && make html
	@echo "Documentation built in docs/_build/html/"

docs-serve: docs ## Build and serve documentation
	@echo "Serving documentation at http://localhost:8080"
	cd docs/_build/html && $(PYTHON) -m http.server 8080

docs-clean: ## Clean documentation build
	cd docs && make clean

# Development targets
dev-setup: install-dev ## Complete development setup
	@echo "Setting up development environment..."
	@echo "Creating .env file if it doesn't exist..."
	@test -f .env || echo "ANTHROPIC_API_KEY=your-key-here" > .env
	@echo "Development setup complete!"
	@echo "Don't forget to set your ANTHROPIC_API_KEY in .env"

dev-run: ## Run development server
	$(PYTHON) -m bountybot.api.cli --reload

dev-dashboard: ## Run development dashboard
	$(PYTHON) -m bountybot.dashboard.cli --reload

# Database targets
db-init: ## Initialize database
	$(PYTHON) -c "from bountybot.database import init_database; init_database('sqlite:///bountybot.db')"

db-migrate: ## Run database migrations
	$(PYTHON) -m bountybot.database.migrations upgrade

db-reset: ## Reset database (WARNING: deletes all data)
	@echo "WARNING: This will delete all data!"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		rm -f bountybot.db; \
		$(MAKE) db-init; \
		echo "Database reset complete!"; \
	fi

# CI/CD targets
ci-test: ## Run CI test suite
	$(PYTEST) tests/ -v --cov=bountybot --cov-report=xml --cov-report=term

ci-lint: ## Run CI linting
	$(BLACK) --check bountybot/ tests/
	$(ISORT) --check-only bountybot/ tests/
	$(FLAKE8) bountybot/ tests/
	$(PYLINT) bountybot/ --exit-zero

ci-security: ## Run CI security checks
	$(BANDIT) -r bountybot/ -f json -o bandit-report.json || true
	$(BANDIT) -r bountybot/ -ll

ci-all: ci-lint ci-security ci-test ## Run all CI checks

# Release targets
release-check: ## Check if ready for release
	@echo "Checking release readiness..."
	@$(MAKE) ci-all
	@$(MAKE) build-check
	@echo "Release checks passed!"

release-patch: ## Bump patch version and create release
	@echo "Bumping patch version..."
	bump2version patch
	git push && git push --tags

release-minor: ## Bump minor version and create release
	@echo "Bumping minor version..."
	bump2version minor
	git push && git push --tags

release-major: ## Bump major version and create release
	@echo "Bumping major version..."
	bump2version major
	git push && git push --tags

# Monitoring targets
metrics: ## Show code metrics
	@echo "Code Metrics:"
	@echo "============="
	@echo "Lines of code:"
	@find bountybot -name "*.py" | xargs wc -l | tail -1
	@echo ""
	@echo "Number of files:"
	@find bountybot -name "*.py" | wc -l
	@echo ""
	@echo "Test coverage:"
	@$(PYTEST) tests/ --cov=bountybot --cov-report=term | grep "TOTAL"

complexity: ## Show code complexity
	@echo "Code Complexity:"
	@echo "================"
	radon cc bountybot/ -a -s

maintainability: ## Show maintainability index
	@echo "Maintainability Index:"
	@echo "======================"
	radon mi bountybot/ -s

# Utility targets
validate: ## Validate report file
	@read -p "Enter report file path: " filepath; \
	$(PYTHON) -m bountybot.cli $$filepath

demo: ## Run demo
	$(PYTHON) demo_monitoring.py

version: ## Show version
	@$(PYTHON) -c "import bountybot; print(f'BountyBot v{bountybot.__version__}')"

info: ## Show system information
	@echo "System Information:"
	@echo "==================="
	@echo "Python version: $$($(PYTHON) --version)"
	@echo "Pip version: $$($(PIP) --version)"
	@echo "Docker version: $$($(DOCKER) --version 2>/dev/null || echo 'Not installed')"
	@echo ""
	@echo "Installed packages:"
	@$(PIP) list | grep -E "anthropic|fastapi|pydantic|sqlalchemy"

