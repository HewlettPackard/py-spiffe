.DEFAULT_GOAL := help

POETRY_CMD=poetry
ROOT_DIR=$(PWD)
PROTO_DIR=./src/pyspiffe/proto/spiffe

.PHONY: all
all: lint build test ## Runs lint, build, and test targets sequentially.

.PHONY: deps
deps: ## Installs project dependencies.
	$(POETRY_CMD) install

.PHONY: build
build: deps ## Build the distributable packages.
	$(POETRY_CMD) build

.PHONY: test
test: ## Run unit tests.
	$(POETRY_CMD) run pytest

.PHONY: compile-proto
compile-proto:
	@echo "Compiling protobuf files..."
	$(POETRY_CMD) run python -m grpc_tools.protoc -I$(PROTO_DIR) --python_out=$(PROTO_DIR) --grpc_python_out=$(PROTO_DIR) $(PROTO_DIR)/*.proto

.PHONY: copyright
copyright:
	@echo "Adding copyright header to files..."
	$(POETRY_CMD) run python scripts/copyright.py

.PHONY: pre-commit ## Prepare files for commit.
pre-commit: copyright lint

.PHONY: test-coverage
test-coverage: ## Run tests with coverage reporting
	@echo "Running tests with coverage reporting..."
	$(POETRY_CMD) run coverage run -m pytest
	$(POETRY_CMD) run coverage report -m
	$(POETRY_CMD) run coverage xml
	$(POETRY_CMD) run coverage html
	@echo "HTML coverage report generated in htmlcov/index.html"

.PHONY: lint
lint: black flake8 mypy ## Lint source files.

.PHONY: format
format: ## Reformat source files with black.
	@echo "Running black to format source files."
	$(POETRY_CMD) run black src test

.PHONY: docs
docs: ## Generates docs.
	@echo "Generating docs."
	$(POETRY_CMD) run sphinx-build -T -W -b html docs docs/_build/html
	@echo "\033[95m\n\nBuild successful! View the docs homepage at docs/_build/html/index.html.\n\033[0m"

.PHONY: black
black:
	@echo "Running black (check only)."
	$(POETRY_CMD) run black --check --diff --color src test

.PHONY: flake8
flake8:
	@echo "Running flake8."
	$(POETRY_CMD) run flake8 src test

.PHONY: mypy
mypy:
	@echo "Running mypy."
	$(POETRY_CMD) run mypy src

# Helper target for displaying help
.PHONY: help
help:
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-30s %s\n", $$1, $$2}'
