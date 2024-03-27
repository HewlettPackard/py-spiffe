.DEFAULT_GOAL := help

POETRY_CMD=poetry
ROOT_DIR=$(shell pwd)
PROTO_DIR=$(ROOT_DIR)/src/spiffe/proto

.PHONY: all
all: lint build test ## Runs lint, build, and test targets sequentially.

.PHONY: deps
deps: ## Installs project dependencies.
	$(POETRY_CMD) lock
	$(POETRY_CMD) install

.PHONY: build
build: deps ## Build the distributable packages.
	$(POETRY_CMD) build

.PHONY: test
test: ## Run unit tests.
	$(POETRY_CMD) run pytest tests/unit -W ignore::DeprecationWarning

.PHONY: integration
integration: ## Run integration tests
	$(POETRY_CMD) run pytest tests/integration -W ignore::DeprecationWarning

.PHONY: compile-proto
compile-proto:
	@echo "Compiling protobuf files..."
	$(POETRY_CMD) run python -m grpc_tools.protoc -I$(PROTO_DIR) --python_out=$(PROTO_DIR) --grpc_python_out=$(PROTO_DIR) $(PROTO_DIR)/*.proto

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
	$(POETRY_CMD) run black src tests

.PHONY: black
black:
	@echo "Running black (check only)."
	$(POETRY_CMD) run black --check --diff --color src tests

.PHONY: flake8
flake8:
	@echo "Running flake8."
	$(POETRY_CMD) run flake8 src tests

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
