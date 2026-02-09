.DEFAULT_GOAL := help

UV_CMD=uv
ROOT_DIR=$(shell pwd)
PROTO_DIR=$(ROOT_DIR)/src/spiffe/_proto

.PHONY: all
all: lint build test ## Runs lint, build, and test targets sequentially.

.PHONY: deps
deps: ## Installs project dependencies.
	$(UV_CMD) sync --all-groups

.PHONY: build
build: deps ## Build the distributable packages.
	$(UV_CMD) build

.PHONY: test
test: ## Run unit tests.
	$(UV_CMD) run pytest tests/unit -W ignore::DeprecationWarning

.PHONY: integration
integration: ## Run integration tests
	$(UV_CMD) run pytest tests/integration -W ignore::DeprecationWarning

.PHONY: compile-proto
compile-proto:
	@echo "Compiling protobuf files..."
	$(UV_CMD) run python -m grpc_tools.protoc -I$(ROOT_DIR)/src --python_out=$(ROOT_DIR)/src --mypy_out=$(ROOT_DIR)/src --grpc_python_out=$(ROOT_DIR)/src $(PROTO_DIR)/*.proto

.PHONY: test-coverage
test-coverage: ## Run tests with coverage reporting
	@echo "Running tests with coverage reporting..."
	$(UV_CMD) run coverage run -m pytest
	$(UV_CMD) run coverage report -m
	$(UV_CMD) run coverage xml
	$(UV_CMD) run coverage html
	@echo "HTML coverage report generated in htmlcov/index.html"

.PHONY: lint
lint: format-check check mypy pyright ## Lint source files.

.PHONY: format
format: ## Reformat source files with ruff.
	@echo "Running ruff to format source files."
	$(UV_CMD) run ruff format src tests

.PHONY: format-check
format-check:
	@echo "Running ruff (check only)."
	$(UV_CMD) run ruff format --check --diff src tests

.PHONY: check
check:
	@echo "Running ruff."
	$(UV_CMD) run ruff check src tests

.PHONY: mypy
mypy:
	@echo "Running mypy."
	$(UV_CMD) run mypy src tests

.PHONY: pyright
pyright:
	@echo "Running pyright."
	$(UV_CMD) run pyright src tests
	$(UV_CMD) run pyright --verifytypes spiffe --ignoreexternal

# Helper target for displaying help
.PHONY: help
help:
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-30s %s\n", $$1, $$2}'
