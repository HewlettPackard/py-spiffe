.DEFAULT_GOAL := help

UV_CMD=uv
ROOT_DIR=$(PWD)

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
integration: ## Run integration tests.
	$(UV_CMD) run pytest tests/integration -W ignore::DeprecationWarning

.PHONY: lint
lint: black flake8 mypy ## Lint source files.

.PHONY: format
format: ## Reformat source files with black.
	@echo "Running black to format source files."
	$(UV_CMD) run black src tests

.PHONY: black
black:
	@echo "Running black (check only)."
	$(UV_CMD) run black --check --diff --color src tests

.PHONY: flake8
flake8:
	@echo "Running flake8."
	$(UV_CMD) run flake8 src tests

.PHONY: mypy
mypy:
	@echo "Running mypy."
	$(UV_CMD) run mypy src

# Helper target for displaying help
.PHONY: help
help:
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-30s %s\n", $$1, $$2}'
