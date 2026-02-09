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
	$(UV_CMD) run pyright --verifytypes spiffetls --ignoreexternal

# Helper target for displaying help
.PHONY: help
help:
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-30s %s\n", $$1, $$2}'
