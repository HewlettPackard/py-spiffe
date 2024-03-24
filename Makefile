# Root Makefile for managing pyspiffe modules

# Define module directories
CORE_DIR=./pyspiffe
TLS_DIR=./pyspiffe-tls

.DEFAULT_GOAL := help

.PHONY: all
all: lint build test

.PHONY: deps
deps:
	@echo "Installing dependencies for all modules..."
	cd $(CORE_DIR) && $(MAKE) deps
	cd $(TLS_DIR) && $(MAKE) deps

.PHONY: build
build: deps
	@echo "Building all modules..."
	cd $(CORE_DIR) && $(MAKE) build
	cd $(TLS_DIR) && $(MAKE) build

.PHONY: test
test:
	@echo "Running tests for all modules..."
	cd $(CORE_DIR) && $(MAKE) test
	cd $(TLS_DIR) && $(MAKE) test


.PHONY: format
format:
	@echo "Formatting all modules..."
	cd $(CORE_DIR) && $(MAKE) format
	cd $(TLS_DIR) && $(MAKE) format

.PHONY: lint
lint: format
	@echo "Linting all modules..."
	cd $(CORE_DIR) && $(MAKE) lint
	cd $(TLS_DIR) && $(MAKE) lint


.PHONY: pre-commit ## Prepare files for commit.
pre-commit: copyright lint

.PHONY: copyright
copyright:
	@echo "Adding copyright header to files..."
	python scripts/copyright.py

# Display help for the root Makefile
help:
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  deps        Install dependencies for all modules"
	@echo "  build       Build all modules"
	@echo "  test        Run tests for all modules"
	@echo "  lint        Lint all modules"
	@echo "  format      Format all modules"
	@echo "  help        Display this help message"
