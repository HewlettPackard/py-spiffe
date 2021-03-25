.DEFAULT_GOAL := help

.PHONY: build test docs lint flake8 black mypy format

PIPENV_CMD=pipenv
ROOT_DIR=$(PWD)
PROTO_DIR=./src/pyspiffe/proto/spiffe

NAME = py-spiffe
VERSION = 0.0.1
AUTHOR=HPE

## Creates the distributable packages.
build:
	$(PIPENV_CMD) run python setup.py sdist bdist_wheel

## Creates a new virtual environment if it is not already created.
env:
	$(PIPENV_CMD) --venv || \
	(echo "Creating virtual environment .venv"; \
	PIPENV_VENV_IN_PROJECT=1 $(PIPENV_CMD) sync;)


## Removes the virtual environment if it exist.
rm_env:
	$(PIPENV_CMD) --rm


## Installs dev requirements.
dev: env
	$(PIPENV_CMD) sync --dev && \
	$(PIPENV_CMD) run pre-commit install


## Runs unit tests.
test: export TOX_SKIP_ENV = lint|cov-report
test: lint
	@echo "Running unit tests."
	$(PIPENV_CMD) run tox --recreate

## Generates tests coverage report.
test_cov: test_clean
	@echo "Running test coverage"
	$(PIPENV_CMD) run tox --recreate -e cov-report

## Lint source files.
lint: black flake8 mypy


## Reformat source files with black.
format:
	@echo "Running black to format source files."
	$(PIPENV_CMD) run black --config pyproject.toml src test


## Generates docs.
docs: docs_clean docs_generate lint
	$(PIPENV_CMD) run sphinx-build -n -T -W -b html docs docs/_build/html
	@echo "\033[95m\n\nBuild successful! View the docs homepage at docs/_build/html/index.html.\n\033[0m"
# -n nitpick: Run in nit-picky mode. This generates warnings for all missing references.
# -T Display the full traceback when an unhandled exception occurs.
# -W Turn warnings into errors. This means that the build stops at the first warning and sphinx-build exits with exit status 1
# -b Selects a builder, html here.

## Generates pb files from ./src/pyspiffe/proto/spiffe/workload.proto.
pb_generate:
	@echo "Generates pb files."
	$(PIPENV_CMD) run python -m grpc_tools.protoc \
		--proto_path=$(PROTO_DIR) \
		--mypy_out=$(PROTO_DIR) \
		--python_out=$(PROTO_DIR) \
		--grpc_python_out=$(PROTO_DIR) $(PROTO_DIR)/workload.proto


#------------------------------------------------------------------------
# Internal targets
#------------------------------------------------------------------------

# Targets that aren't normally manually run, so not in the generated help

black:
	@echo "Running black (check only)."
	$(PIPENV_CMD) run black --config pyproject.toml --check --diff --color src test

flake8:
	@echo "Running flake8."
	$(PIPENV_CMD) run flake8 --config tox.ini src test

mypy:
	@echo "Running mypy."
    # `--disable-error-code override` is a workaround to suppress mypy errors in the protobuf generated code,
    # that start showing up when make calls to it, even though it is excluded. TODO: research if there's already a fix for this.
	MYPYPATH=src $(PIPENV_CMD) run mypy --ignore-missing-imports --exclude pyspiffe/proto -p pyspiffe --disable-error-code override

test_clean:
	@echo "cleaning existing test reports"
	rm -rf reports/*

# Generate source files for the documentation
docs_generate: export SPHINX_APIDOC_OPTIONS = members,show-inheritance
docs_generate:
	@echo "Generating source files."
	cd docs && $(PIPENV_CMD) run sphinx-apidoc -feM -o ./source ../src/pyspiffe/

# Cleans docs.
docs_clean:
	@echo "Cleans docs."
	cd docs && $(PIPENV_CMD) run make clean

define COVERALL_CALL
import os
from subprocess import call

if __name__ == '__main__':
    if 'CIRCLECI' in os.environ:
        rc = call('coveralls')
        raise SystemExit(rc)
    print("Not in Circle-CI, skipping coveralls call")
endef
export COVERALL_CALL

# runs coveralls if CIRCLECI env var is set. Prevents the call to coveralls when running locally.
coveralls_call:
	$(PIPENV_CMD) run python -c "$$COVERALL_CALL"

#------------------------------------------------------------------------
# Document file
#------------------------------------------------------------------------

# COLORS
GREEN := $(shell tput -Txterm setaf 2)
RESET := $(shell tput -Txterm sgr0)

TARGET_MAX_CHAR_NUM=20

## shows help.
help:
	@echo "--------------------------------------------------------------------------------"
	@echo "Author  : ${GREEN}$(AUTHOR)${RESET}"
	@echo "Project : ${GREEN}$(NAME)${RESET}"
	@echo "Version : ${GREEN}$(VERSION)${RESET}"
	@echo "--------------------------------------------------------------------------------"
	@echo ""
	@echo "Usage:"
	@echo "  ${GREEN}make${RESET} <target>"
	@echo "Targets:"
	@awk '/^[a-zA-Z\-\_0-9]+:/ { \
		helpMessage = match(lastLine, /^## (.*)/); \
		if (helpMessage) { \
			helpCommand = substr($$1, 0, index($$1, ":")); \
			helpMessage = substr(lastLine, RSTART + 3, RLENGTH); \
			printf "  ${GREEN}%-$(TARGET_MAX_CHAR_NUM)s${RESET} %s\n", helpCommand, helpMessage; \
		} \
	} \
{ lastLine = $$0 }' $(MAKEFILE_LIST)
