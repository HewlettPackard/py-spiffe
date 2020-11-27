.DEFAULT_GOAL := help

.PHONY: build test docs

PYTHON=3.6
PIPENV_CMD=pipenv
ROOT_DIR=$(PWD)

NAME = py-spiffe
VERSION = 0.0.1

## Creates the distributable packages
build:
	$(PIPENV_CMD) run python setup.py sdist bdist_wheel

## Creates a new virtual environment if it is not already created.
env:
	$(PIPENV_CMD) --venv || \
	(echo "Creating virtual environment .venv"; \
	PIPENV_VENV_IN_PROJECT=1 $(PIPENV_CMD) install --python $(PYTHON);)


## Removes the virtual environment if it exist.
rm_env:
	$(PIPENV_CMD) --rm


## Installs dev requirements.
dev: env
	$(PIPENV_CMD) install --dev && \
	$(PIPENV_CMD) run pre-commit install


## Runs unit tests.
test:
	@echo "Running unit tests."
	$(PIPENV_CMD) run tox


## Generates docs.
docs:
	@echo "Generates docs."
	cd docs && $(PIPENV_CMD) run make html

#------------------------------------------------------------------------
# Document file
#------------------------------------------------------------------------

# COLORS
GREEN := $(shell tput -Txterm setaf 2)
RESET := $(shell tput -Txterm sgr0)

TARGET_MAX_CHAR_NUM=20
Author=Spiffe.io

## shows help.
help:
	@echo "--------------------------------------------------------------------------------"
	@echo "Author  : ${GREEN}$(Author)${RESET}"
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
