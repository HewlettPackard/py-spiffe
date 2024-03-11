#!/bin/bash

# Check if pyproject.toml is in the list of staged changes
if git diff --cached --name-only | grep -E 'pyproject.toml'; then
  echo "pyproject.toml changed. Running 'poetry lock'..."
  poetry lock
  git add poetry.lock
else
  echo "No dependency changes detected."
fi
