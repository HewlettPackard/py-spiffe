#!/bin/bash
set -euo pipefail

# Check if pyproject.toml is in the list of staged changes
if git diff --cached --name-only | grep -Eq '(^|/)pyproject.toml$'; then
  echo "pyproject.toml changed. Running 'uv lock' at repository root..."
  uv lock
  git add uv.lock
else
  echo "No dependency changes detected."
fi
