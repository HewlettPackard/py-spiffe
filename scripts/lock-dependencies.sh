#!/bin/bash

modules=("spiffe" "spiffe-tls")

# Check if pyproject.toml is in the list of staged changes
if git diff --cached --name-only | grep -q 'pyproject.toml'; then
  echo "pyproject.toml changed. Running 'poetry lock'..."

  for module in "${modules[@]}"; do
    if [[ -d "$module" ]]; then
      echo "Locking dependencies for $module..."
      (cd "$module" && poetry lock && git add poetry.lock) || {
        echo "Failed to lock dependencies for $module"
        exit 1
      }
    else
      echo "Directory $module does not exist. Skipping..."
    fi
  done
else
  echo "No dependency changes detected."
fi
