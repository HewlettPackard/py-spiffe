# Changelog

## [0.3.1] – 2026-03-15

### Development
- Enable pyright strict mode; minor typing and code cleanup in `spiffetls.util`.
- Move shared dev dependencies to workspace root; replace per-package Makefiles with shared runner.


## [0.3.0] – 2026-02-24

### Added
- Added `SpiffeSSLContext` for standard library `ssl.SSLContext` compatibility, enabling seamless integration with httpx, requests, urllib3, and other HTTP libraries (#364)

### Changed
- Added PEP 561 `py.typed` markers for downstream type checking (#372)
- Migrated build system from Poetry to uv
- Replaced black and flake8 with ruff for formatting and linting

### Development
- Enabled mypy strict mode in tests
- Added pyright type checking with `--verifytypes` validation
- Improved test reliability by letting OS pick listening ports

## [0.2.2] – 2026-01-17

### Changed
- Updated dependency on `spiffe` to v0.2.3.

### Dependencies
- Bumped pyOpenSSL to 25.3.0.


## [0.2.1] - 2025-06-11

### Changed
- Bumped `spiffe` dependency to `0.2.1`

## [0.2.0] - 2025-06-09

### Changed
- Dropped support for Python 3.9.
- Updated minimum required Python version to **3.10**.
- Bumped `cryptography` dependency from `^43.0` to `^44.0` in `spiffe` package.

### Notes
- `cryptography>=44.0` requires Python 3.10 or later.
- This release introduces a **breaking change** due to the updated Python compatibility and dependency requirements.
