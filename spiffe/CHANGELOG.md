# Changelog

## [Unreleased]

### Changed
- Tightened `X509Svid` leaf SPIFFE ID validation to reject trust-domain root IDs in leaf certificates (a non-empty path is required).
- In `X509Svid.parse()`, `X509Svid.parse_raw()`, and `X509Svid.load()`, leaf certificate SPIFFE ID validation now occurs before private key parsing; when both the leaf SPIFFE ID and private key are invalid, `InvalidLeafCertificateError` now takes precedence over `ParsePrivateKeyError`.
- Accept mixed-case SPIFFE URI scheme and trust domain input during `SpiffeId`/`TrustDomain` parsing, while canonicalizing trust domains to lowercase output.
- Allow underscore (`_`) in trust-domain labels (for example `trust_domain_1.example.org`) to align trust-domain validation with SPIFFE ID spec section 2.1.
- Relax trust-domain validation to follow SPIFFE trust-domain character-set rules (`[a-z0-9._-]`), including non-DNS-shaped names such as `example..org`, `.example.org`, `example.org.`, `-example.org`, and `example-.org`.

## [0.2.6] – 2026-03-15

### Fixed
- Handle single-string `aud` claim in `JwtSvid` constructor per RFC 7519 §4.1.3 when there is only one audience (Fixes #404).
- Add atomic X.509 context snapshot getter in workload API for consistent reads during updates. (Fixes #399)

### Deprecated
- `X509Source.svid` and `X509Source.bundles` are deprecated; use the new snapshot getter API instead.

### Development
- Move shared dev dependencies to workspace root; replace per-package Makefiles with shared runner.


## [0.2.5] – 2026-03-07

### Fixed
- Raised protobuf runtime requirement to `>=6.31.1,<8` to prevent gencode/runtime mismatches with checked-in generated protobuf code (e.g. gencode 6.31.1 with runtime 5.x).


## [0.2.4] – 2026-02-24

### Fixed
- Hardened JWT and X.509 SVID validation and error handling (#375)

### Changed
- Refactored workload API source lifecycle and client behavior for improved robustness (#376)
- Privatized `proto` module internals for cleaner public API surface
- Added PEP 561 `py.typed` markers for downstream type checking (#372)
- Migrated build system from Poetry to uv
- Replaced black and flake8 with ruff for formatting and linting
- Updated dependencies:
  - cryptography to 46.0.4
  - grpcio to 1.78.0
  - protobuf to 6.33.5
  - pyjwt[crypto] to permit 2.11.x

### Development
- Enabled mypy strict mode across src and tests
- Added pyright type checking with `--verifytypes` validation
- Updated codegen for protobuf compilation

## [0.2.3] – 2026-01-17

### Fixed
- Fixed initialization timeout handling in `JwtSource` and `X509Source`, ensuring timeouts raise the correct error and watcher threads do not block process shutdown (#369)

### Changed
- Updated dependencies:
  - grpcio to 1.76.0
  - cryptography to 46.0.3
  - protobuf to 6.33.x
  - pyasn1 to 0.6.2

### Development
- Updated tooling:
  - pytest to 9.0.2
  - mypy to 1.19.1
  - mypy-protobuf to 5.0.0
  - black to 25.12.0
  - pre-commit to 4.3.0

## [0.2.2] - 2025-07-15

## Changed
- Fix #324: issue with single string audience (#325)
- Bump grpcio to 1.73.1 (#322)
- Bump cryptography to 45.0.5 (#323)

## [0.2.1] - 2025-06-11

### Changed
- Bumped `cryptography` dependency to `^45.0`.

## [0.2.0] - 2025-06-09

### Changed
- Dropped support for Python 3.9.
- Updated minimum required Python version to **3.10**.
- Bumped `cryptography` dependency from `^43.0` to `^44.0`.

### Notes
- `cryptography>=44.0` requires Python 3.10 or later.
- This release introduces a **breaking change** due to the updated Python compatibility and dependency requirements.
