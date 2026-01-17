# Changelog

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
