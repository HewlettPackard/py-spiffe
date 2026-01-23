# py-spiffe

[![CI](https://github.com/HewlettPackard/py-spiffe/actions/workflows/build.yaml/badge.svg?branch=main)](https://github.com/HewlettPackard/py-spiffe/actions/workflows/build.yaml?branch=main)

`py-spiffe` is a Python library designed to provide support for [SPIFFE](https://spiffe.io). The library is
structured into two main packages:

### [spiffe](spiffe/README.md)

[![PyPI spiffe](https://badge.fury.io/py/spiffe.svg)](https://pypi.org/project/spiffe/)

The `spiffe` package is the core of the `py-spiffe` library. It provides
functionality for managing SPIFFE identities, including a Workload API client and automatic handling of X.509 and
JWT SVIDs. This package simplifies working with SPIFFE identities by automating SVID fetching and renewal.

### [spiffe-tls](spiffe-tls/README.md) (experimental)

[![PyPI spiffe-tls](https://badge.fury.io/py/spiffe-tls.svg)](https://pypi.org/project/spiffe-tls/)

The `spiffe-tls` package, still in its experimental stages, is designed to enhance Python applications with TLS
utilities that simplify the integration of SPIFFE authentication. Its primary objective is to ease the process of
incorporating SPIFFE identities into TLS contexts. To achieve this, it offers a set of utility functions that allow for
the creation of TLS listeners and connections, leveraging the [pyOpenSSL](https://pypi.org/project/pyOpenSSL/) library.

## Installation

You can install the `spiffe` and `spiffe-tls` packages directly from PyPI:

```bash
pip install spiffe
pip install spiffe-tls
```

## Examples

Manual smoke test examples are available in the `examples/` directory:

- **[mtls-smoke](examples/mtls-smoke/)**: mTLS smoke test using `spiffetls.dial()` and `spiffetls.listen()`
- **[httpx-stdlib-mtls](examples/httpx-stdlib-mtls/)**: `SpiffeSSLContext` integration with `httpx` and stdlib TLS

These examples are intended for manual testing only and not for production use.

## Contributing

Contributions to both `spiffe` and the `spiffe-tls` packages are welcome! Please see
our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to the project.
