# py-spiffe

[![CI](https://github.com/HewlettPackard/py-spiffe/actions/workflows/build.yaml/badge.svg?branch=main)](https://github.com/HewlettPackard/py-spiffe/actions/workflows/build.yaml?branch=main)

`py-spiffe` is a Python library designed to provide support for [SPIFFE](https://spiffe.io). The library is
structured into two main packages:

### [spiffe](spiffe/README.md)

[![PyPI spiffe](https://badge.fury.io/py/spiffe.svg)](https://pypi.org/project/spiffe/)

The `spiffe` package is the core of the `py-spiffe` library, implementing the SPIFFE specification. It provides
functionality for managing SPIFFE identities, including the Workload API client and automatic handling of X.509 and
JWT SVIDs. This package simplifies working with SPIFFE identities by automating SVID fetching and renewal.

### [spiffe-tls](spiffe-tls/README.md) (experimental)

[![PyPI spiffe-tls](https://badge.fury.io/py/spiffe-tls.svg)](https://pypi.org/project/spiffe-tls/)

The `spiffe-tls` package is currently in experimental development and aims to provide Python applications with advanced
TLS utilities. Its primary goal is to streamline the integration of SPIFFE identities into TLS contexts, facilitating
not only mutual TLS configurations but also enhancing certificate validation processes.

## Installation

You can install the `spiffe` and `spiffe-tls` packages directly from PyPI:

```bash
pip install spiffe
pip install spiffe-tls
```

## Contributing

Contributions to both `spiffe` and the `spiffe-tls` packages are welcome! Please see
our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to the project.
