# py-spiffe

[![CI](https://github.com/HewlettPackard/py-spiffe/actions/workflows/build.yaml/badge.svg?branch=main)](https://github.com/HewlettPackard/py-spiffe/actions/workflows/build.yaml?branch=main)

`py-spiffe` is a Python library designed to provide support for [SPIFFE](https://spiffe.io). The library is
structured into two main modules:

## Modules

### [spiffe](spiffe/README.md)

The `spiffe` module is the core of the `py-spiffe` library, implementing the SPIFFE specification. It provides
functionality for managing SPIFFE identities, including the Workload API client and automatic handling of X.509 and
JWT SVIDs. This module simplifies working with SPIFFE identities by automating SVID fetching and renewal.

### [spiffe-tls (In Development)](spiffe-tls/README.md)

The `spiffe-tls` module, currently in development, will offer TLS utilities for Python applications. It aims to simplify
the use of SPIFFE identities in TLS contexts, including mutual TLS support and certificate validation. This module will
enhance secure communication by leveraging SPIFFE identities for authentication.

## Contributing

Contributions to both `spiffe` and the `spiffe-tls` modules are welcome! Please see
our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to the project.
