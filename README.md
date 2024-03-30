# py-spiffe

[![CI](https://github.com/HewlettPackard/py-spiffe/actions/workflows/build.yaml/badge.svg?branch=main)](https://github.com/HewlettPackard/py-spiffe/actions/workflows/build.yaml?branch=main)

`py-spiffe` is a Python library designed to provide support for [SPIFFE](https://spiffe.io). The library is
structured into two main modules:

## Modules

### [spiffe](spiffe/README.md)

The `spiffe` module is the core of the `py-spiffe` library, implementing the SPIFFE specification. It provides
functionality for managing SPIFFE identities, including the Workload API client and automatic handling of X.509 and
JWT SVIDs. This module simplifies working with SPIFFE identities by automating SVID fetching and renewal.

### [spiffe-tls (Experimental)](spiffe-tls/README.md)

The `spiffe-tls` module is currently in experimental development and aims to provide Python applications with advanced
TLS utilities. Its primary goal is to streamline the integration of SPIFFE identities into TLS contexts, facilitating
not only mutual TLS configurations but also enhancing certificate validation processes.

## Installation

`spiffe` module:

```sh
pip install spiffe
```

`spiffe-tls` module:
```sh
pip install spiffe-tls
```

## Contributing

Contributions to both `spiffe` and the `spiffe-tls` modules are welcome! Please see
our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to the project.
