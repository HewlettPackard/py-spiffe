# py-spiffe

[![CI](https://github.com/HewlettPackard/py-spiffe/actions/workflows/build.yaml/badge.svg?branch=main)](https://github.com/HewlettPackard/py-spiffe/actions/workflows/build.yaml?branch=main)

`py-spiffe` is a Python library designed to provide support for [SPIFFE](https://spiffe.io). The library is
structured into two main modules:

## Modules

### [pyspiffe](pyspiffe/README.md)

`pyspiffe` is the foundational module of the `py-spiffe` library, offering key functionalities around SPIFFE
specification, including the Workload API client implementation, and handling of SVIDs (SPIFFE Verifiable Identity
Documents). 

### [pyspiffe-tls (In Development)](pyspiffe-tls/README.md)

The `pyspiffe-tls` module, currently in development, is planned to provide TLS utilities that facilitate the easy
integration of SPIFFE identities into the TLS workflows of Python applications. This module will offer features such as
mutual TLS (mTLS) support, certificate validation, and automatic SVID fetching and renewal, aimed at simplifying secure
service-to-service communication using SPIFFE identities.

## Contributing

Contributions to both `pyspiffe` and the `pyspiffe-tls` modules are welcome! Please see
our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to the project.
