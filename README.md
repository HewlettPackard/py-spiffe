# py-spiffe Library

[![Build](https://github.com/HewlettPackard/py-spiffe/actions/workflows/build.yaml/badge.svg?branch=master)](https://github.com/HewlettPackard/py-spiffe/actions/workflows/build.yaml?branch=master)
[![Coverage](https://coveralls.io/repos/github/HewlettPackard/py-spiffe/badge.svg?branch=master)](https://coveralls.io/github/HewlettPackard/py-spiffe?branch=master)

## Overview

The py-spiffe library is a Python solution designed to integrate with the SPIFFE (Secure
Production Identity Framework For Everyone) ecosystem. By enabling the fetching of SPIFFE Verifiable Identity
Documents (SVIDs) and trust bundles, this library offers a rich set of classes and types that encapsulate SPIFFE
standards.

## Status of the Library

This SPIFFE library extends beyond providing a Workload API client for fetching X.509 and JWT SVIDs and trust bundles;
it also introduces classes and types that closely align with SPIFFE standards. These components are instrumental in
developing systems that adhere to and take full advantage of SPIFFE specifications for secure and flexible
cross-platform authentication.

**Important:** The current release does not directly support establishing TLS connections using SPIFFE certificates, a
feature crucial for certain applications requiring secure communication channels. 

## Contributing

* See [CONTRIBUTING](https://github.com/HewlettPackard/py-spiffe/blob/master/CONTRIBUTING.md) to get started.
* Use [GitHub Issues](https://github.com/HewlettPackard/py-spiffe/issues) to request features or file bugs.
