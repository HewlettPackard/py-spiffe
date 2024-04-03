# `spiffe` package

## Overview

The `spiffe` package, part of the [py-spiffe library](https://github.com/HewlettPackard/py-spiffe),
provides [SPIFFE](https://spiffe.io) support and essential
tools for interacting with
the [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md). It simplifies
the management and validation of SPIFFE identities,
supporting [X509-SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md), [JWT-SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md),
and X.509 CA and JWKS Bundles.

# Features

- Automatic Management of SPIFFE Identities: Streamlines fetching, renewing, and validation of X.509 and JWT SVIDs.
- Seamless Integration with SPIFFE Workload API: Facilitates communication with [SPIRE](https://github.com/spiffe/spire)
  or other SPIFFE Workload API compliant systems.
- Continuous Update Handling: Automatically receives and applies updates for SVIDs and bundles, ensuring your
  application always uses valid certificates.

## Prerequisites

- A running instance of [SPIRE](https://github.com/spiffe/spire) or another SPIFFE Workload API implementation.
- The `SPIFFE_ENDPOINT_SOCKET` environment variable set to the address of the Workload API (e.g., `unix:
  /tmp/spire-agent/public/api.sock`), or provided programmatically.

## Usage

Below are examples demonstrating the core functionalities of the `spiffe` package.

### WorkloadApiClient

```python
from spiffe import WorkloadApiClient

# Fetch X.509 and JWT SVIDs
with WorkloadApiClient() as client:
    x509_svid = client.fetch_x509_svid()
    print(f'SPIFFE ID: {x509_svid.spiffe_id}')

    jwt_svid = client.fetch_jwt_svid(audience={"test"})
    print(f'SPIFFE ID: {jwt_svid.spiffe_id}')
```

### X509Source

```python
from spiffe import X509Source

# Automatically manage X.509 SVIDs and CA bundles
with X509Source() as source:
    x509_svid = source.svid
    print(f'SPIFFE ID: {x509_svid.spiffe_id}')
```

### JwtSource

```python
from spiffe import JwtSource

# Manage and validate JWT SVIDs and JWKS bundles
with JwtSource() as source:
    jwt_svid = source.fetch_svid(audience={'test'})
    print(f'SPIFFE ID: {jwt_svid.spiffe_id}')
    print(f'Token: {jwt_svid.token}')
```

## Contributing

We welcome contributions to the `spiffe` package! Please see
our [contribution guidelines](https://github.com/HewlettPackard/py-spiffe/blob/main/CONTRIBUTING.md) for more
details. For feedback and issues, please submit them through
the [GitHub issue tracker](https://github.com/HewlettPackard/py-spiffe/issues).
