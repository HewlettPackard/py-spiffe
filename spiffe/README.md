# `spiffe` module

## Overview

The `spiffe` module, part of the `py-spiffe` library, provides Python developers with essential tools for interacting
with the [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md). It
streamlines the management and validation of SPIFFE identities, including support
for both [X509-SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md)
and [JWT-SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md),
and [SPIFFE Bundles](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#3-spiffe-bundles).

## Usage

Below are examples demonstrating the core functionalities of the `spiffe` module.

Prerequisites:

1. Running [SPIRE](https://spiffe.io/spire/) or another SPIFFE Workload API implementation.
2. `SPIFFE_ENDPOINT_SOCKET` environment variable set to the address of the Workload
   API (e.g. `unix:/tmp/spire-agent/public/api.sock`). Alternatively the socket address can be
   provided programmatically.

### WorkloadApiClient

Facilitates fetching X.509 and JWT SVIDs and Bundles, and validating JWT tokens communicating with the SPIFFE Workload
API.

```python
from spiffe import WorkloadApiClient

# Interacting with the Workload API to fetch SVIDs
with WorkloadApiClient() as client:
    # Fetch a X.509 SVID
    x509_svid = client.fetch_x509_svid()
    print(f'SPIFFE ID: {x509_svid.spiffe_id}')
    print(f'Certificate chain: {x509_svid.cert_chain}')

    # Fetch a JWT SVID
    jwt_svid = client.fetch_jwt_svid(audience={'test'})

    # Validate JWT SVID
    validated_svid = client.validate_jwt_svid(jwt_svid.token, audience='test')
    print(f'Validated JWT SVID for audience `test`: {jwt_svid.spiffe_id}')

    # Fetch bundles of public keys
    x509_bundles = client.fetch_x509_bundles()
    jwt_bundles = client.fetch_jwt_bundles
```

### X509Source

Automatically fetches X.509 SVIDs and Bundles from the SPIFFE Workload API and continuously receives updates. This
ensures your application always uses valid certificates without manual intervention.

```python
from spiffe import X509Source
from spiffe import TrustDomain

with X509Source() as source:
    # Access the fetched X.509 SVID
    x509_svid = source.svid
    print(f'SPIFFE ID: {x509_svid.spiffe_id}')
    print(f'Certificate chain: {[cert for cert in x509_svid.cert_chain]}')

    # Access the fetched X.509 Bundle for a specific Trust Domain
    x509_bundle = source.get_bundle_for_trust_domain(TrustDomain('example.org'))
    print(f'X.509 Bundle for example.org: {x509_bundle}')
```

### JwtSource

Facilitates the management and validation of JWT SVIDs and Bundles. It automatically fetches JWT SVIDs from the SPIFFE
Workload API and validates them against the JWT bundles for their trust domains.

```python
from spiffe import JwtSource
from spiffe import TrustDomain
from spiffe import JwtSvid

with JwtSource() as source:
    jwt_svid = source.fetch_svid(audience={'test'})
    print(f'SPIFFE ID: {jwt_svid.spiffe_id}')

    jwt_bundle = source.get_bundle_for_trust_domain(TrustDomain('example.org'))
    validated_svid = JwtSvid.parse_and_validate(jwt_svid.token, jwt_bundle, audience={'test'})
```

