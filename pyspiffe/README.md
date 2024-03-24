# pyspiffe

## Overview

`pyspiffe` is a Python library designed for interacting with the SPIFFE Workload API. It offers robust mechanisms
for managing and validating SPIFFE IDs and SVIDs, both X.509 and JWT SPIFFE Verifiable Identity Documents (SVIDs),
ensuring secure and scalable handling of identity documents within your applications.

## Usage

Below are concise examples demonstrating how to leverage the core functionalities provided by `pyspiffe`.

### WorkloadApiClient

Facilitates fetching X.509 and JWT SVIDs from the SPIFFE Workload API.

```python
from pyspiffe import WorkloadApiClient

# Interacting with the Workload API to fetch X.509 SVID
with WorkloadApiClient() as client:
    x509_svid = client.fetch_x509_svid()
    print(f'SPIFFE ID: {x509_svid.spiffe_id}')
    print(f'Certificate chain: {x509_svid.cert_chain}')

    jwt_svid = client.fetch_jwt_svid(audience={'test'})

    # Validate JWT SVID
    validated_svid = client.validate_jwt_svid(jwt_svid.token, audience='test')
    print(f'Validated JWT SVID for audience `test`: {jwt_svid.spiffe_id}')
```

### X509Source

Automatically fetches and updates X.509 SVIDs from the Workload API.

```python
from pyspiffe import X509Source
from pyspiffe import TrustDomain

# Automatically manage and update X.509 SVIDs
with X509Source() as source:
    x509_svid = source.svid
    bundle = source.get_bundle_for_trust_domain(TrustDomain('example.org'))
    print(f'SPIFFE ID: {x509_svid.spiffe_id}')
    print(f'Trust domain bundle: {bundle}')
```

### JwtSource

Fetches and validates JWT SVIDs, facilitating secure service-to-service authentication.

```python
from pyspiffe import JwtSource
from pyspiffe import TrustDomain
from pyspiffe import JwtSvid

# Fetch and validate JWT SVIDs for secure authentication
with JwtSource() as source:
    jwt_svid = source.fetch_svid(audience={'test'})
    print(f'SPIFFE ID: {jwt_svid.spiffe_id}')

    jwt_bundle = source.get_bundle_for_trust_domain(TrustDomain('example.org'))
    validated_svid = JwtSvid.parse_and_validate(jwt_svid.token, jwt_bundle, audience={'test'})
    print(f'Validated SPIFFE ID: {validated_svid.spiffe_id}')
```
