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

By default, blocking Workload API calls wait without a deadline. To avoid
indefinitely blocking a calling thread when the Workload API is unresponsive,
set `default_timeout` on the client or pass a per-call `timeout` in seconds:

```python
with WorkloadApiClient(default_timeout=5.0) as client:
    jwt_svid = client.fetch_jwt_svid(audience={"test"})
    jwt_svid = client.fetch_jwt_svid(audience={"test"}, timeout=1.0)
```

Per-call timeouts override `default_timeout`. Deadline expiry is reported as
the SPIFFE-specific error for the call, such as `FetchJwtSvidError`. Timeouts do
not apply to long-lived streaming methods.

When a workload is entitled to more than one identity, the Workload API may
attach an operator-defined `hint` (for example `internal` or `external`) to each
SVID. The hint is exposed on `X509Svid` and `JwtSvid`, and is an empty string
when not set:

```python
with WorkloadApiClient() as client:
    svids = client.fetch_x509_svids()
    external = next((s for s in svids if s.hint == 'external'), None)
```

The hint is metadata that the local Workload API attaches to the workload's own
SVIDs. It is not part of the certificate or token, is not authenticated, and is
never sent to peers, so it must not be used to authorize a peer. SVIDs obtained by
validating a peer's token (`JwtSvid.parse_and_validate()`,
`WorkloadApiClient.validate_jwt_svid()`) always have an empty hint.

Handling a missing or unexpected hint is the workload's responsibility. Servers
must keep non-empty hints unique. If a response nevertheless contains more than
one SVID with the same hint, the client keeps only the first one, as the SPIFFE
Workload API specification recommends. The trust bundles of skipped X.509-SVIDs
are still added to the X.509 context. SVIDs without a hint are never dropped.

### X509Source

```python
from spiffe import X509Source

# Automatically manage X.509 SVIDs and CA bundles
with X509Source() as source:
    x509_svid = source.svid
    print(f'SPIFFE ID: {x509_svid.spiffe_id}')
```

When the workload receives more than one X.509-SVID, pass an `svid_picker` to
choose which one the source uses, for example by `hint`. The picker is called with
all SVIDs on every Workload API update, not only at startup, and the chosen SVID
is what the source (and `spiffe-tls`) serves.

If the picker raises, the source fails closed: it is closed permanently and does
not recover when a later update would match again. This applies to any update, so
renaming or removing the expected hint at runtime takes the source (and any TLS
context built on it) out of service until the process creates a new source. Raise
a descriptive error when no SVID matches:

```python
from spiffe import X509Source


def pick_internal(svids):
    for svid in svids:
        if svid.hint == 'internal':
            return svid
    raise ValueError("no X.509-SVID with hint 'internal'")


with X509Source(svid_picker=pick_internal) as source:
    x509_svid = source.get_x509_context().default_svid
    print(f'SPIFFE ID: {x509_svid.spiffe_id}, hint: {x509_svid.hint}')
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
