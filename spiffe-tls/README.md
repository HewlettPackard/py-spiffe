# `spiffe-tls` Module

This `py-spiffe` module provides TLS utilities that facilitate creating secure TLS connections leveraging SPIFFE IDs for
authentication. It wraps [pyOpenSSL](https://pypi.org/project/pyOpenSSL/), offering easy-to-use functions for setting up
TLS clients and servers with SPIFFE-based authentication using `X509Source` to manage and automatically update X.509
certificates and CA trusted bundles.

## Key Features

- Establish TLS connections with SPIFFE ID validation.
- Support for Mutual TLS (MTLS) and TLS with server authorization.
- Extensible options for server and client configurations.

## Quick Start

### Server Setup

Use the `listen()` function to create a TLS server socket bound to a specified address, configured according to SPIFFE
X.509 SVIDs.

```python
from spiffetls import listen, ListenOptions
from spiffe import SpiffeId, X509Source
from spiffetls.mode import ServerTlsMode
from spiffetls.tlsconfig.authorize import authorize_id

x509_source = X509Source()
options = ListenOptions(
    tls_mode=ServerTlsMode.MTLS,
    authorize_fn=authorize_id(SpiffeId("spiffe://example.org/client-service")),
)

listener = listen("localhost:8443", x509_source, options)
```

### Client Connection

Use the `dial()` function to establish a secure client connection to a TLS server.

```python
from spiffetls import dial
from spiffe import SpiffeId, X509Source
from spiffetls.tlsconfig.authorize import authorize_id

x509_source = X509Source()

conn = dial(
    "localhost:8443",
    x509_source,
    authorize_fn=authorize_id(SpiffeId("spiffe://example.org/client-service")),
)
```

### Authorization Functions

The module supports custom authorization functions for additional certificate validation:

- `authorize_any()`: Authorizes any valid SPIFFE ID.
- `authorize_id(expected_spiffe_id)`: Authorizes a specific SPIFFE ID.
- `authorize_one_of(allowed_ids)`: Authorizes any SPIFFE ID in a given set.
- `authorize_member_of(allowed_trust_domain)`: Authorizes any SPIFFE ID within a specific trust domain.