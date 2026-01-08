# `spiffe-tls` package (experimental)

## Overview

The `spiffe-tls` package, part of the [py-spiffe library](https://github.com/HewlettPackard/py-spiffe), streamlines the
establishment of secure TLS connections using [SPIFFE](https://spiffe.io) certificates. Powered
by  [pyOpenSSL](https://pypi.org/project/pyOpenSSL/), it provides straightforward utilities for configuring TLS clients
and servers. Currently experimental, `spiffe-tls` facilitates the seamless integration of SPIFFE for the automatic
management of X.509 certificates and CA trust bundles via `X509Source` from
the [spiffe](https://pypi.org/project/spiffe/) package.

## Key Features

- TLS connections with SPIFFE ID validation.
- Mutual TLS (MTLS) support for authenticated client-server communication.
- Customizable server and client TLS configurations.
- Standard library-compatible SSL context with automatic certificate refresh.

## Quick Start

### Server Setup

```python
# Create a TLS server with SPIFFE-based MTLS
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

```python
# Establish a secure connection to a TLS server
from spiffetls import dial
from spiffe import SpiffeId, X509Source
from spiffetls.tlsconfig.authorize import authorize_id

x509_source = X509Source()

conn = dial(
    "localhost:8443",
    x509_source,
    authorize_fn=authorize_id(SpiffeId("spiffe://example.org/server")),
)
```

### Using with Standard HTTP Libraries

For integration with standard Python HTTP libraries (like `requests`, `httpx`, `urllib3`), use `SpiffeSSLContext`:

```python
# Use SPIFFE authentication with httpx
from spiffetls import SpiffeSSLContext
from spiffe import X509Source
import httpx

x509_source = X509Source()

# Create an SSL context that automatically refreshes certificates
ssl_context = SpiffeSSLContext(x509_source, use_system_trusted_cas=True)

# Use with httpx
client = httpx.Client(verify=ssl_context)
response = client.get("https://api.example.org/data")
```

The `SpiffeSSLContext` provides a standard library-compatible interface that automatically refreshes X.509 SVIDs as they rotate, without requiring manual updates to the SSL context. This is particularly useful for long-running applications.

### Authorization Functions

The package supports custom authorization functions for additional certificate validation:

- `authorize_any()`: Accepts any SPIFFE ID.
- `authorize_id()`: Validates a specific SPIFFE ID.
- `authorize_one_of()`: Allows any ID from a set of allowed SPIFFE IDs.
- `authorize_member_of()`: Permits any ID from a specific trust domain.

## Contributing

We welcome contributions to the `spiffe-tls` package! Please see
our [contribution guidelines](https://github.com/HewlettPackard/py-spiffe/blob/main/CONTRIBUTING.md) for more
details. For feedback and issues, please submit them through
the [GitHub issue tracker](https://github.com/HewlettPackard/py-spiffe/issues).
