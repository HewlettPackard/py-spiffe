# `spiffe-tls` package (experimental)

## Overview

The `spiffe-tls` package, part of the `py-spiffe` library, is designed to simplify the creation of secure TLS
connections by leveraging SPIFFE IDs for authentication. Utilizing the capabilities
of [pyOpenSSL](https://pypi.org/project/pyOpenSSL/), this package offers
straightforward utilities for both TLS client and server configurations. Currently in its experimental phase,
`spiffe-tls`enables integration of [SPIFFE](https://spiffe.io)-based authentication, facilitating automatic management
of X.509 certificates and CA trusted bundles through an `X509Source` from the [spiffe](https://pypi.org/project/spiffe/)
package.

## Key Features

- TLS connections with SPIFFE ID validation.
- Mutual TLS (MTLS) support for authenticated client-server communication.
- Customizable server and client TLS configurations.

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
