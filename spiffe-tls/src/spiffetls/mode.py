"""
(C) Copyright 2021 Hewlett Packard Enterprise Development LP

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

from enum import Enum, auto


class ServerTlsMode(Enum):
    """
    Represents the TLS modes that can be used for setting up TLS connections on the Server.

    Modes:
        TLS: The server doesn't require the client to present a TLS certificate. Use this mode for traditional TLS
             where client authentication is not necessary. Suitable for public-facing services where client identity
             verification is not required.

        MTLS: The server requires client authentication using certificates provided by the SPIFFE Workload API. Use this
              mode for mutual TLS (mTLS) where both server and client identities must be verified. Ideal for secure,
              internal communication between services in a SPIFFE-enabled environment.

        MTLS_WEB: Similar to MTLS, but the server also trusts certificates from the system's trust store. This mode
                  allows for mutual TLS authentication with clients that may use well-known CA certificates. It's useful
                  when you need to authenticate SPIFFE identities and also support clients with traditional web PKI
                  certificates.
    """

    TLS = auto()
    MTLS = auto()
    MTLS_WEB = auto()


class ClientTlsMode(Enum):
    """
    Represents the TLS modes that can be used for setting up TLS connections on the Client.

    Modes:
        TLS: The server is authenticated using a certificate provided by the SPIFFE Workload API. This mode ensures that
             the client can securely communicate with a server that presents a SPIFFE identity.

        TLS_WEB: The server is authenticated using certificates provided by the SPIFFE Workload API and also trusts
                 certificates from the system's trust store. This mode supports server authentication via both
                 SPIFFE IDs and traditional web PKI. It's suitable for clients that communicate with both SPIFFE-enabled
                 services and standard web services.
    """

    TLS = auto()
    TLS_WEB = auto()
