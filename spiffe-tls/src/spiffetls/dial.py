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

import logging
import socket
from typing import Optional, Callable

from OpenSSL import SSL, crypto

from spiffe import X509Source
from spiffetls.context import create_ssl_context
from spiffetls.errors import TLSConnectionError
from spiffetls.mode import ClientTlsMode

logger = logging.getLogger(__name__)


def dial(
    address: str,
    x509_source: X509Source,
    tls_mode: ClientTlsMode = ClientTlsMode.TLS,
    authorize_fn: Optional[Callable[[crypto.X509], bool]] = None,
) -> SSL.Connection:
    """
    Establishes a secure TLS connection to a server at the specified address.

    This function creates a client-side connection using certificates and keys provided by the X509Source.
    It can optionally perform additional server certificate validations using the provided `authorize_fn`.

    Args:
        address (str): Target server address in 'host:port' format.
        tls_mode(ClientTlsMode, optional): Client-side TLS mode. Defaults to ClientTlsMode.TLS.
        x509_source (X509Source): Provides the client's X.509 certificates and keys.
        authorize_fn (Callable[[crypto.X509], bool], optional): A callback for additional server
        certificate validation. If not provided, standard certificate validation is performed.

    Returns:
        SSL.Connection: A secured connection to the server.

    Raises:
        Exception: If there's an error establishing the connection or configuring TLS context.
    """

    host, port = address.split(':')

    # Configures SSL context for the client to verify the server's certificate.
    # The client always attempts to verify the server's certificate to ensure a secure connection.
    verify_mode = SSL.VERIFY_PEER
    use_system_trusted_cas = True if tls_mode == ClientTlsMode.TLS_WEB else False

    ssl_context = create_ssl_context(
        SSL.TLS_CLIENT_METHOD,
        x509_source,
        authorize_fn,
        verify_mode,
        use_system_trusted_cas,
    )

    sock = socket.socket()
    conn = SSL.Connection(ssl_context, sock)

    try:
        conn.connect((host, int(port)))
        conn.do_handshake()
        return conn
    except SSL.Error as ssl_error:
        raise TLSConnectionError(
            "TLS connection failed", address=address, reason=str(ssl_error)
        ) from ssl_error
    except socket.error as sock_error:
        raise ConnectionError(f"Socket connection failed: {sock_error}") from sock_error
