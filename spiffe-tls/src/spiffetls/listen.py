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

import socket
import logging
from typing import Callable, Optional

from OpenSSL import SSL, crypto

from spiffe import X509Source
from spiffetls.context import create_ssl_context
from spiffetls.errors import ListenError
from spiffetls.mode import ServerTlsMode

logger = logging.getLogger(__name__)


class ListenOptions:
    """
    Configuration options for creating a TLS listening socket with the listen function.

    Attributes:
        tls_mode (ServerTlsMode): Serveer-side TLS mode. Defaults to ServerTlsMode.TLS.
        authentication only, MTLS for mutual authentication, and MTLS_WEB for mutual authentication with system trusted CAs.
        authorize_fn (Callable[[crypto.X509], bool], optional): Optional callback function for additional client
        certificate verification.
        backlog (int): Maximum number of queued connections. Default is 5.
        socket_family (int): Socket family. Default is socket.AF_INET.
        socket_type (int): Socket type. Default is socket.SOCK_STREAM.

    This class allows for customization of the listening socket and SSL context behavior, including SSL mode, authorization function, and socket characteristics.
    """

    def __init__(
        self,
        tls_mode: ServerTlsMode = ServerTlsMode.MTLS,
        authorize_fn: Optional[Callable[[crypto.X509], bool]] = None,
        backlog: int = 5,
        socket_family: int = socket.AF_INET,
        socket_type: int = socket.SOCK_STREAM,
    ):
        self.tls_mode = tls_mode
        self.authorize_fn = authorize_fn
        self.backlog = backlog
        self.socket_family = socket_family
        self.socket_type = socket_type


def listen(
    address: str, x509_source: X509Source, options: Optional[ListenOptions] = None
) -> SSL.Connection:
    """
    Creates a TLS listening socket bound to the specified address.

    Args:
        address (str): The address to bind the server to, formatted as 'host:port'.
        x509_source (X509Source): Source of X.509 certificates and private key for TLS configuration.
        options (ListenOptions, optional): Optional configuration options for the server. Defaults to None.

    Returns:
        SSL.Connection: A configured SSL connection wrapped around a listening socket.

    This function sets up a server socket to listen for incoming TLS connections based on the provided X.509 source.
    """

    if options is None:
        options = ListenOptions()

    host, port = _parse_address(address)

    # For mTLS, require the client to present a certificate and fail if no certificate is presented.
    # For TLS, verify the peer's certificate if presented but do not require a client certificate.
    verify_mode = (
        SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT
        if options.tls_mode in (ServerTlsMode.MTLS, ServerTlsMode.MTLS_WEB)
        else SSL.VERIFY_PEER
    )
    use_system_trusted_cas = (
        True if options.tls_mode == ServerTlsMode.MTLS_WEB else False
    )

    ssl_context = create_ssl_context(
        SSL.TLS_SERVER_METHOD,
        x509_source,
        options.authorize_fn,
        verify_mode,
        use_system_trusted_cas,
    )

    sock = None
    try:
        sock = socket.socket(options.socket_family, options.socket_type)
        sock.bind((host, int(port)))
        sock.listen(options.backlog)
    except socket.error as err:
        if sock:
            sock.close()
        raise ListenError(host, port, err) from err

    ssl_connection = SSL.Connection(ssl_context, sock)
    ssl_connection.set_accept_state()

    return ssl_connection


def _parse_address(address):
    try:
        host, port_str = address.split(':')
        port = int(port_str)
        return host, port
    except ValueError:
        raise ValueError(
            f"Invalid address format or port number: '{address}'. Format should be 'host:port'."
        )
