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

from contextlib import contextmanager
import queue
import ssl
import threading
import urllib.request
import urllib.error
from collections.abc import Iterator
from typing import Tuple

import pytest
from OpenSSL import SSL

import spiffetls.tlsconfig.authorize
from spiffetls import listen, ListenOptions, SpiffeSSLContext
from spiffe import X509Source, SpiffeId
from spiffetls.mode import ServerTlsMode


@contextmanager
def setup_http_server(
    options: ListenOptions,
) -> Iterator[Tuple[SSL.Connection, Tuple[str, int], X509Source]]:
    server_host = "localhost"
    x509_source = X509Source(timeout_in_seconds=30)
    exception_queue: queue.Queue[Exception] = queue.Queue()

    server_socket = listen(f"{server_host}:0", x509_source, options)
    server_address = (server_host, int(server_socket.getsockname()[1]))
    ready_event = threading.Event()

    def server_thread_func() -> None:
        try:
            http_server_handler(server_socket, ready_event)
        except Exception as e:
            exception_queue.put(e)

    server_thread = threading.Thread(target=server_thread_func, daemon=True)
    server_thread.start()
    ready_event.wait()

    # Check if there was an exception in the server thread before proceeding
    if not exception_queue.empty():
        e = exception_queue.get()
        pytest.fail(f"Server thread failed with exception: {e}")

    yield server_socket, server_address, x509_source

    server_socket.close()
    x509_source.close()


def http_server_handler(server_socket: SSL.Connection, ready_event: threading.Event) -> None:
    """Simple HTTP server that responds to GET requests."""
    ready_event.set()
    while True:
        conn, _ = server_socket.accept()
        try:
            # Read the HTTP request
            data = conn.recv(4096)
            if data:
                # Send a simple HTTP response
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: 24\r\n"
                    b"Connection: close\r\n"
                    b"\r\n"
                    b"Hello from SPIFFE server"
                )
                conn.sendall(response)
        finally:
            conn.close()


def test_stdlib_context_successful_mtls_connection() -> None:
    """Test SpiffeSSLContext with urllib.request against a server requiring mTLS."""
    with X509Source(timeout_in_seconds=30) as x509_source:
        spiffe_id = x509_source.svid.spiffe_id
        options = ListenOptions(
            tls_mode=ServerTlsMode.MTLS,
            authorize_fn=spiffetls.tlsconfig.authorize.authorize_id(spiffe_id),
        )

        with setup_http_server(options) as (_, server_address, _):
            # Create SpiffeSSLContext and use it with urllib.request
            ssl_context = SpiffeSSLContext(x509_source)
            assert isinstance(ssl_context, ssl.SSLContext)
            url = f"https://{server_address[0]}:{server_address[1]}/"

            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ssl_context)
            )

            response = opener.open(url, timeout=5)
            content = response.read()

            assert content == b'Hello from SPIFFE server'
            assert response.status == 200


def test_stdlib_context_mtls_connection_fails_with_unauthorized_client() -> None:
    """Test SpiffeSSLContext rejects connections when client is not authorized."""
    with X509Source(timeout_in_seconds=30) as x509_source:
        trust_domain = x509_source.svid.spiffe_id.trust_domain.as_spiffe_id()

        # Set the server to authorize only a specific SPIFFE ID that the client does not have
        server_options = ListenOptions(
            tls_mode=ServerTlsMode.MTLS,
            authorize_fn=spiffetls.tlsconfig.authorize.authorize_id(
                SpiffeId(f"{trust_domain}/unauthorized-service")
            ),
        )

        with setup_http_server(server_options) as (_, server_address, _):
            # Create SpiffeSSLContext and attempt to connect
            ssl_context = SpiffeSSLContext(x509_source)
            assert isinstance(ssl_context, ssl.SSLContext)
            url = f"https://{server_address[0]}:{server_address[1]}/"

            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ssl_context)
            )

            # Attempt to connect, expecting failure due to authorization
            with pytest.raises((urllib.error.URLError, ssl.SSLError)) as exc_info:
                opener.open(url, timeout=5)

            # The connection should fail with an SSL/TLS error
            error_str = str(exc_info.value)
            assert (
                "tlsv1 alert" in error_str.lower()
                or "SSL" in error_str
                or "certificate verify failed" in error_str
            )
