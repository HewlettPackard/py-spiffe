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

import queue
import random
import threading

import pytest

import spiffetls.tlsconfig.authorize
from spiffetls import listen, dial, ListenOptions
from spiffe import X509Source, SpiffeId
from spiffetls.errors import TLSConnectionError
from spiffetls.mode import ServerTlsMode


@pytest.fixture
def setup_server():
    server_address = ('localhost', random.randint(50000, 60000))
    x509_source = X509Source(timeout_in_seconds=30)
    server_socket = None
    exception_queue = queue.Queue()

    def _setup_server(options):
        nonlocal server_socket
        server_socket = listen(
            f"{server_address[0]}:{server_address[1]}", x509_source, options
        )
        ready_event = threading.Event()

        def server_thread_func():
            try:
                echo_server_handler(server_socket, ready_event)
            except Exception as e:
                exception_queue.put(e)

        server_thread = threading.Thread(target=server_thread_func, daemon=True)
        server_thread.start()
        ready_event.wait()

        # Check if there was an exception in the server thread before proceeding
        if not exception_queue.empty():
            e = exception_queue.get()
            pytest.fail(f"Server thread failed with exception: {e}")

        return server_socket, server_address, x509_source

    yield _setup_server

    if server_socket:
        server_socket.close()
    x509_source.close()


def test_successful_mtls_connection_with_server_authorization(setup_server):
    x509_source = X509Source(timeout_in_seconds=30)
    spiffe_id = x509_source.svid.spiffe_id

    options = ListenOptions(
        tls_mode=ServerTlsMode.MTLS,
        authorize_fn=spiffetls.tlsconfig.authorize.authorize_id(spiffe_id),
    )

    _, server_address, _ = setup_server(options)

    client_connection = dial(f"{server_address[0]}:{server_address[1]}", x509_source)
    test_message = b"Hello, SPIFFE!"
    client_connection.sendall(test_message)

    received_message = client_connection.recv(1024)
    assert received_message == test_message

    client_connection.close()


def test_successful_tls_connection_with_client_authorization(setup_server):
    x509_source = X509Source(timeout_in_seconds=30)
    spiffe_id = x509_source.svid.spiffe_id

    options = ListenOptions(tls_mode=ServerTlsMode.TLS)

    _, server_address, _ = setup_server(options)

    client_connection = dial(
        f"{server_address[0]}:{server_address[1]}",
        x509_source,
        authorize_fn=spiffetls.tlsconfig.authorize.authorize_id(spiffe_id),
    )
    test_message = b"Hello, SPIFFE!"
    client_connection.sendall(test_message)

    received_message = client_connection.recv(1024)
    assert received_message == test_message

    client_connection.close()


def test_mtls_connection_fails_with_unauthorized_client(setup_server):
    x509_source = X509Source(timeout_in_seconds=30)
    trust_domain = x509_source.svid.spiffe_id.trust_domain.as_spiffe_id()

    # Set the server to authorize only a specific SPIFFE ID that the client does not have
    server_options = ListenOptions(
        tls_mode=ServerTlsMode.MTLS,
        authorize_fn=spiffetls.tlsconfig.authorize.authorize_id(
            SpiffeId(f"{trust_domain}/other")
        ),
    )

    _, server_address, _ = setup_server(server_options)

    # Attempt to communicate with the server, expecting failure
    with pytest.raises(Exception) as exc_info:
        client_connection = dial(
            f"{server_address[0]}:{server_address[1]}", x509_source
        )
        try:
            test_message = b"Hello, SPIFFE!"
            client_connection.sendall(test_message)
            client_connection.recv(1024)
        finally:
            client_connection.close()

    assert "tlsv1 alert internal error" in str(exc_info.value)


def test_tls_connection_fails_due_to_client_certificate_verification_failure(
    setup_server,
):
    x509_source = X509Source(timeout_in_seconds=30)
    trust_domain = x509_source.svid.spiffe_id.trust_domain.as_spiffe_id()

    options = ListenOptions(tls_mode=ServerTlsMode.MTLS)

    _, server_address, _ = setup_server(options)

    with pytest.raises(TLSConnectionError) as exc_info:
        dial(
            f"{server_address[0]}:{server_address[1]}",
            x509_source,
            authorize_fn=spiffetls.tlsconfig.authorize.authorize_id(
                SpiffeId(f"{trust_domain}/other")
            ),
        )

    assert "TLS connection failed" in str(exc_info.value)
    assert 'reason' in exc_info.value.context
    error_reason = exc_info.value.context['reason']
    assert "certificate verify failed" in error_reason


def echo_server_handler(server_socket, ready_event):
    ready_event.set()
    while True:
        conn, _ = server_socket.accept()
        try:
            data = conn.recv(1024)
            if data:
                conn.sendall(data)
        finally:
            conn.close()
