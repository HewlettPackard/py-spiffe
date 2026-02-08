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

import ssl
from typing import Tuple
from unittest.mock import PropertyMock, MagicMock, patch

import pytest
from OpenSSL import SSL
from cryptography.hazmat.primitives import serialization

from spiffe import X509Source, X509Svid, TrustDomain, X509Bundle, X509BundleSet
from spiffetls import SpiffeSSLContext
from testutils.certs import TEST_BUNDLE_CERTS_DIR
from testutils.certs import TEST_CERTS_DIR


@pytest.fixture
def source_mocks() -> Tuple[MagicMock, PropertyMock, PropertyMock]:
    """Create mock X509Source with test certificates."""
    der_type = serialization.Encoding.DER
    chain_path = TEST_CERTS_DIR / '1-chain.der'
    key_path = TEST_CERTS_DIR / '1-key.der'
    x509_svid = X509Svid.load(str(chain_path), str(key_path), der_type)

    bundle_1 = X509Bundle.load(
        TrustDomain('domain.test'), TEST_BUNDLE_CERTS_DIR / 'certs.der', der_type
    )
    bundle_2 = X509Bundle.load(
        TrustDomain('example.org'),
        TEST_BUNDLE_CERTS_DIR / 'federated_bundle.der',
        der_type,
    )
    x509_bundle_set = X509BundleSet.of([bundle_1, bundle_2])

    x509_source_mock = MagicMock(spec=X509Source)
    mock_svid = PropertyMock(return_value=x509_svid)
    mock_bundles = PropertyMock(return_value=x509_bundle_set.bundles)

    type(x509_source_mock).svid = mock_svid
    type(x509_source_mock).bundles = mock_bundles

    return x509_source_mock, mock_svid, mock_bundles


@pytest.mark.parametrize(
    "use_system_trust_store",
    [False, True],
)
def test_spiffe_ssl_context_initialization(
    use_system_trust_store: bool,
    source_mocks: Tuple[MagicMock, PropertyMock, PropertyMock],
) -> None:
    """Test SpiffeSSLContext initialization."""
    x509_source, mock_svid, mock_bundle = source_mocks

    ctx = SpiffeSSLContext(x509_source, use_system_trusted_cas=use_system_trust_store)

    assert ctx is not None
    assert ctx.check_hostname is False
    assert ctx.minimum_version == ssl.TLSVersion.MINIMUM_SUPPORTED
    assert ctx.maximum_version == ssl.TLSVersion.MAXIMUM_SUPPORTED
    assert mock_svid.call_count > 0, "Expected x509_source.svid to be accessed"
    assert mock_bundle.call_count > 0, "Expected x509_source.bundles to be accessed"


def test_spiffe_ssl_context_class_property(
    source_mocks: Tuple[MagicMock, PropertyMock, PropertyMock],
) -> None:
    """Test that SpiffeSSLContext masquerades as ssl.SSLContext."""
    x509_source, _, _ = source_mocks

    ctx = SpiffeSSLContext(x509_source)

    # The __class__ property should return ssl.SSLContext for compatibility
    assert ctx.__class__ == ssl.SSLContext


def test_spiffe_ssl_context_options(
    source_mocks: Tuple[MagicMock, PropertyMock, PropertyMock],
) -> None:
    """Test setting and getting SSL options."""
    x509_source, _, _ = source_mocks

    ctx = SpiffeSSLContext(x509_source)

    # Test default options
    assert ctx.options == 0

    # Test setting options
    ctx.options = SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3
    assert ctx.options == SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3


def test_spiffe_ssl_context_verify_mode(
    source_mocks: Tuple[MagicMock, PropertyMock, PropertyMock],
) -> None:
    """Test setting and getting verification mode."""
    x509_source, _, _ = source_mocks

    ctx = SpiffeSSLContext(x509_source)

    # Test default verify mode
    assert ctx.verify_mode == ssl.CERT_REQUIRED

    # Test setting verify mode
    ctx.verify_mode = ssl.CERT_OPTIONAL
    assert ctx.verify_mode == ssl.CERT_OPTIONAL


def test_spiffe_ssl_context_tls_versions(
    source_mocks: Tuple[MagicMock, PropertyMock, PropertyMock],
) -> None:
    """Test setting minimum and maximum TLS versions."""
    x509_source, _, _ = source_mocks

    ctx = SpiffeSSLContext(x509_source)

    # Test setting minimum version
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2

    # Test setting maximum version
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    assert ctx.maximum_version == ssl.TLSVersion.TLSv1_3


def test_spiffe_ssl_context_set_ciphers(
    source_mocks: Tuple[MagicMock, PropertyMock, PropertyMock],
) -> None:
    """Test setting cipher list."""
    x509_source, _, _ = source_mocks

    ctx = SpiffeSSLContext(x509_source)

    # Should not raise an exception
    ctx.set_ciphers("HIGH:!aNULL:!MD5")
    ctx.set_ciphers(b"HIGH:!aNULL:!MD5")


def test_spiffe_ssl_context_no_op_methods(
    source_mocks: Tuple[MagicMock, PropertyMock, PropertyMock],
) -> None:
    """Test that no-op methods don't raise exceptions."""
    x509_source, _, _ = source_mocks

    ctx = SpiffeSSLContext(x509_source)

    # These should be no-ops and not raise exceptions
    ctx.set_default_verify_paths()
    ctx.load_verify_locations(cafile="/path/to/ca.pem")
    ctx.load_cert_chain(certfile="/path/to/cert.pem", keyfile="/path/to/key.pem")


@patch('socket.socket')
def test_spiffe_ssl_context_wrap_socket(
    mock_socket: MagicMock,
    source_mocks: Tuple[MagicMock, PropertyMock, PropertyMock],
) -> None:
    """Test wrapping a socket with SSL."""
    x509_source, _, _ = source_mocks

    ctx = SpiffeSSLContext(x509_source)

    mock_sock_instance = MagicMock()
    mock_sock_instance.fileno.return_value = 1
    mock_sock_instance.gettimeout.return_value = None

    # Test wrap_socket
    with patch('OpenSSL.SSL.Connection') as mock_connection_class:
        mock_connection = MagicMock()
        mock_connection_class.return_value = mock_connection

        wrapped = ctx.wrap_socket(
            mock_sock_instance,
            server_hostname="example.org",
            do_handshake_on_connect=False,
        )

        # Verify that Connection was created with the context
        mock_connection_class.assert_called_once()
        # Verify that set_tlsext_host_name was called for SNI
        mock_connection.set_tlsext_host_name.assert_called_once_with(b"example.org")
        # Verify that set_connect_state was called
        mock_connection.set_connect_state.assert_called_once()

        assert wrapped is not None


def test_spiffe_ssl_context_set_alpn_protocols(
    source_mocks: Tuple[MagicMock, PropertyMock, PropertyMock],
) -> None:
    """Test setting ALPN protocols."""
    x509_source, _, _ = source_mocks

    ctx = SpiffeSSLContext(x509_source)

    # Should not raise an exception
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    ctx.set_alpn_protocols([b"h2", b"http/1.1"])
