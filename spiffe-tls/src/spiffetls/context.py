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
from typing import Optional, Callable

from OpenSSL import SSL, crypto
from cryptography.hazmat.primitives import serialization

from spiffe import X509Source
from spiffetls.errors import SslContextError

logger = logging.getLogger(__name__)


def create_ssl_context(
    method: int,
    x509_source: X509Source,
    authorize_fn: Optional[Callable[[crypto.X509], bool]] = None,
    verify_mode: int = SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
    use_system_trusted_cas=False,
) -> SSL.Context:
    """Configures and returns an SSL context for secure connections.

    This function abstracts the complexity of configuring SSL contexts with
    certificates provided by a X509Source, including setting up custom
    certificate verification if needed.

    Args:
        method: SSL method to use (e.g., SSL.TLS_SERVER_METHOD).
        x509_source: Provides the certificates and private keys.
        authorize_fn: Optional callback for additional cert verification.
        verify_mode: Determines the SSL certificate verification strategy.
        use_system_trusted_cas (bool): If True, the SSL context will include the system's trusted Certificate Authorities
        in addition to any custom certificates. Default is False.
        to any custom certificates. Default is False.

    Returns:
        Configured SSL.Context object.

    Raises:
        SslContextError: If SSL context configuration fails.
    """
    ssl_context = SSL.Context(method)

    try:
        _load_certificate_chain(ssl_context, x509_source)
        _load_ca_bundles(ssl_context, x509_source)

        def verify_callback(connection, x509, errno, depth, preverify_ok):
            if not preverify_ok:
                return False
            if depth == 0 and authorize_fn:
                # Perform custom verification at the leaf certificate
                return authorize_fn(x509)

            return preverify_ok

        ssl_context.set_verify(verify_mode, verify_callback)
        x509_source.subscribe_for_updates(
            lambda: _on_source_update(ssl_context, x509_source)
        )

        if use_system_trusted_cas:
            ssl_context.set_default_verify_paths()

    except SSL.Error as err:
        raise SslContextError("Error setting up certificates", err) from err
    except Exception as err:
        raise SslContextError("Unexpected error during SSL context setup", err) from err

    return ssl_context


def _load_certificate_chain(ssl_context: SSL.Context, x509_source: X509Source):
    """
    Loads the certificate chain and private key into the SSL context.
    """
    try:
        svid = x509_source.svid
        encoding_type = serialization.Encoding.PEM
        crypto_file_type = crypto.FILETYPE_PEM

        # Load the leaf certificate
        leaf_cert_pem = svid.leaf.public_bytes(encoding_type)
        leaf_cert = crypto.load_certificate(crypto_file_type, leaf_cert_pem)
        ssl_context.use_certificate(leaf_cert)

        # Load the private key
        private_key_pem = svid.private_key.private_bytes(
            encoding=encoding_type,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_key = crypto.load_privatekey(crypto_file_type, private_key_pem)
        ssl_context.use_privatekey(private_key)

        # Ensure the private key and certificate match
        ssl_context.check_privatekey()

        # Load the rest of certificate chain
        for cert_pem in svid.cert_chain[1:]:
            cert = crypto.load_certificate(
                crypto_file_type, cert_pem.public_bytes(encoding_type)
            )
            ssl_context.add_extra_chain_cert(cert)
    except Exception as e:
        raise Exception(f'Error loading certificates into SSL Context: {e}') from e


def _load_ca_bundles(ssl_context: SSL.Context, x509_source: X509Source):
    """
    Loads the trusted CA certificate bundles into the SSL context.
    """
    try:
        # Load trusted CA certificates
        for bundle in x509_source.bundles:
            for ca_cert in bundle.x509_authorities:
                ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
                ca_cert_obj = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem)
                ssl_context.get_cert_store().add_cert(ca_cert_obj)
    except Exception as e:
        raise Exception(
            f'Error loading trusted CA certificates into SSL Context: {e}'
        ) from e


def _on_source_update(ssl_context: SSL.Context, x509_source: X509Source):
    """
    Callback function to reload certificates.
    """
    _load_ca_bundles(ssl_context, x509_source)
    _load_certificate_chain(ssl_context, x509_source)
    logger.info("Certificates updated in SSL context.")
