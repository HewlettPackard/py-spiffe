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
from typing import Callable, Set

from OpenSSL import crypto
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from spiffe.spiffe_id.spiffe_id import SpiffeId, SpiffeIdError, TrustDomain
from spiffe.spiffe_id.spiffe_id import SCHEME_PREFIX
from spiffe.utils.errors import X509CertificateError

_logger: logging.Logger = logging.getLogger(__name__)


def authorize_any() -> Callable[[crypto.X509], bool]:
    """Authorizes any valid SPIFFE ID, rejects if no valid SPIFFE ID is present."""

    def _authorize(cert: crypto.X509) -> bool:
        try:
            _spiffe_id_from_cert(cert)
            return True
        except X509CertificateError as e:
            _logger.error(f'Failed to authorize certificate due to invalid SPIFFE ID: {e}')

        return False

    return _authorize


def authorize_id(expected_spiffe_id: SpiffeId) -> Callable[[crypto.X509], bool]:
    """Authorizes a specific SPIFFE ID."""

    def _authorize(cert: crypto.X509) -> bool:
        try:
            spiffe_id = _spiffe_id_from_cert(cert)
            return spiffe_id == expected_spiffe_id
        except X509CertificateError as e:
            _logger.error(f'Failed to extract SPIFFE ID from certificate: {e}')

        return False

    return _authorize


def authorize_one_of(allowed_ids: Set[SpiffeId]) -> Callable[[crypto.X509], bool]:
    """Authorizes any SPIFFE ID in the given list of IDs."""

    def _authorize(cert: crypto.X509) -> bool:
        try:
            spiffe_id = _spiffe_id_from_cert(cert)
            if spiffe_id in allowed_ids:
                return True
            else:
                _logger.error(f"Unauthorized SPIFFE ID: {spiffe_id}")
        except X509CertificateError as e:
            _logger.error(f"Failed to extract SPIFFE ID from certificate: {e}")

        return False

    return _authorize


def authorize_member_of(
    allowed_trust_domain: TrustDomain,
) -> Callable[[crypto.X509], bool]:
    """Authorizes any SPIFFE ID in the given trust domain."""

    def _authorize(cert: crypto.X509) -> bool:
        try:
            cert_spiffe_id = _spiffe_id_from_cert(cert)
            return cert_spiffe_id.trust_domain == allowed_trust_domain
        except X509CertificateError as e:
            _logger.error(f'Failed to extract SPIFFE ID from certificate: {e}')

        return False

    return _authorize


def _spiffe_id_from_cert(cert: crypto.X509) -> SpiffeId:
    """Returns the SPIFFE ID from a pyOpenSSL certificate"""
    cryptography_cert = cert.to_cryptography()

    try:
        ext = cryptography_cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound as e:
        raise X509CertificateError(
            'Certificate does not contain a Subject Alternative Name extension'
        ) from e

    san_value = ext.value
    if not isinstance(san_value, x509.SubjectAlternativeName):
        raise X509CertificateError(
            'Certificate does not contain a valid Subject Alternative Name extension'
        )

    uri_sans = san_value.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uri_sans) == 0:
        raise X509CertificateError(
            'Certificate does not contain a URI SAN (expected exactly one SPIFFE ID)'
        )

    if len(uri_sans) != 1:
        raise X509CertificateError(
            'Certificate contains multiple URI SAN entries (expected exactly one SPIFFE ID)'
        )

    uri = uri_sans[0]
    if not uri.startswith(SCHEME_PREFIX):
        raise X509CertificateError('Certificate URI SAN is not a SPIFFE ID')

    try:
        return SpiffeId(uri)
    except SpiffeIdError as e:
        raise X509CertificateError(
            f'Certificate contains a malformed SPIFFE ID in the URI SAN: {uri!r}'
        ) from e
