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

"""
This module manages X.509 SVID objects.
"""

from typing import List

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate
from spiffe.errors import ArgumentError
from spiffe.spiffe_id.spiffe_id import SpiffeId
from spiffe.svid.errors import (
    InvalidLeafCertificateError,
    InvalidIntermediateCertificateError,
)
from spiffe.utils.certificate_utils import (
    parse_der_certificates,
    parse_pem_certificates,
    load_certificates_bytes_from_file,
    load_private_key_from_file,
    write_certificates_to_file,
    write_private_key_to_file,
    parse_pem_private_key,
    parse_der_private_key,
    PRIVATE_KEY_TYPES,
)

__all__ = ['X509Svid']


class X509Svid(object):
    """
    Represents a SPIFFE X.509-SVID.

    Contains a SpiffeId, a private key and a chain of X.509 certificates.
    """

    def __init__(
        self,
        spiffe_id: SpiffeId,
        cert_chain: List[Certificate],
        private_key: PRIVATE_KEY_TYPES,
    ) -> None:
        """Creates a X509Svid instance.

        Args:
            spiffe_id: A SpiffeId instance.
            cert_chain: A list representing a chain of X.509 Certificate.
            private_key: A Private Key object.
        """

        if not spiffe_id:
            raise ArgumentError('spiffe_id cannot be None')

        if not cert_chain:
            raise ArgumentError('cert_chain cannot be empty')

        if not private_key:
            raise ArgumentError('private_key cannot be None')

        self._spiffe_id = spiffe_id
        self._cert_chain = cert_chain
        self._private_key = private_key

    @property
    def leaf(self) -> Certificate:
        """Returns the Leaf X.509 certificate of the chain."""
        return self._cert_chain[0]

    @property
    def cert_chain(self) -> List[Certificate]:
        """Returns the X.509 chain of certificates."""
        return self._cert_chain.copy()

    @property
    def private_key(self) -> PRIVATE_KEY_TYPES:
        """Returns the private key."""
        return self._private_key

    @property
    def spiffe_id(self) -> SpiffeId:
        """Returns the SpiffeId."""
        return self._spiffe_id

    def save(
        self,
        certs_chain_path: str,
        private_key_path: str,
        encoding: serialization.Encoding,
    ) -> None:
        """Saves the X.509 SVID certs chain and private key in PEM or DER encoded files on disk.

        The private key is stored without encryption, but the file is set with filemode = '0600' (only owner has read/write permission).

        Args:
            certs_chain_path: Path to the file the chain of certificates will be written to.
                              The certs_chain file is configured with a filemode = '0644'.
            private_key_path: Path the file the private key will be written to.
                              The private_key file is configured with a filemode = '0600'.
            encoding: The encoding used to serialize the certs and private key, can be
                                            serialization.Encoding.PEM or serialization.Encoding.DER.

        Raises:
            ArgumentError: In case the encoding is not either PEM or DER (from serialization.Encoding).
            X509SvidError: In case the certs chain or the private key in the X509Svid cannot be converted to bytes.
            StorePrivateKeyError: In the case there is an error storing the private key to the file.
            StoreCertificateError: In the case the file path in certs_chain_path cannot be open to write,
                                  or there is an error storing the certificates to the file.
        """

        if encoding not in [encoding.PEM, encoding.DER]:
            raise ArgumentError(
                'Encoding not supported: {}. Expected \'PEM\' or \'DER\''.format(encoding)
            )

        write_certificates_to_file(certs_chain_path, encoding, self._cert_chain)
        write_private_key_to_file(private_key_path, encoding, self._private_key)

    @classmethod
    def parse_raw(cls, certs_chain_bytes: bytes, private_key_bytes: bytes) -> 'X509Svid':
        """Parses the X509-SVID from certificate chain and private key bytes.

        The certificate chain must be ASN.1 DER (concatenated with no intermediate padding if there are more than
        one certificate). The private key must be a PKCS#8 ASN.1 DER.

        It is assumed that the leaf certificate is always the first certificate in the parsed chain.

        Args:
            certs_chain_bytes: Chain of X.509 certificates in ASN.1 DER format.
            private_key_bytes: Private key as PKCS#8 ASN.1 DER.

        Returns:
            An instance of a 'X509Svid' containing the chain of certificates, the private key, and the SPIFFE ID of the
            leaf certificate in the chain.

        Raises:
            ParseCertificateError: In case the chain of certificates cannot be parsed from the cert_chain_bytes.
            ParsePrivateKeyError: In case the private key cannot be parsed from the private_key_bytes.
            InvalidLeafCertificateError: In case the leaf certificate does not have a SPIFFE ID in the URI SAN,
                                         in case the leaf certificate is CA,
                                         in case the leaf certificate has 'keyCertSign' as key usage,
                                         in case the leaf certificate does not have 'digitalSignature' as key usage,
                                         in case the leaf certificate does not have 'cRLSign' as key usage.
            InvalidIntermediateCertificateError: In case one of the intermediate certificates is not CA,
                                                 in case one of the intermediate certificates does not have 'keyCertSign' as key usage.
        """

        chain = parse_der_certificates(certs_chain_bytes)
        _validate_chain(chain)

        private_key = parse_der_private_key(private_key_bytes)
        spiffe_id = _extract_spiffe_id(chain[0])

        return X509Svid(spiffe_id, chain, private_key)

    @classmethod
    def parse(cls, certs_chain_bytes: bytes, private_key_bytes: bytes) -> 'X509Svid':
        """Parses the X.509 SVID from PEM blocks containing certificate chain and key bytes.

        The private key must be a PKCS#8 PEM block.

        It is assumed that the leaf certificate is always the first certificate in the parsed chain.

        Args:
            certs_chain_bytes: Chain of X.509 certificates in PEM format.
            private_key_bytes: Private key as PKCS#8 PEM block.

        Returns:
            An instance of a 'X509Svid' containing the chain of certificates, the private key, and the SPIFFE ID of the
            leaf certificate in the chain.

        Raises:
            ParseCertificateError: In case the chain of certificates cannot be parsed from the cert_chain_bytes.
            ParsePrivateKeyError: In case the private key cannot be parsed from the private_key_bytes.
            InvalidLeafCertificateError: In case the leaf certificate does not have a SPIFFE ID in the URI SAN,
                                         in case the leaf certificate is CA,
                                         in case the leaf certificate has 'keyCertSign' as key usage,
                                         in case the leaf certificate does not have 'digitalSignature' as key usage,
                                         in case the leaf certificate does not have 'cRLSign' as key usage.
            InvalidIntermediateCertificateError: In case one of the intermediate certificates is not CA,
                                                 in case one of the intermediate certificates does not have 'keyCertSign' as key usage.
        """

        chain = parse_pem_certificates(certs_chain_bytes)
        _validate_chain(chain)

        private_key = parse_pem_private_key(private_key_bytes)
        spiffe_id = _extract_spiffe_id(chain[0])

        return X509Svid(spiffe_id, chain, private_key)

    @classmethod
    def load(
        cls,
        certs_chain_path: str,
        private_key_path: str,
        encoding: serialization.Encoding,
    ) -> 'X509Svid':
        """Loads the X.509 SVID from PEM or DER encoded files on disk.

        The private key should be without encryption.

        Args:
            certs_chain_path: Path to the file containing one or more X.509 certificates as PEM blocks.
            private_key_path: Path the file containing a private key as PKCS#8 PEM block.
            encoding: The encoding used to serialize the certs and private key, can be
                                            serialization.Encoding.PEM or serialization.Encoding.DER.

        Returns:
            An instance of a 'X509Svid' containing the chain of certificates, the private key, and the SPIFFE ID of the
            leaf certificate in the chain.

        Raises:
            ArgumentError: In case the encoding is not either PEM or DER (from serialization.Encoding).
            X509SvidError: In case the file path in certs_chain_path or in private_key_path does not exists or cannot be open.
            ParseCertificateError: In case the chain of certificates cannot be parsed from the bytes read from certs_chain_path.
            ParsePrivateKeyError: In case the private key cannot be parsed from the bytes read from private_key_path.
            InvalidLeafCertificateError: In case the leaf certificate does not have a SPIFFE ID in the URI SAN,
                                         in case the leaf certificate is CA,
                                         in case the leaf certificate has 'keyCertSign' as key usage,
                                         in case the leaf certificate does not have 'digitalSignature' as key usage,
                                         in case the leaf certificate does not have 'cRLSign' as key usage.
            InvalidIntermediateCertificateError: In case one of the intermediate certificates is not CA,
                                                 in case one of the intermediate certificates does not have 'keyCertSign' as key usage.
        """

        chain_bytes = load_certificates_bytes_from_file(certs_chain_path)
        key_bytes = load_private_key_from_file(private_key_path)

        if encoding == serialization.Encoding.PEM:
            return cls.parse(chain_bytes, key_bytes)

        if encoding == serialization.Encoding.DER:
            return cls.parse_raw(chain_bytes, key_bytes)

        raise ArgumentError(
            'Encoding not supported: {}. Expected \'PEM\' or \'DER\''.format(encoding)
        )


def _extract_spiffe_id(cert: Certificate) -> SpiffeId:
    ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if isinstance(ext.value, x509.SubjectAlternativeName):
        sans = ext.value.get_values_for_type(x509.UniformResourceIdentifier)
    if len(sans) == 0:
        raise InvalidLeafCertificateError(
            'Certificate does not contain a SPIFFE ID in the URI SAN'
        )
    return SpiffeId(sans[0])


def _validate_chain(cert_chain: List[Certificate]) -> None:
    leaf = cert_chain[0]
    _validate_leaf_certificate(leaf)

    for cert in cert_chain[1:]:
        _validate_intermediate_certificate(cert)


def _validate_leaf_certificate(leaf: Certificate) -> None:
    basic_constraints = leaf.extensions.get_extension_for_oid(
        x509.ExtensionOID.BASIC_CONSTRAINTS
    ).value
    if isinstance(basic_constraints, x509.BasicConstraints) and basic_constraints.ca:
        raise InvalidLeafCertificateError('Leaf certificate must not have CA flag set to true')

    key_usage = leaf.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE).value
    if isinstance(key_usage, x509.KeyUsage) and not key_usage.digital_signature:
        raise InvalidLeafCertificateError(
            'Leaf certificate must have \'digitalSignature\' as key usage'
        )
    if isinstance(key_usage, x509.KeyUsage) and key_usage.key_cert_sign:
        raise InvalidLeafCertificateError(
            'Leaf certificate must not have \'keyCertSign\' as key usage'
        )
    if isinstance(key_usage, x509.KeyUsage) and key_usage.crl_sign:
        raise InvalidLeafCertificateError(
            'Leaf certificate must not have \'cRLSign\' as key usage'
        )


def _validate_intermediate_certificate(cert: Certificate) -> None:
    basic_constraints = cert.extensions.get_extension_for_oid(
        x509.ExtensionOID.BASIC_CONSTRAINTS
    ).value
    if isinstance(basic_constraints, x509.BasicConstraints) and not basic_constraints.ca:
        raise InvalidIntermediateCertificateError(
            'Signing certificate must have CA flag set to true'
        )
    key_usage = cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE).value
    if isinstance(key_usage, x509.KeyUsage) and not key_usage.key_cert_sign:
        raise InvalidIntermediateCertificateError(
            'Signing certificate must have \'keyCertSign\' as key usage'
        )
