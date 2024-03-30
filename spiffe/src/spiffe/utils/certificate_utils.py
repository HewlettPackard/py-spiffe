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

from typing import List, Iterable, Union

import os
import pem
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    ed25519,
    ed448,
    rsa,
    ec,
    dsa,
    dh,
    x25519,
    x448,
)
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_pem_private_key,
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1_modules.rfc5280 import Certificate as Pyasn1Certificate
from spiffe.utils.errors import (
    X509CertificateError,
    ParseCertificateError,
    LoadCertificateError,
    StoreCertificateError,
    ParsePrivateKeyError,
    LoadPrivateKeyError,
    StorePrivateKeyError,
)

_CERTS_FILE_MODE = 0o644
_PRIVATE_KEY_FILE_MODE = 0o600

PRIVATE_KEY_TYPES = Union[
    dh.DHPrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
    rsa.RSAPrivateKey,
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    x25519.X25519PrivateKey,
    x448.X448PrivateKey,
]


def parse_pem_certificates(pem_bytes: bytes) -> List[Certificate]:
    """Parses a list of certificates from PEM bytes.

    Args:
        pem_bytes: List of X.509 certificates as PEM blocks bytes.

    Returns:
        A list of Certificate objects.

    Raises:
        ParseCertificateError: In case the certificates cannot be parsed from the pem_bytes.
    """

    parsed_certs = pem.parse(pem_bytes)
    if not parsed_certs:
        raise ParseCertificateError('Unable to parse PEM X.509 certificate')

    try:
        return [
            x509.load_pem_x509_certificate(x509_cert.as_bytes(), default_backend())
            for x509_cert in parsed_certs
        ]
    except Exception as err:
        raise ParseCertificateError('Unable to parse PEM X.509 certificate') from err


def parse_der_certificates(der_bytes: bytes) -> List[Certificate]:
    """Parses a list of certificates from ASN.1 DER bytes.

    Args:
        der_bytes: List of X.509 certificates as ASN.1 DER bytes.

    Returns:
        A list of Certificate objects.

    Raises:
        ParseCertificateError: In case the certificates cannot be parsed from the der_bytes.
    """

    try:
        result = []
        cert, remaining_data = decode(der_bytes, Pyasn1Certificate())
        result.append(x509.load_der_x509_certificate(encode(cert)))
        while len(remaining_data) > 0:
            cert, remaining_data = decode(remaining_data, Pyasn1Certificate())
            result.append(x509.load_der_x509_certificate(encode(cert)))
        return result
    except Exception as err:
        raise ParseCertificateError('Unable to parse DER X.509 certificate') from err


def load_certificates_bytes_from_file(certificates_file_path: str) -> bytes:
    """Loads bytes from file path.

    Args:
        certificates_file_path: Path to the file containing the certificates.

    Returns:
        Bytes read from the file specified.

    Raises:
        X509CertificateError: In case the certificates_file cannot not be found or read.
    """

    try:
        return _load_bytes_from_file(certificates_file_path)
    except FileNotFoundError:
        raise LoadCertificateError('File not found: {}'.format(certificates_file_path))
    except Exception as err:
        raise LoadCertificateError('File could not be read: {}'.format(str(err))) from err


def write_certificates_to_file(
    certs_file_path: str,
    encoding: serialization.Encoding,
    certificates: Iterable[Certificate],
) -> None:
    """Writes certificates to a file.

    Args:
        certs_file_path: Path to the file the certificates will be written to.
        encoding: The serialization format used to encode the certificates. Can be 'PEM' or 'DER'.
        certificates: Iterable of certificate objects to be saved to file.

    Raises:
        StoreCertificateError: In case a certificate cannot be saved to file.
    """

    try:
        with open(certs_file_path, 'wb') as certs_file:
            os.chmod(certs_file.name, _CERTS_FILE_MODE)
            for cert in certificates:
                cert_bytes = serialize_certificate(cert, encoding)
                certs_file.write(cert_bytes)
    except Exception as err:
        raise StoreCertificateError(format(str(err))) from err


def serialize_certificate(certificate: Certificate, encoding: serialization.Encoding) -> bytes:
    """Serializes an X.509 certificate using the specified encoding.

    Args:
        certificate: Certificate object to be serialized to bytes.
        encoding: The serialization format to use to save the certificate.

    Raises:
        X509CertificateError: In case it cannot get the bytes from the certificate object.
    """
    try:
        cert_bytes = certificate.public_bytes(encoding)
    except Exception as err:
        raise X509CertificateError(
            'Could not serialize certificate from bytes: {}'.format(str(err))
        ) from err

    return cert_bytes


def load_private_key_from_file(private_key_path: str) -> bytes:
    """Loads bytes from file path.

    Args:
        private_key_path: Path to the file containing the private key.

    Returns:
        Bytes read from the file specified.

    Raises:
        LoadPrivateKeyError: In case the private_key_path cannot not be found or read.
    """

    try:
        return _load_bytes_from_file(private_key_path)
    except FileNotFoundError:
        raise LoadPrivateKeyError('File not found: {}'.format(private_key_path))
    except Exception as err:
        raise LoadPrivateKeyError('File could not be read: {}'.format(str(err))) from err


def write_private_key_to_file(
    private_key_path: str,
    encoding: serialization.Encoding,
    private_key: PRIVATE_KEY_TYPES,
) -> None:
    """Writes private key to a file.

    Args:
        private_key_path: Path to the file containing the private key.
        encoding: The serialization format used to encode the private key. Can be 'PEM' or 'DER'.
        private_key: Private key objects to be saved to file.

    Raises:
        StorePrivateKeyError: In case the private key cannot be saved to file.
    """
    try:
        private_key_bytes = _extract_private_key_bytes(encoding, private_key)

        with open(private_key_path, 'wb') as private_key_file:
            os.chmod(private_key_file.name, _PRIVATE_KEY_FILE_MODE)
            private_key_file.write(private_key_bytes)
    except Exception as err:
        raise StorePrivateKeyError(str(err)) from err


def parse_der_private_key(der_bytes: bytes) -> PRIVATE_KEY_TYPES:
    """Parses a private key from ASN.1 bytes.

    Args:
        der_bytes: A private Key as ASN.1 DER bytes.

    Returns:
        A private key object.

    Raises:
        ParsePrivateKeyError: In case the private key cannot be parsed from the der_bytes.
    """
    try:
        return load_der_private_key(der_bytes, None, None)
    except Exception as err:
        raise ParsePrivateKeyError(str(err)) from err


def parse_pem_private_key(pem_bytes: bytes) -> PRIVATE_KEY_TYPES:
    """Parses a private key from PEM bytes.

    Args:
        pem_bytes: A private Key as PEM blocks bytes.

    Returns:
        A private key object.

    Raises:
        ParsePrivateKeyError: In case the private key cannot be parsed from the pem_bytes.
    """
    try:
        return load_pem_private_key(pem_bytes, None, None)
    except Exception as err:
        raise ParsePrivateKeyError(str(err)) from err


def _load_bytes_from_file(file_path: str) -> bytes:
    with open(file_path, 'rb') as file:
        return file.read()


def _extract_private_key_bytes(
    encoding: serialization.Encoding, private_key: PRIVATE_KEY_TYPES
) -> bytes:
    try:
        return private_key.private_bytes(
            encoding,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    except Exception as err:
        raise Exception(
            'Could not serialize private key from bytes: {}'.format(str(err))
        ) from err
