from typing import List

import pem
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate
from pyasn1.codec.der.decoder import decode
from typing.io import BinaryIO

from pyspiffe.utils.exceptions import X509CertificateError


def parse_pem_certificates(pem_bytes: bytes) -> List[Certificate]:
    """Parses a list of certificates from PEM bytes.

    Args:
        pem_bytes: List of X.509 certificates as PEM blocks bytes.

    Returns:
        A list of Certificate objects.

    Raises:
        X509CertificateError: In case the certificates cannot be parsed from the pem_bytes.
    """

    parsed_certs = pem.parse(pem_bytes)
    if not parsed_certs:
        raise X509CertificateError('Unable to parse PEM X.509 certificate')

    result = []
    for cert in parsed_certs:
        try:
            x509_cert = x509.load_pem_x509_certificate(
                cert.as_bytes(), default_backend()
            )
            result.append(x509_cert)
        except Exception:
            raise X509CertificateError('Unable to parse PEM X.509 certificate')

    return result


def parse_der_certificates(der_bytes: bytes) -> List[Certificate]:
    """Parses a list of certificates from ASN.1 DER bytes.

    Args:
        der_bytes: List of X.509 certificates as ASN.1 DER bytes.

    Returns:
        A list of Certificate objects.

    Raises:
        X509CertificateError: In case the certificates cannot be parsed from the der_bytes.
    """

    result = []
    try:
        leaf = x509.load_der_x509_certificate(der_bytes, default_backend())
        result.append(leaf)
        _, remaining_data = decode(der_bytes)
        while len(remaining_data) > 0:
            cert = x509.load_der_x509_certificate(remaining_data, default_backend())
            result.append(cert)
            _, remaining_data = decode(remaining_data)
    except Exception:
        raise X509CertificateError('Unable to parse DER X.509 certificate')

    return result


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
        with open(certificates_file_path, 'rb') as certs_file:
            return certs_file.read()
    except FileNotFoundError:
        raise X509CertificateError(
            'Certificates file not found: {}'.format(certificates_file_path)
        )
    except Exception as err:
        raise X509CertificateError(
            'Certificates file could not be read: {}'.format(str(err))
        )


def write_certificate_to_file(
    certificate: Certificate,
    dest_file: BinaryIO,
    encoding: serialization.Encoding,
) -> None:
    """Writes a certificate to a file.

    Args:
        certificate: Certificate object to be saved to file.
        dest_file: BinaryIO object representing the file to be written to.
        encoding: The serialization format to use to save the certificate.

    Raises:
        X509CertificateError: In case the certificate cannot be saved to file.
    """

    try:
        cert_bytes = serialize_certificate(certificate, encoding)
        dest_file.write(cert_bytes)
    except Exception as err:
        raise X509CertificateError(
            'Error writing certificate to file: {}'.format(str(err))
        )


def serialize_certificate(
    certificate: Certificate, encoding: serialization.Encoding
) -> bytes:
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
            'Could not get bytes from object: {}'.format(str(err))
        )

    return cert_bytes
