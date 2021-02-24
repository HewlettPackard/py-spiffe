"""
This module manages X.509 Bundle objects.
"""

import os
from typing import Set

import pem
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate
from typing.io import BinaryIO

from pyspiffe.bundle.x509_bundle.exceptions import (
    ParseX509BundleError,
    X509BundleError,
    LoadX509BundleError,
    SaveX509BundleError,
)
from pyspiffe.spiffe_id.trust_domain import TrustDomain, EMPTY_DOMAIN_ERROR
from pyasn1.codec.der.decoder import decode

_BUNDLE_FILE_MODE = 0o644


class X509Bundle(object):
    """
    Represents a collection of trusted X.509 authorities for a trust domain.
    """

    def __init__(
        self,
        trust_domain: TrustDomain,
        x509_authorities: Set[Certificate],
    ) -> None:
        """Creates a X509Bundle instance.

        Args:
            trust_domain: A TrustDomain instance.
            x509_authorities: A set of CA certificates.
        """
        self._trust_domain = trust_domain
        self._x509_authorities = x509_authorities

    def trust_domain(self) -> TrustDomain:
        """Returns the trust domain of the bundle. """
        return self._trust_domain

    def x509_authorities(self) -> Set[Certificate]:
        """Returns the set of X.509 authorities in the bundle. """
        return self._x509_authorities

    def add_authority(self, x509_authority: Certificate) -> None:
        """Adds an X.509 authority to the bundle. """
        if not self._x509_authorities:
            self._x509_authorities = set()

        self._x509_authorities.add(x509_authority)

    def remove_authority(self, x509_authority: Certificate) -> None:
        """Removes an X.509 authority from the bundle. """
        if not self._x509_authorities:
            return
        self._x509_authorities.remove(x509_authority)

    @classmethod
    def parse(cls, trust_domain: TrustDomain, bundle_bytes: bytes) -> 'X509Bundle':
        """Parses an X.509 bundle from an array of bytes containing trusted authorities as PEM blocks.

        Args:
            trust_domain: A TrustDomain to associate to the bundle.
            bundle_bytes: An array of bytes that represents a set of X.509 authorities.

        Returns:
            An instance of 'X509Bundle' with the X.509 authorities associated to the given trust domain.

        Raises:
            ParseBundleError: In case the set of x509_authorities cannot be parsed from the bundle_bytes.
        """

        if not trust_domain:
            raise X509BundleError(EMPTY_DOMAIN_ERROR)

        authorities = cls._parse_pem_authorities(bundle_bytes)

        return X509Bundle(trust_domain, authorities)

    @classmethod
    def parse_raw(cls, trust_domain: TrustDomain, bundle_bytes: bytes) -> 'X509Bundle':
        """Parses an X.509 bundle from an array of bytes containing trusted authorities as DER blocks.

        Args:
            trust_domain: A TrustDomain to associate to the bundle.
            bundle_bytes: An array of bytes that represents a set of X.509 authorities.

        Returns:
            An instance of 'X509Bundle' with the X.509 authorities associated to the given trust domain.

        Raises:
            ParseBundleError: In case the set of x509_authorities cannot be parsed from the bundle_bytes.
        """

        if not trust_domain:
            raise X509BundleError(EMPTY_DOMAIN_ERROR)

        authorities = cls._parse_der_authorities(bundle_bytes)

        return X509Bundle(trust_domain, authorities)

    @classmethod
    def load(
        cls,
        trust_domain: TrustDomain,
        bundle_path: str,
        encoding: serialization.Encoding,
    ) -> 'X509Bundle':
        """Loads an X.509 bundle from a file in disk containing DER or PEM encoded trusted authorities.

        Args:
            trust_domain: A trust domain to associate to the bundle.
            bundle_path: Path to the file containing a set of X.509 authorities.
            encoding: Bundle encoding format, either serialization.Encoding.PEM or serialization.Encoding.DER.

        Returns:
            An instance of 'X509Bundle' with the X.509 authorities associated to the given trust domain.

        Raises:
            LoadBundleError: In case the set of x509_authorities cannot be parsed from the bundle_bytes.
        """

        if not trust_domain:
            raise X509BundleError(EMPTY_DOMAIN_ERROR)

        bundle_bytes = cls._load_bundle_bytes(bundle_path)

        if encoding == serialization.Encoding.PEM:
            return cls.parse(trust_domain, bundle_bytes)

        if encoding == serialization.Encoding.DER:
            return cls.parse_raw(trust_domain, bundle_bytes)

        raise ValueError(
            'Encoding not supported: {}. Expected \'PEM\' or \'DER\'.'.format(encoding)
        )

    @classmethod
    def save(
        cls,
        x509_bundle: 'X509Bundle',
        bundle_path: str,
        encoding: serialization.Encoding,
    ) -> None:
        """Saves an X.509 bundle to a file in disk.

        Args:
            x509_bundle: Instance of 'X509Bundle' to be saved to disk
            bundle_path: Path to the file containing a set of X.509 authorities
            encoding: Bundle encoding format, either serialization.Encoding.PEM or serialization.Encoding.DER

        Raises:
            ValueError: In case the encoding is not either PEM or DER (from serialization.Encoding)
            X509BundleError: In case the authorities in the bundle cannot be converted to bytes.
            SaveX509BundleError: In the case the file path in bundle_path cannot be open to write, or there is an error
                                writing the authorities bytes to the file.
        """

        if not (encoding is encoding.PEM or encoding is encoding.DER):
            raise ValueError(
                'Encoding not supported: {}. Expected \'PEM\' or \'DER\'.'.format(
                    encoding
                )
            )
        cls._write_certs_to_file(bundle_path, encoding, x509_bundle)

    @staticmethod
    def _parse_pem_authorities(pem_bytes: bytes) -> Set[Certificate]:
        result = set()
        parsed_certs = pem.parse(pem_bytes)
        for cert in parsed_certs:
            try:
                x509_cert = x509.load_pem_x509_certificate(
                    cert.as_bytes(), default_backend()
                )
                result.add(x509_cert)
            except Exception:
                raise ParseX509BundleError('Unable to load PEM X.509 certificate')

        if len(result) < 1:
            raise ParseX509BundleError('Unable to load PEM X.509 certificate')
        return result

    @staticmethod
    def _parse_der_authorities(der_bytes: bytes) -> Set[Certificate]:
        chain = set()
        try:
            leaf = x509.load_der_x509_certificate(der_bytes, default_backend())
            chain.add(leaf)
            _, remaining_data = decode(der_bytes)
            while len(remaining_data) > 0:
                cert = x509.load_der_x509_certificate(remaining_data, default_backend())
                chain.add(cert)
                _, remaining_data = decode(remaining_data)
        except Exception as err:
            raise ParseX509BundleError(str(err))

        return chain

    @staticmethod
    def _load_bundle_bytes(certs_chain_path: str) -> bytes:
        try:
            with open(certs_chain_path, 'rb') as chain_file:
                return chain_file.read()
        except FileNotFoundError:
            raise LoadX509BundleError(
                'Certs chain file file not found: {}'.format(certs_chain_path)
            )
        except Exception as err:
            raise LoadX509BundleError(
                'Certs chain file could not be read: {}'.format(str(err))
            )

    @classmethod
    def _write_certs_to_file(
        cls,
        bundle_path: str,
        encoding: serialization.Encoding,
        x509_bundle: 'X509Bundle',
    ) -> None:
        try:
            with open(bundle_path, 'wb') as chain_file:
                os.chmod(chain_file.name, _BUNDLE_FILE_MODE)
                for cert in x509_bundle._x509_authorities:
                    cls._write_cert_to_file(cert, chain_file, encoding)
        except Exception as err:
            raise SaveX509BundleError(
                'Error opening certs chain file: {}'.format(str(err))
            )

    @classmethod
    def _write_cert_to_file(
        cls,
        authority: Certificate,
        bundle_file: BinaryIO,
        encoding: serialization.Encoding,
    ) -> None:
        try:
            authority_bytes = cls._extract_chain_bytes(authority, encoding)
            bundle_file.write(authority_bytes)
        except Exception as err:
            raise SaveX509BundleError(
                'Error writing authority certificate to file: {}'.format(str(err))
            )

    @staticmethod
    def _extract_chain_bytes(
        cert: Certificate, encoding: serialization.Encoding
    ) -> bytes:
        try:
            cert_bytes = cert.public_bytes(encoding)
        except Exception as err:
            raise X509BundleError(
                'Could not get bytes from object: {}'.format(str(err))
            )

        return cert_bytes
