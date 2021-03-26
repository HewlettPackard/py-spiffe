"""
This module manages X.509 Bundle objects.
"""
import os
import threading
from typing import Set

from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate

from pyspiffe.bundle.x509_bundle.exceptions import (
    X509BundleError,
    SaveX509BundleError,
    ParseX509BundleError,
    LoadX509BundleError,
)
from pyspiffe.spiffe_id.trust_domain import TrustDomain, EMPTY_DOMAIN_ERROR
from pyspiffe.utils.certificate_utils import (
    parse_pem_certificates,
    parse_der_certificates,
    load_certificates_bytes_from_file,
    write_certificate_to_file,
)

_BUNDLE_FILE_MODE = 0o644

__all__ = ['X509Bundle']


class X509Bundle(object):
    """Represents a collection of trusted X.509 authorities for a trust domain. """

    def __init__(
        self,
        trust_domain: TrustDomain,
        x509_authorities: Set[Certificate],
    ) -> None:
        """Creates a X509Bundle instance.

        Args:
            trust_domain: A TrustDomain instance.
            x509_authorities: A set of CA certificates.

        Raises:
            X509BundleError: In case the trust_domain is empty.
        """

        self.lock = threading.Lock()

        if not trust_domain:
            raise X509BundleError(EMPTY_DOMAIN_ERROR)

        self._trust_domain = trust_domain
        self._x509_authorities = x509_authorities.copy() if x509_authorities else set()

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, X509Bundle):
            return False
        with self.lock:
            return (
                self._trust_domain.__eq__(o._trust_domain)
                and self._x509_authorities == o._x509_authorities
            )

    def trust_domain(self) -> TrustDomain:
        """Returns the trust domain of the bundle. """
        return self._trust_domain

    def x509_authorities(self) -> Set[Certificate]:
        """Returns a copy of set of X.509 authorities in the bundle. """
        with self.lock:
            return self._x509_authorities.copy()

    def add_authority(self, x509_authority: Certificate) -> None:
        """Adds an X.509 authority to the bundle. """
        with self.lock:
            self._x509_authorities.add(x509_authority)

    def remove_authority(self, x509_authority: Certificate) -> None:
        """Removes an X.509 authority from the bundle. """
        with self.lock:
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
            X509BundleError: In case the trust_domain is empty.
            ParseX509BundleError: In case the set of x509_authorities cannot be parsed from the bundle_bytes.
        """

        try:
            authorities = parse_pem_certificates(bundle_bytes)
        except Exception as e:
            raise ParseX509BundleError(str(e))

        return X509Bundle(trust_domain, set(authorities))

    @classmethod
    def parse_raw(cls, trust_domain: TrustDomain, bundle_bytes: bytes) -> 'X509Bundle':
        """Parses an X.509 bundle from an array of bytes containing trusted authorities as DER blocks.

        Args:
            trust_domain: A TrustDomain to associate to the bundle.
            bundle_bytes: An array of bytes that represents a set of X.509 authorities.

        Returns:
            An instance of 'X509Bundle' with the X.509 authorities associated to the given trust domain.

        Raises:
            X509BundleError: In case the trust_domain is empty.
            ParseBundleError: In case the set of x509_authorities cannot be parsed from the bundle_bytes.
        """

        authorities = parse_der_certificates(bundle_bytes)
        return X509Bundle(trust_domain, set(authorities))

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
            X509BundleError: In case the trust_domain is empty.
            LoadBundleError: In case the set of x509_authorities cannot be parsed from the bundle_bytes.
        """

        try:
            bundle_bytes = load_certificates_bytes_from_file(bundle_path)
        except Exception as e:
            raise LoadX509BundleError(str(e))

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

        if encoding not in [encoding.PEM, encoding.DER]:
            raise ValueError(
                'Encoding not supported: {}. Expected \'PEM\' or \'DER\'.'.format(
                    encoding
                )
            )
        _write_bundle_to_file(bundle_path, encoding, x509_bundle)


def _write_bundle_to_file(
    bundle_path: str,
    encoding: serialization.Encoding,
    x509_bundle: 'X509Bundle',
) -> None:
    try:
        with open(bundle_path, 'wb') as certs_file:
            os.chmod(certs_file.name, _BUNDLE_FILE_MODE)
            for cert in x509_bundle.x509_authorities():
                write_certificate_to_file(cert, certs_file, encoding)
    except Exception as err:
        raise SaveX509BundleError(
            'Error writing X.509 bundle to file: {}'.format(str(err))
        )
