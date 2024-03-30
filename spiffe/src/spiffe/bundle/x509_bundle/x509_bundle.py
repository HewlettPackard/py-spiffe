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
This module manages X.509 Bundle objects.
"""

import threading
from typing import Set, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate
from spiffe.errors import ArgumentError
from spiffe.bundle.x509_bundle.errors import (
    X509BundleError,
    SaveX509BundleError,
    ParseX509BundleError,
    LoadX509BundleError,
)
from spiffe.spiffe_id.spiffe_id import TrustDomain
from spiffe.utils.certificate_utils import (
    parse_pem_certificates,
    parse_der_certificates,
    load_certificates_bytes_from_file,
    write_certificates_to_file,
)

__all__ = ['X509Bundle']


class X509Bundle(object):
    """Represents a collection of trusted X.509 authorities for a trust domain."""

    def __init__(
        self,
        trust_domain: TrustDomain,
        x509_authorities: Optional[Set[Certificate]],
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
            raise X509BundleError("Trust domain cannot be empty")

        self._trust_domain = trust_domain
        self._x509_authorities = x509_authorities.copy() if x509_authorities else set()

    @property
    def trust_domain(self) -> TrustDomain:
        """Returns the trust domain of the bundle."""
        return self._trust_domain

    @property
    def x509_authorities(self) -> Set[Certificate]:
        """Returns a copy of set of X.509 authorities in the bundle."""
        with self.lock:
            return self._x509_authorities.copy()

    def add_authority(self, x509_authority: Certificate) -> None:
        """Adds an X.509 authority to the bundle."""
        with self.lock:
            self._x509_authorities.add(x509_authority)

    def remove_authority(self, x509_authority: Certificate) -> None:
        """Removes an X.509 authority from the bundle."""
        with self.lock:
            if not self._x509_authorities:
                return
            self._x509_authorities.remove(x509_authority)

    def save(
        self,
        bundle_path: str,
        encoding: serialization.Encoding,
    ) -> None:
        """Saves the X.509 bundle to a file in disk.

        Args:
            bundle_path: Path to the file the set of X.509 authorities will be written to.
            encoding: Bundle encoding format, either serialization.Encoding.PEM or serialization.Encoding.DER

        Raises:
            ArgumentError: In case the encoding is not either PEM or DER (from serialization.Encoding)
            SaveX509BundleError: In the case the file path in bundle_path cannot be open to write, or there is an error
                                converting or writing the authorities bytes to the file.
        """

        if encoding not in [encoding.PEM, encoding.DER]:
            raise ArgumentError(
                'Encoding not supported: {}. Expected \'PEM\' or \'DER\''.format(encoding)
            )
        try:
            write_certificates_to_file(bundle_path, encoding, self._x509_authorities)
        except Exception as err:
            raise SaveX509BundleError(bundle_path) from err

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
        except Exception as err:
            raise ParseX509BundleError(str(err)) from err

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
            ParseX509BundleError: In case the set of x509_authorities cannot be parsed from the bundle_bytes.
        """

        try:
            authorities = parse_der_certificates(bundle_bytes)
        except Exception as err:
            raise ParseX509BundleError(str(err)) from err

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
            LoadX509BundleError: In case the set of x509_authorities cannot be parsed from the bundle_bytes.
        """

        try:
            bundle_bytes = load_certificates_bytes_from_file(bundle_path)
        except Exception as err:
            raise LoadX509BundleError(str(err)) from err

        if encoding == serialization.Encoding.PEM:
            return cls.parse(trust_domain, bundle_bytes)

        if encoding == serialization.Encoding.DER:
            return cls.parse_raw(trust_domain, bundle_bytes)

        raise ArgumentError(
            'Encoding not supported: {}. Expected \'PEM\' or \'DER\''.format(encoding)
        )

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, X509Bundle):
            return False
        with self.lock:
            return (
                self.trust_domain.__eq__(o.trust_domain)
                and self._x509_authorities == o._x509_authorities
            )

    def __hash__(self):
        trust_domain_hash = hash(self.trust_domain)
        authorities_hash = hash(tuple(hash(authority) for authority in self._x509_authorities))
        return hash((trust_domain_hash, authorities_hash))
