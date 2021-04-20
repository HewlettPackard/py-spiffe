"""
This module manages TrustDomain objects.
"""

from urllib.parse import urlparse, ParseResult
from typing import Any, cast


from pyspiffe.spiffe_id import SPIFFE_SCHEME
from pyspiffe.exceptions import ArgumentError

EMPTY_DOMAIN_ERROR = 'Trust domain cannot be empty'
"""str: Default error message for empty Trust Domains."""

SCHEME_SUFFIX = '://'
"""str: SPIFFE Scheme suffix."""

TRUST_DOMAIN_MAXIMUM_LENGTH = 255
"""str: Trust domain maximum length."""


class TrustDomain(object):
    """Represents the name of a SPIFFE trust domain (e.g. 'domain.test')."""

    def __init__(self, name: str) -> None:
        """Creates a new TrustDomain Object.

        Args:
            name: The name of the Trust Domain.

        Raises:
            ArgumentError: If the name of the trust domain is empty, has a port, or contains an invalid scheme.

        Examples:
            >>> trust_domain = TrustDomain('Domain.Test')
            >>> print(trust_domain)
            domain.test

            >>> print(trust_domain.as_str_id())
            spiffe://domain.test

        """
        self.__set_name(name)

    def __str__(self) -> str:
        return self.__name

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, self.__class__):
            return self.__name == other.name()
        return False

    def __hash__(self) -> int:
        return hash(self.__name)

    def name(self) -> str:
        return self.__name

    def as_str_id(self) -> str:
        return '{}://{}'.format(SPIFFE_SCHEME, self.__name)

    def __set_name(self, name: str) -> None:
        if not name:
            raise ArgumentError(EMPTY_DOMAIN_ERROR)

        if len(name) > TRUST_DOMAIN_MAXIMUM_LENGTH:
            raise ArgumentError(
                'Trust domain cannot be longer than {} bytes'.format(
                    TRUST_DOMAIN_MAXIMUM_LENGTH
                )
            )

        name = self.normalize(name)
        uri: ParseResult = urlparse(name)
        self.validate_uri(uri)
        self.__name = cast(str, uri.hostname).lower().strip()

    @staticmethod
    def normalize(name: str) -> str:
        """Adds the SPIFFE scheme if not present."""
        if SCHEME_SUFFIX not in name:
            name = SPIFFE_SCHEME + SCHEME_SUFFIX + name
        return name

    @staticmethod
    def validate_uri(uri: ParseResult) -> None:
        if uri.scheme != SPIFFE_SCHEME:
            raise ArgumentError(
                'Trust domain: invalid scheme: expected {}'.format(SPIFFE_SCHEME)
            )
        if not uri.hostname:
            raise ArgumentError(EMPTY_DOMAIN_ERROR)
        if uri.port:
            raise ArgumentError('Trust domain: port is not allowed')
