"""
This module manages SpiffeId objects.
"""

from typing import Any, Union, List, Optional

from pyspiffe.exceptions import SpiffeIdError, ArgumentError
from pyspiffe.spiffe_id import SCHEME_PREFIX
from pyspiffe.spiffe_id import SPIFFE_SCHEME
from pyspiffe.spiffe_id.errors import (
    EMPTY,
    WRONG_SCHEME,
    EMPTY_SEGMENT,
    DOT_SEGMENT,
    BAD_PATH_SEGMENT_CHAR,
    BAD_TRUST_DOMAIN_CHAR,
    TRAILING_SLASH,
    MISSING_TRUST_DOMAIN,
)


class TrustDomain(object):
    """Represents the name of a SPIFFE trust domain (e.g. 'domain.test')."""

    @classmethod
    def parse(cls, id_or_name: str) -> 'TrustDomain':
        """Creates a new TrustDomain Object.

        Args:
            id_or_name: The name of a Trust Domain or a string representing a SPIFFE ID.

        Raises:
            ArgumentError: If the name of the trust domain is empty.
            SpiffeIdError: If the name contains an invalid char.

        Examples:
            >>> trust_domain = TrustDomain.parse('domain.test')
            >>> print(trust_domain)
            domain.test

            >>> print(trust_domain.as_str_id())
            spiffe://domain.test

        """

        if not id_or_name:
            raise ArgumentError(MISSING_TRUST_DOMAIN)

        # Something looks kinda like a scheme separator, let's try to parse as
        # an ID. We use :/ instead of :// since the diagnostics are better for
        # a bad input like spiffe:/trustdomain.
        if ':/' in id_or_name:
            spiffe_id = SpiffeId.parse(id_or_name)
            return spiffe_id.trust_domain()

        validate_trust_domain_name(id_or_name)

        result = TrustDomain()
        result._set_name(id_or_name)
        return result

    def __str__(self) -> str:
        return self._name

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, self.__class__):
            return self._name == other.name()
        return False

    def __hash__(self) -> int:
        return hash(self._name)

    def name(self) -> str:
        return self._name

    def _set_name(self, name):
        self._name = name

    def as_str_id(self) -> str:
        return '{}://{}'.format(SPIFFE_SCHEME, self._name)


class SpiffeId(object):
    """Represents a SPIFFE ID as defined in the `SPIFFE standard <https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md>`_."""

    @classmethod
    def parse(cls, id: str) -> 'SpiffeId':
        """Parses a SPIFFE ID from a string into a SpiffeId type instance.

        Args:
            id: A string representing a SPIFFE ID.

        Returns:
            An instance of a compliant SPIFFE ID (SpiffeId type).

        Raises:
            ArgumentError: If the id is emtpy.
            SpiffeIdError: If the string spiffe_id doesn't comply the the SPIFFE standard.

        Examples:
            >>> spiffe_id = SpiffeId.parse('spiffe://domain.test/path/element')
            >>> print(spiffe_id.trust_domain())
            domain.test
            >>> print(spiffe_id.path())
            /path/element
        """

        if not id:
            raise ArgumentError(EMPTY)

        if SCHEME_PREFIX not in id:
            raise SpiffeIdError(WRONG_SCHEME)

        rest = id[len(SCHEME_PREFIX) :]

        i = 0
        for c in rest:
            if c == '/':
                break
            if not is_valid_trustdomain_char(c):
                raise SpiffeIdError(BAD_TRUST_DOMAIN_CHAR)
            i += 1

        if i == 0:
            raise SpiffeIdError(MISSING_TRUST_DOMAIN)

        td = rest[:i]
        path = rest[i:]

        if path:
            validate_path(path)

        result = SpiffeId()
        trust_domain = TrustDomain()
        trust_domain._set_name(td)
        result._set_trust_domain(trust_domain)
        result._set_path(path)
        return result

    @classmethod
    def from_segments(
        cls, trust_domain: TrustDomain, path_segments: Optional[Union[str, List[str]]]
    ) -> 'SpiffeId':
        """Creates SpiffeId type instance from a Trust Domain and one or more paths.

        Args:
            trust_domain: The trust domain corresponds to the trust root of a system.
            path_segments: A single string or a list of path segments.

        Returns:
            An instance of a compliant SPIFFE ID (SpiffeId type).

        Raises:
            ArgumentError: If the trust_domain is None.
            SpiffeIdError: If the path segments are not SPIFFE conformant.

        Examples:
            >>> spiffe_id_1 = SpiffeId.from_segments(TrustDomain.parse('example.org'), 'path')
            >>> print(spiffe_id_1)
            spiffe://example.org/path

            an array of paths:
            >>> spiffe_id_2 = SpiffeId.from_segments(TrustDomain.parse('example.org'), ['path1', 'path2', 'element'])
            >>> print(spiffe_id_2)
            spiffe://example.org/path1/path2/element
        """

        if not trust_domain:
            raise ArgumentError(MISSING_TRUST_DOMAIN)

        result = SpiffeId()
        result._set_trust_domain(trust_domain)

        if path_segments is not None:
            path = ''

            if isinstance(path_segments, List):
                for p in path_segments:
                    validate_path(p)
                    path += '/' + p
            else:
                validate_path(path_segments)
                path = '/' + path_segments

            result._set_path(path)

        return result

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, self.__class__):
            return False
        return self._trust_domain == other._trust_domain and self._path == other.path()

    def __hash__(self) -> int:
        return hash((self._trust_domain, self._path))

    def __str__(self) -> str:
        if self._path:
            return '{}://{}{}'.format(
                SPIFFE_SCHEME, self._trust_domain.name(), self._path
            )
        return '{}://{}'.format(SPIFFE_SCHEME, self._trust_domain.name())

    def path(self) -> str:
        return self._path

    def trust_domain(self) -> TrustDomain:
        return self._trust_domain

    def is_member_of(self, trust_domain: TrustDomain) -> bool:
        return self._trust_domain == trust_domain

    def _set_trust_domain(self, trust_domain: TrustDomain) -> None:
        self._trust_domain = trust_domain

    def _set_path(self, path: str):
        self._path = path


def validate_trust_domain_name(name):
    for c in name:
        if not is_valid_trustdomain_char(c):
            raise SpiffeIdError(BAD_TRUST_DOMAIN_CHAR)


def is_valid_trustdomain_char(c) -> bool:
    if 'a' <= c <= 'z':
        return True
    if '0' <= c <= '9':
        return True
    return c == '-' or c == '.' or c == '_'


def is_valid_path_segment_char(c):
    if 'a' <= c <= 'z':
        return True
    if 'A' <= c <= 'Z':
        return True
    if '0' <= c <= '9':
        return True
    return c == '-' or c == '.' or c == '_'


# Validates that a path string is a conformant path for a SPIFFE ID.
# See https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
def validate_path(path):
    if not path:
        raise ArgumentError(EMPTY)

    segment_start = 0
    segment_end = 0

    while segment_end < len(path):
        c = path[segment_end]
        if c == '/':
            sub = path[segment_start:segment_end]
            if sub == '/':
                raise SpiffeIdError(EMPTY_SEGMENT)
            if sub == '/.' or sub == '/..':
                raise SpiffeIdError(DOT_SEGMENT)
            segment_start = segment_end
            segment_end += 1
            continue

        if not is_valid_path_segment_char(c):
            raise SpiffeIdError(BAD_PATH_SEGMENT_CHAR)

        segment_end += 1

    sub = path[segment_start:segment_end]
    if sub == '/':
        raise SpiffeIdError(TRAILING_SLASH)
    if sub == '/.' or sub == '/..':
        raise SpiffeIdError(DOT_SEGMENT)
