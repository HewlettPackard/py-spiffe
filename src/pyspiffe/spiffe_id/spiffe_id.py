from typing import Any

from pyspiffe.spiffe_id import SPIFFE_SCHEME
from pyspiffe.spiffe_id.trust_domain import TrustDomain

from rfc3987 import parse

SPIFFE_ID_MAXIMUM_LENGTH = 2048


class SpiffeId(object):
    """
    Represents a SPIFFE ID
    as defined in the `SPIFFE standard <https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md>`
    """

    @classmethod
    def parse(cls, spiffe_id: str):
        """Parses a SPIFFE ID from a string into a SpiffeId type instance.

        Args:
            spiffe_id: a string representing the SPIFFE ID

        Returns:
            an instance of a compliant SPIFFE ID (SpiffeId type)

        Raises:
            ValueError: if the string spiffe_id doesn't comply the the SPIFFE standard.

        Examples:
            >>> spiffe_id = SpiffeId.parse('spiffe://domain.test/path/element')
            >>> print(spiffe_id.trust_domain())
            domain.test
            >>> print(spiffe_id.path())
            /path/element
        """

        if spiffe_id == '' or spiffe_id is None:
            raise ValueError('SPIFFE ID cannot be empty.')

        uri = cls.parse_and_validate_uri(spiffe_id)

        result = SpiffeId()
        result.__set_path(uri.get('path'))
        result.__set_trust_domain(TrustDomain(uri.get('authority')))
        return result

    @classmethod
    def of(cls, trust_domain: TrustDomain, path_segments=None):
        """Creates SpiffeId type instance from a Trust Domain and zero or more paths.

        Args:
            trust_domain(TrustDomain): The trust domain corresponds to the trust root of a system.
            path_segments (optional): can be a single string or a list of path segments

        Returns:
            an instance of a compliant SPIFFE ID (SpiffeId type)

        Raises:
            ValueError: if the trust_domain is None or is not instance of the class TrustDomain.

        Examples:
            >>> spiffe_id_1 = SpiffeId.of(TrustDomain('example.org'), 'path')
            >>> print(spiffe_id_1)
            spiffe://example.org/path

            an array of paths:
            >>> spiffe_id_2 = SpiffeId.of(TrustDomain('example.org'), ['path1', 'path2', 'element'])
            >>> print(spiffe_id_2)
            spiffe://example.org/path1/path2/element
        """

        if trust_domain is None:
            raise ValueError('SPIFFE ID: trust domain cannot be empty.')

        result = SpiffeId()
        if isinstance(trust_domain, TrustDomain):
            result.__set_trust_domain(trust_domain)
        else:
            raise ValueError(
                'SPIFFE ID: trust_domain argument must be a TrustDomain instance.'
            )

        if path_segments is not None:
            result.__set_path(path_segments)

        cls.parse_and_validate_uri(str(result))
        return result

    def __eq__(self, other: Any):
        if isinstance(other, self.__class__):
            return (
                self.__trust_domain == other.__trust_domain
                and self.__path == other.path()
            )

    def __str__(self):
        if self.__path is not None:
            return '{}://{}{}'.format(
                SPIFFE_SCHEME, self.__trust_domain.name(), self.__path
            )
        else:
            return '{}://{}'.format(SPIFFE_SCHEME, self.__trust_domain.name())

    # path_segments can be an array of path segments or a single string representing a path
    def __set_path(self, path: Any):
        if isinstance(path, list):
            self.__path = ''
            for s in path:
                self.__path += self.normalize_path(s)
        else:
            self.__path = self.normalize_path(path)

    def __set_trust_domain(self, trust_domain: TrustDomain):
        self.__trust_domain = trust_domain

    def path(self):
        return self.__path

    def trust_domain(self):
        return self.__trust_domain

    @classmethod
    def parse_and_validate_uri(cls, spiffe_id: str):
        if len(spiffe_id) > SPIFFE_ID_MAXIMUM_LENGTH:
            raise ValueError(
                'SPIFFE ID: maximum length is {} bytes.'.format(
                    SPIFFE_ID_MAXIMUM_LENGTH
                )
            )

        uri = parse(spiffe_id.strip(), rule='URI')

        scheme = uri.get('scheme')
        if not scheme.lower() == SPIFFE_SCHEME:
            raise ValueError('SPIFFE ID: invalid scheme: expected spiffe.')

        query = uri.get('query')
        if query is not None and not query == '':
            raise ValueError('SPIFFE ID: query is not allowed.')

        fragment = uri.get('fragment')
        if fragment is not None and not fragment == '':
            raise ValueError('SPIFFE ID: fragment is not allowed.')

        authority = uri.get('authority')
        if authority == '' or authority is None:
            raise ValueError('SPIFFE ID: trust domain cannot be empty.')

        # has user@info:
        if '@' in authority:
            raise ValueError('SPIFFE ID: user info is not allowed.')

        # has domain:port
        if ':' in authority:
            raise ValueError('SPIFFE ID: port is not allowed.')

        return uri

    @staticmethod
    def normalize_path(path: str):
        path = path.strip()
        if path and not path.startswith('/'):
            return '/' + path
        return path
