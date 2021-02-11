from pyspiffe.bundle.jwt_bundle.exceptions import JwtBundleNotFoundError


class JwtBundle(object):
    """Represents a JWT Bundle."""

    def __init__(self) -> None:
        """Creates an instance of JwtBundle.
        TODO: complete

        """
        pass
        # self.jwt_authorities = {}

    def findJwtAuthority(self, key_id: str) -> str:
        """Returns the authority for the specified key_id.
            TODO: complete

        Args:
            key_id: key of the token to return the correspondent bundle.

        Returns:
            TBD

        Raises
            JwtBundleNotFoundError:  when no authority is found for the given key_id.
        """
        # key = self.jwt_authorities.get(key_id)
        key = ''
        if not key:
            raise JwtBundleNotFoundError(key_id)

        return key
