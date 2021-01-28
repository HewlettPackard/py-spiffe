from pyspiffe.bundle.jwt_bundle.exceptions import JwtBundleNotFoundError


class JwtBundle(object):
    """
    Represents a JWT Bundle .

    """

    def __init__(self) -> None:
        self.jwt_authorities = {}

    """
        Returns the authority for the specified key_id.
        Raises
            JwtBundleNotFoundError  when no authority is found for the given key_id.
    """

    def findJwtAuthority(self, key_id: str) -> str:
        key = self.jwt_authorities.get(key_id)
        if not key:
            raise JwtBundleNotFoundError(key_id)

        return key
