from src.pyspiffe.exceptions import JwtBundleNotFoundError


class JwtBundle(object):
    def __init__(self):
        self.jwt_authorities = {}

    def findJwtAuthority(self, key_id: str) -> str:
        key = self.jwt_authorities.get(key_id)
        if key is not None:
            return key
        """there should be an exception here"""
        return None
