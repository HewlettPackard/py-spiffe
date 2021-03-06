"""
This module handles JWT bundle exceptions.
"""
from pyspiffe.exceptions import PySpiffeError


class AuthorityNotFoundError(PySpiffeError):
    """Raised when an authority is not found associated with a key_id.

    Attributes:
        message: message describing the error.
    """

    _MESSAGE = 'Key ({}) not found in authorities.'

    def __init__(self, key_id: str = "not specified") -> None:
        """Creates an instance of JwtSvidError.

        Args:
            key_id: the key_id with no authority associated.
        """
        self.message = self._MESSAGE.format(key_id)

    def __str__(self) -> str:
        return self.message
