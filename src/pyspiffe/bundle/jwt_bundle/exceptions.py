"""
This module handles JWT bundle exceptions.
"""
from pyspiffe.exceptions import PySpiffeError


class JwtBundleError(PySpiffeError):
    """Top level exception for the JwtBundle module. """

    def __init__(self, message: str) -> None:
        """Creates an instance of JwtBundleError.

        Args:
            message: Message describing the error.
        """

        super().__init__(message)

    def __str__(self) -> str:
        return self.message


class AuthorityNotFoundError(JwtBundleError):
    """Raised when an authority is not found associated with a key_id."""

    _MESSAGE = 'Key ({}) not found in authorities.'

    def __init__(self, key_id: str = 'not specified') -> None:
        """Creates an instance of AuthorityNotFoundError.

        Args:
            key_id: The key_id with no authority associated.
        """
        super().__init__(self._MESSAGE.format(key_id))

    def __str__(self) -> str:
        return self.message
