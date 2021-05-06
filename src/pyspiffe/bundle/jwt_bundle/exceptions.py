"""
This module handles JWT bundle exceptions.
"""
from pyspiffe.exceptions import PySpiffeError


class JwtBundleError(PySpiffeError):
    """Top level exception for the JwtBundle module."""

    def __init__(self, message: str) -> None:
        """Creates an instance of JwtBundleError.

        Args:
            message: Message describing the error.
        """

        super().__init__(message)

    def __str__(self) -> str:
        return self.message


class ParseJWTBundleError(JwtBundleError):
    """Error raised when a JWT bundle could not be parsed from bytes."""

    _MESSAGE = 'Error parsing JWT bundle: {}'

    def __init__(self, additional_information: str) -> None:
        """Creates an instance of ParseJWTBundleError.

        Args:
            additional_information: Additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


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
