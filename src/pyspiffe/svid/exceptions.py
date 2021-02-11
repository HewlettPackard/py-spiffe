"""
This module defines SVID exceptions.
"""

from pyspiffe.exceptions import PySpiffeError

INVALID_VALUE_ERROR = '{} is not supported.'
"""str: not supported error message."""


class JwtSvidError(PySpiffeError):
    """Top level exception for JwtSvid module.

    Attributes:
        message: message describing the error.
    """

    def __init__(self, message: str) -> None:
        """Creates an instance of JwtSvidError.

        Args:
            message: message describing the error.
        """

        self.message = message

    def __str__(self) -> str:
        return self.message


class InvalidTokenError(JwtSvidError):
    """Error raised when provided token is invalid."""

    def __init__(self, message: str = '') -> None:
        """Creates an instace of InvalidTokenError adding the provided message to the error mesage.

        Args:
            message: contains additional information about the error.
        """
        super().__init__(message)


class InvalidClaimError(JwtSvidError):
    """Error raised when an invalid value is found in the JWT token claims (e.g  missing required claims, invalid claims values, etc)."""

    _MESSAGE = 'Invalid claim value: {}.'

    def __init__(self, additional_information: str = '') -> None:
        """Creates an instace of InvalidClaimError adding the provided additional_information to the error mesage.

        Args:
            additional_information: contains additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


class TokenExpiredError(JwtSvidError):
    """Raised when the JWT token is expired."""

    _MESSAGE = 'Token has expired.'

    def __init__(self) -> None:
        """Creates an instance of TokenExpiredError"""
        super().__init__(self._MESSAGE)


class InvalidAlgorithmError(JwtSvidError):
    """Error raised when an invalid value is found in the JWT token's algorithm field."""

    _MESSAGE = INVALID_VALUE_ERROR

    def __init__(self, additional_information: str = '') -> None:
        """Creates an instance of InvalidAlgorithmError

        Args:
            additional_information: additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


class InvalidTypeError(JwtSvidError):
    """Error raised when an invalid value is found in the JWT token's type field."""

    _MESSAGE = INVALID_VALUE_ERROR

    def __init__(self, additional_information: str = '') -> None:
        """Creates an instance of InvalidTypeError

        Args:
            additional_information: additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))
