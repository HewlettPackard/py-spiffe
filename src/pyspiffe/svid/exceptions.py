from pyspiffe.exceptions import PySpiffeError

INVALID_VALUE_ERROR = '{} is not supported.'


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


class InvalidClaimError(JwtSvidError):
    """Raised when an invalid value is found in the JWT token claims (e.g  missing required claims, invalid claims values, etc).

    Attributes:
        _MESSAGE: error message describing the encountered error.

    """

    _MESSAGE = 'Invalid claim value: {}.'

    def __init__(self, additional_information: str) -> None:
        """Creates an instace of InvalidClaimError adding the provided additional_information to the error mesage.

        Args:
            additional_information: contains additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


class TokenExpiredError(JwtSvidError):
    """Raised when the JWT token is expired.

    Attributes:
        _text (str): error message describing the encountered error.

    """

    _text = 'Token has expired.'

    def __init__(self) -> None:
        super().__init__(self._text)


class InvalidAlgorithmError(JwtSvidError):
    """Raised when an invalid value is found in the JWT token's algorithm field.

    Args:
        complement_text (str): complementary text to be appended to the default error message.

    Attributes:
        _text (str): message describing the encountered error.

    """

    _text = INVALID_VALUE_ERROR

    def __init__(self, complement_text: str) -> None:
        super().__init__(self._text.format(complement_text))


class InvalidTypeError(JwtSvidError):
    """Raised when an invalid value is found in the JWT token's type field.

    Args:
        complement_text (str): complementary text to be appended to the default error message.

    Attributes:
        _text (str): message describing the encountered error.

    """

    _text = INVALID_VALUE_ERROR

    def __init__(self, complement_text: str) -> None:
        super().__init__(self._text.format(complement_text))
