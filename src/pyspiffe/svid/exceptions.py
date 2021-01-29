from pyspiffe.exceptions import PySpiffeError

INVALID_VALUE_ERROR = '{} is not supported.'


class JwtSvidError(PySpiffeError):
    """Top level exception for JwtSvid module.

    Args:
        text (str): message describing the error.

    Attributes:
        text (str): message describing the error. This is the message to be returned when __str__ is called.

    """

    def __init__(self, text: str) -> None:
        self.text = text

    def __str__(self) -> str:
        return self.text


class InvalidClaimError(JwtSvidError):
    """Raised when an erronic value is found in the JWT token claims (e.g  missing required claims, invalid claims values, etc).

    Args:
        complement_text (str): complementary text to be appended to the default error message.

    Attributes:
        _text (str): error message describing the encountered error.

    """

    _text = 'Invalid claim value: {}.'

    def __init__(self, complement_text: str) -> None:
        super().__init__(self._text.format(complement_text))


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
