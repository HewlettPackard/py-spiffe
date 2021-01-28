from pyspiffe.exceptions import PySpiffeError

INVALID_VALUE_ERROR = '{} is not supported.'


class JwtSvidError(PySpiffeError):
    def __init__(self, text: str) -> None:
        self.text = text

    def __str__(self) -> str:
        return self.text


class InvalidClaimError(JwtSvidError):
    _text = 'Invalid claim value: {}.'

    def __init__(self, complement_text: str) -> None:
        super().__init__(self._text.format(complement_text))


class TokenExpiredError(JwtSvidError):
    _text = 'Token has expired.'

    def __init__(self) -> None:
        super().__init__(self._text)


class InvalidAlgorithmError(JwtSvidError):
    _text = INVALID_VALUE_ERROR

    def __init__(self, complement_text: str) -> None:
        super().__init__(self._text.format(complement_text))


class InvalidTypeError(JwtSvidError):
    _text = INVALID_VALUE_ERROR

    def __init__(self, complement_text: str) -> None:
        super().__init__(self._text.format(complement_text))
