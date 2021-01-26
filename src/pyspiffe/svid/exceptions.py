from pyspiffe.exceptions import PySpiffeError


class JwtSvidError(PySpiffeError):
    pass


class InvalidClaimError(JwtSvidError):
    pass


class TokenExpiredError(JwtSvidError):
    pass


class UnsupportedAlgorithmError(JwtSvidError):
    pass


class UnsupportedTypeError(JwtSvidError):
    pass
