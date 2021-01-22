class PySpiffeError(Exception):
    pass


class JwtSvidError(PySpiffeError):
    pass


class JwtBundleNotFoundError(PySpiffeError):
    pass
