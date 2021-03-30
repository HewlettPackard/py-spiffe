from pyspiffe.exceptions import PySpiffeError


class X509CertificateError(PySpiffeError):
    """Error raised when there is a problem processing an X.509 certificate. """

    def __init__(self, message: str) -> None:
        """Creates an instance of X509CertificateError.

        Args:
            message: Message describing the error.
        """

        self.message = message

    def __str__(self) -> str:
        return self.message


def normalized_exception_message(e: Exception) -> str:
    """Removes the last point from the exception message."""

    msg = str(e)
    if msg[-1] != '.':
        return msg
    return msg[:-1]
