from pyspiffe.exceptions import PySpiffeError


class X509CertificateError(PySpiffeError):
    """Error raised when there is a problem processing an X.509 certificate."""

    def __init__(self, message: str) -> None:
        """Creates an instance of X509CertificateError.

        Args:
            message: Message describing the error.
        """

        super().__init__(message)

    def __str__(self) -> str:
        return self.message
