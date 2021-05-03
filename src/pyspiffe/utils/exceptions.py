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


class ParseCertificateError(X509CertificateError):
    """Error raised when an certificate could not be parsed from bytes."""

    def __init__(self, message: str) -> None:
        """Creates an instance of ParseCertificateError

        Args:
            message: Message describing the error.
        """
        super().__init__(message)


class LoadCertificateError(X509CertificateError):
    """Error raised when an certificate could not be loaded from disk."""

    _MESSAGE = 'Error loading certificate from file: {}'

    def __init__(self, additional_information: str) -> None:
        """Creates an instance of LoadCertificateError

        Args:
            additional_information: Additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


class StoreCertificateError(X509CertificateError):
    """Error raised when an certificate could not be saved to disk."""

    _MESSAGE = 'Error saving certificate to file: {}'

    def __init__(self, additional_information: str) -> None:
        """Creates an instance of StoreCertificateError

        Args:
            additional_information: Additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


class ParsePrivateKeyError(X509CertificateError):
    """Error raised when the private key could not be parsed from bytes."""

    _MESSAGE = 'Error parsing private key: {}'

    def __init__(self, additional_information: str) -> None:
        """Creates an instance of ParsePrivateKeyError

        Args:
            additional_information: Additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


class LoadPrivateKeyError(X509CertificateError):
    """Error raised when the private key could not be loaded from disk."""

    _MESSAGE = 'Error loading private key from file: {}'

    def __init__(self, additional_information: str) -> None:
        """Creates an instance of LoadPrivateKeyError

        Args:
            additional_information: Additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


class StorePrivateKeyError(X509CertificateError):
    """Error raised when the private key could not be saved to disk."""

    _MESSAGE = 'Error saving private key to file: {}'

    def __init__(self, additional_information: str) -> None:
        """Creates an instance of StorePrivateKeyError

        Args:
            additional_information: Additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))
