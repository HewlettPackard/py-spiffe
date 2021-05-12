"""
This module defines Workload API exceptions.
"""

from pyspiffe.exceptions import PySpiffeError


class WorkloadApiError(PySpiffeError):
    """Top level exception for Workload API module."""

    def __init__(self, message: str) -> None:
        """Creates an instance of WorkloadApiError.

        Args:
            message: Message describing the error.
        """

        super().__init__(message)

    def __str__(self) -> str:
        return self.message


class FetchX509SvidError(WorkloadApiError):
    """Error raised when there is an error fetching X.509 SVIDs."""

    _MESSAGE = 'Error fetching X.509 SVID: {}'

    def __init__(self, additional_information: str) -> None:
        """Creates an instance of FetchX509SvidError.

        Args:
            additional_information: Additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


class FetchX509BundleError(WorkloadApiError):
    """Error raised when there is an error fetching X.509 Bundles."""

    _MESSAGE = 'Error fetching X.509 Bundles: {}'

    def __init__(self, additional_information: str) -> None:
        """Creates an instance of FetchX509BundleError.

        Args:
            additional_information: Additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


class FetchJwtSvidError(WorkloadApiError):
    """Error raised when there is an error fetching JWT SVIDs."""

    _MESSAGE = 'Error fetching JWT SVID: {}'

    def __init__(self, additional_information: str = 'none') -> None:
        """Creates an instance of FetchJwtSvidError.

        Args:
            additional_information: Additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


class ValidateJwtSvidError(WorkloadApiError):
    """Error raised when a JWT-SVID cannot be validated by the Workload API."""

    _MESSAGE = 'JWT SVID is not valid: {}.'

    def __init__(self, additional_information: str = 'none') -> None:
        """Creates an instance of ValidateJwtSvidError.

        Args:
            additional_information: Additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


class X509SourceError(WorkloadApiError):
    """Error raised when there is an error in the X.509 Source."""

    _MESSAGE = 'X.509 Source error: {}.'

    def __init__(self, additional_information: str) -> None:
        """Creates an instance of X509SourceError.

        Args:
            additional_information: Additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))
