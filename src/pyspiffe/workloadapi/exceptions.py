"""
This module defines Workload API exceptions.
"""

from pyspiffe.exceptions import PySpiffeError


class WorkloadApiError(PySpiffeError):
    """Top level exception for Workload API module. """

    def __init__(self, message: str) -> None:
        """Creates an instance of WorkloadApiError.

        Args:
            message: Message describing the error.
        """

        self.message = message

    def __str__(self) -> str:
        return self.message


class FetchX509SvidError(WorkloadApiError):
    """Error raised when there is an error fetching X.509 SVIDs."""

    def __init__(self, message: str) -> None:
        """Creates an instance of FetchX509SvidError.

        Args:
            message: Message describing the error.
        """
        super().__init__(message)


class FetchX509BundleError(WorkloadApiError):
    """Error raised when there is an error fetching X.509 Bundles."""

    def __init__(self, message: str) -> None:
        """Creates an instance of FetchX509BundleError.

        Args:
            message: Message describing the error.
        """
        super().__init__(message)
