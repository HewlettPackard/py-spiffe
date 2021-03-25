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

    def __init__(self, message: str = '') -> None:
        """Creates an instance of FetchX509SvidError adding the provided message to the error message.

        Args:
            message: Contains additional information about the error.
        """
        super().__init__(message)
