"""
This module defines py-spiffe top level exceptions.
"""


class PySpiffeError(Exception):
    """Top level exception for py-spiffe library."""

    def __init__(self, message: str) -> None:
        """Creates an instance of WorkloadApiError.

        Args:
            message: Message describing the error.
        """

        self.message = message if message[-1] == '.' else message + '.'

    def __str__(self) -> str:
        return self.message


class ArgumentError(PySpiffeError):
    """Validation error for py-spiffe library."""

    def __init__(self, message: str) -> None:
        """Creates an instance of ArgumentError.

        Args:
            message: Message describing the error.
        """

        super().__init__(message)

    def __str__(self) -> str:
        return super().__str__()
