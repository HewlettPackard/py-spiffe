""""
(C) Copyright 2021 Hewlett Packard Enterprise Development LP

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

"""
This module defines SVID exceptions.
"""

from pyspiffe.exceptions import PySpiffeError

INVALID_VALUE_ERROR = '{} is not supported.'
"""str: not supported error message."""


class JwtSvidError(PySpiffeError):
    """Top level exception for JwtSvid module."""

    def __init__(self, message: str) -> None:
        """Creates an instance of JwtSvidError.

        Args:
            message: Message describing the error.
        """

        super().__init__(message)

    def __str__(self) -> str:
        return self.message


class InvalidTokenError(JwtSvidError):
    """Error raised when provided token is invalid."""

    def __init__(self, message: str = '') -> None:
        """Creates an instance of InvalidTokenError adding the provided message to the error message.

        Args:
            message: Contains additional information about the error.
        """
        super().__init__(message)


class InvalidClaimError(JwtSvidError):
    """Error raised when an invalid value is found in the JWT token claims."""

    _MESSAGE = 'Invalid claim value: {}'

    def __init__(self, additional_information: str) -> None:
        """Creates an instance of InvalidClaimError adding the provided additional_information to the error message.

        Args:
            additional_information: Contains additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


class MissingClaimError(JwtSvidError):
    """Error raised when missing required claims in the JWT token."""

    _MESSAGE = 'Missing required claim: {}'

    def __init__(self, additional_information: str) -> None:
        """Creates an instance of MissingClaimError adding the provided additional_information to the error message.

        Args:
            additional_information: Contains additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


class TokenExpiredError(JwtSvidError):
    """Raised when the JWT token is expired."""

    _MESSAGE = 'Token has expired.'

    def __init__(self) -> None:
        """Creates an instance of TokenExpiredError"""
        super().__init__(self._MESSAGE)


class InvalidAlgorithmError(JwtSvidError):
    """Error raised when an invalid value is found in the JWT token's algorithm field."""

    _MESSAGE = INVALID_VALUE_ERROR

    def __init__(self, additional_information: str) -> None:
        """Creates an instance of InvalidAlgorithmError

        Args:
            additional_information: Additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


class InvalidTypeError(JwtSvidError):
    """Error raised when an invalid value is found in the JWT token's type field."""

    _MESSAGE = INVALID_VALUE_ERROR

    def __init__(self, additional_information: str) -> None:
        """Creates an instance of InvalidTypeError

        Args:
            additional_information: Additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


class X509SvidError(PySpiffeError):
    """Top level exception for the X509Svid module."""

    def __init__(self, message: str) -> None:
        """Creates an instance of X509SvidError.

        Args:
            message: Message describing the error.
        """

        super().__init__(message)

    def __str__(self) -> str:
        return self.message


class InvalidLeafCertificateError(X509SvidError):
    """Error raised when an invalid leaf certificate is found in the X.509 chain."""

    _MESSAGE = 'Invalid leaf certificate: {}'

    def __init__(self, additional_information: str) -> None:
        """Creates an instance of InvalidLeafCertificateError

        Args:
            additional_information: Additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


class InvalidIntermediateCertificateError(X509SvidError):
    """Error raised when an invalid intermediate certificate is found in the X.509 chain."""

    _MESSAGE = 'Invalid intermediate certificate: {}'

    def __init__(self, additional_information: str) -> None:
        """Creates an instance of InvalidIntermediateCertificateError

        Args:
            additional_information: Additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))
