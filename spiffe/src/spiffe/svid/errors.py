"""
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

from spiffe.errors import PySpiffeError


class JwtSvidError(PySpiffeError):
    """Exception raised for JWT SVID related errors."""


class InvalidTokenError(JwtSvidError):
    """Error raised when provided token is invalid."""


class InvalidClaimError(JwtSvidError):
    """Error raised for invalid values in JWT token claims."""

    def __init__(self, claim: str) -> None:
        super().__init__(f'Invalid claim value: {claim}')


class MissingClaimError(JwtSvidError):
    """Error raised for missing required claims in the JWT token."""

    def __init__(self, claim: str) -> None:
        super().__init__(f'Missing required claim: {claim}')


class TokenExpiredError(JwtSvidError):
    """Raised when the JWT token is expired."""

    def __init__(self) -> None:
        super().__init__('Token has expired.')


class InvalidAlgorithmError(JwtSvidError):
    """Error raised for invalid algorithms in JWT token."""

    def __init__(self, algorithm: str) -> None:
        super().__init__(f'Algorithm not supported: {algorithm}')


class InvalidTypeError(JwtSvidError):
    """Error raised for invalid types in JWT token."""

    def __init__(self, token_type: str) -> None:
        super().__init__(f'Token type not supported: {token_type}')


class X509SvidError(PySpiffeError):
    """Exception raised for X.509 SVID related errors."""


class InvalidLeafCertificateError(X509SvidError):
    """Error raised for invalid leaf certificates in X.509 chain."""

    def __init__(self, additional_information: str) -> None:
        super().__init__(f'Invalid leaf certificate: {additional_information}')


class InvalidIntermediateCertificateError(X509SvidError):
    """Error raised for invalid intermediate certificates in X.509 chain."""

    def __init__(self, additional_information: str) -> None:
        super().__init__(f'Invalid intermediate certificate: {additional_information}')
