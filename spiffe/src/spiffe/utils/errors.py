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

from spiffe.errors import PySpiffeError


class X509CertificateError(PySpiffeError):
    """Exception raised for issues related to X.509 certificate processing."""


class ParseCertificateError(X509CertificateError):
    """Error raised when unable to parse an X.509 certificate from bytes."""

    def __init__(self, detail: str) -> None:
        super().__init__(f'Error parsing certificate: {detail}')


class LoadCertificateError(X509CertificateError):
    """Error raised when an X.509 certificate cannot be loaded from disk."""

    def __init__(self, detail: str) -> None:
        super().__init__(f'Error loading certificate from file: {detail}')


class StoreCertificateError(X509CertificateError):
    """Error raised when an X.509 certificate cannot be saved to disk."""

    def __init__(self, detail: str) -> None:
        super().__init__(f'Error saving certificate to file: {detail}')


class ParsePrivateKeyError(X509CertificateError):
    """Error raised when unable to parse a private key from bytes."""

    def __init__(self, detail: str) -> None:
        super().__init__(f'Error parsing private key: {detail}')


class LoadPrivateKeyError(X509CertificateError):
    """Error raised when a private key cannot be loaded from disk."""

    def __init__(self, detail: str) -> None:
        super().__init__(f'Error loading private key from file: {detail}')


class StorePrivateKeyError(X509CertificateError):
    """Error raised when a private key cannot be saved to disk."""

    def __init__(self, detail: str) -> None:
        super().__init__(f'Error saving private key to file: {detail}')
