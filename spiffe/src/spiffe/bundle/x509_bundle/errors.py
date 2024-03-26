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
This module defines X.509 Bundle exceptions.
"""

from spiffe.errors import PySpiffeError


class X509BundleError(PySpiffeError):
    """Exception raised for X509Bundle module related errors."""


class ParseX509BundleError(X509BundleError):
    """Error raised when unable to parse an X.509 bundle from bytes."""

    def __init__(self, detail: str) -> None:
        super().__init__(f'Error parsing X.509 bundle: {detail}')


class LoadX509BundleError(X509BundleError):
    """Error raised when unable to load an X.509 bundle from a file."""

    def __init__(self, path: str) -> None:
        super().__init__(f'Error loading X.509 bundle from {path}')


class SaveX509BundleError(X509BundleError):
    """Error raised when unable to save an X.509 bundle to a file."""

    def __init__(self, path: str) -> None:
        super().__init__(f'Error saving X.509 bundle to {path}')
