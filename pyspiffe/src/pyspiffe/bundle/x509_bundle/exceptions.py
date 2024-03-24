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

from pyspiffe.exceptions import PySpiffeError


class X509BundleError(PySpiffeError):
    """Top level exception for the X509Bundle module."""

    def __init__(self, message: str) -> None:
        """Creates an instance of X509BundleError.

        Args:
            message: Message describing the error.
        """

        super().__init__(message)

    def __str__(self) -> str:
        return self.message


class ParseX509BundleError(X509BundleError):
    """Error raised when an X.509 bundle could not be parsed from bytes."""

    _MESSAGE = 'Error parsing X.509 bundle: {}'

    def __init__(self, additional_information: str) -> None:
        """Creates an instance of ParseX509BundleError.

        Args:
            additional_information: Additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


class LoadX509BundleError(X509BundleError):
    """Error raised when an X.509 bundle could not be loaded from file."""

    _MESSAGE = 'Error loading X.509 bundle: {}'

    def __init__(self, additional_information: str) -> None:
        """Creates an instance of LoadX509BundleError.

        Args:
            additional_information: Additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))


class SaveX509BundleError(X509BundleError):
    """Error raised when an X.509 bundle could not be save to file."""

    _MESSAGE = 'Error saving X.509 bundle: {}'

    def __init__(self, additional_information: str) -> None:
        """Creates an instance of SaveX509BundleError.

        Args:
            additional_information: Additional information about the error.
        """
        super().__init__(self._MESSAGE.format(additional_information))
