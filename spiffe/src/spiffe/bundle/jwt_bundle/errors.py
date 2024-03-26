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
This module handles JWT bundle exceptions.
"""

from spiffe.errors import PySpiffeError


class JwtBundleError(PySpiffeError):
    """Exception raised for JwtBundle module related errors."""


class ParseJWTBundleError(JwtBundleError):
    """Error raised when unable to parse a JWT bundle from bytes."""

    def __init__(self, detail: str) -> None:
        super().__init__(f'Error parsing JWT bundle: {detail}')


class AuthorityNotFoundError(JwtBundleError):
    """Error raised when an authority is not found for a given key ID."""

    def __init__(self, key_id: str) -> None:
        super().__init__(f'Authority not found for key ID: {key_id}')
