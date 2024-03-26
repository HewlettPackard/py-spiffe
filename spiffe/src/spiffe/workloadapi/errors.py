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
This module defines Workload API exceptions.
"""

from spiffe.errors import PySpiffeError


class WorkloadApiError(PySpiffeError):
    """Exception for errors related to the Workload API."""


class FetchX509SvidError(WorkloadApiError):
    """Error raised when fetching X.509 SVIDs fails."""

    def __init__(self, detail: str) -> None:
        super().__init__(f'Error fetching X.509 SVID: {detail}')


class FetchX509BundleError(WorkloadApiError):
    """Error raised during X.509 Bundle fetching."""

    def __init__(self, detail: str) -> None:
        super().__init__(f'Error fetching X.509 Bundle: {detail}')


class FetchJwtSvidError(WorkloadApiError):
    """Error raised during JWT SVID fetching."""

    def __init__(self, detail: str = 'none') -> None:
        super().__init__(f'Error fetching JWT SVID: {detail}')


class FetchJwtBundleError(WorkloadApiError):
    """Error raised during JWT Bundle fetching."""

    def __init__(self, detail: str = 'none') -> None:
        super().__init__(f'Error fetching JWT Bundle: {detail}')


class ValidateJwtSvidError(WorkloadApiError):
    """Error raised when validating a JWT-SVID fails."""

    def __init__(self, detail: str = 'none') -> None:
        super().__init__(f'JWT SVID is not valid: {detail}')


class X509SourceError(WorkloadApiError):
    """Error related to the X.509 Source."""

    def __init__(self, detail: str) -> None:
        super().__init__(f'X.509 Source error: {detail}')


class JwtSourceError(WorkloadApiError):
    """Error related to the JWT Source."""

    def __init__(self, detail: str) -> None:
        super().__init__(f'JWT Source error: {detail}')
