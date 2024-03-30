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

from typing import Optional

from spiffe.errors import PySpiffeError


class SslContextError(PySpiffeError):
    """
    Represents errors that occur during SSL context configuration.

    Attributes:
        detail (str): Detailed error message.
        cause (Exception, optional): The original exception that caused this error.
    """

    def __init__(self, detail: str, cause: Optional[Exception] = None) -> None:
        message = f"SSL context configuration failed: {detail}"
        if cause:
            message += f". Cause: {cause}"
        super().__init__(message)
        self.cause = cause


class TLSConnectionError(PySpiffeError):
    """Exception raised for errors during TLS connection setup."""

    def __init__(self, message, **context):
        super().__init__(message)
        self.context = context


class ListenError(Exception):
    """Exception raised when a listening socket cannot be created."""

    def __init__(self, host, port, original_error):
        self.host = host
        self.port = port
        self.original_error = original_error
        message = (
            f"Failed to create listening socket on {host}:{port}: {original_error}"
        )
        super().__init__(message)
