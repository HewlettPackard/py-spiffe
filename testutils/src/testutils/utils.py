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

import grpc
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Generic, TypeVar

_T = TypeVar('_T')


def read_file_bytes(filename: Path | str) -> bytes:
    with open(filename, 'rb') as file:
        return file.read()


class FakeCall(grpc.Call, grpc.RpcError):
    def __init__(self) -> None:
        self._code = grpc.StatusCode.UNKNOWN
        self._details = 'Error details from Workload API'

    def is_active(self) -> bool:
        return False

    def time_remaining(self) -> float:
        return 0.0


    def cancel(self) -> bool:
        return False

    def add_callback(self, callback: Callable[[], None]) -> bool:
        del callback
        return False

    def initial_metadata(self) -> tuple[()]:
        return ()

    def trailing_metadata(self) -> tuple[()]:
        return ()

    def code(self) -> grpc.StatusCode:
        return self._code

    def details(self) -> str:
        return self._details


class ResponseHolder(Generic[_T]):
    """Helper class to be used in test cases for watch methods."""

    def __init__(self) -> None:
        self.error: Exception | None = None
        self.success: _T | None = None


def handle_success(
    response: _T, response_holder: ResponseHolder[_T], event: threading.Event
) -> None:
    """Helper method to store a response when running tests for watch methods."""

    response_holder.success = response
    event.set()


def handle_error(
    error: Exception, response_holder: ResponseHolder, event: threading.Event
) -> None:
    """Helper method to store an error when running tests for watch methods."""

    response_holder.error = error
    event.set()


def assert_error(error: Exception, expected: Exception) -> None:
    """Helper method to assert errors raised when running test for watch methods."""

    assert isinstance(error, type(expected))
    assert str(error) == str(expected)
