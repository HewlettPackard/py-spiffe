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
from typing import Any


def read_file_bytes(filename):
    with open(filename, 'rb') as file:
        return file.read()


class FakeCall(grpc.Call, grpc.RpcError):
    def __init__(self):
        self._code = grpc.StatusCode.UNKNOWN
        self._details = 'Error details from Workload API'

    def code(self):
        return self._code

    def details(self):
        return self._details


class ResponseHolder:
    """Helper class to be used in test cases for watch methods."""

    def __init__(self):
        self.error = None
        self.success = None


def handle_success(
    response: Any, response_holder: ResponseHolder, event: threading.Event
):
    """Helper method to store a response when running tests for watch methods."""

    response_holder.success = response
    event.set()


def handle_error(
    error: Exception, response_holder: ResponseHolder, event: threading.Event
):
    """Helper method to store an error when running tests for watch methods."""

    response_holder.error = error
    event.set()


def assert_error(error: Exception, expected: Exception):
    """Helper method to assert errors raised when running test for watch methods."""

    assert isinstance(error, type(expected))
    assert str(error) == str(expected)
