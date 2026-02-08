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

from collections.abc import Iterator

import os
import pytest
from spiffe.config import ConfigSetter, _SPIFFE_ENDPOINT_SOCKET
from spiffe.errors import ArgumentError


@pytest.fixture(autouse=True)
def restore_env_vars() -> Iterator[None]:
    env_vars = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(env_vars)


def test_socket_must_be_set(monkeypatch: pytest.MonkeyPatch) -> None:
    # Ensure the SPIFFE_ENDPOINT_SOCKET environment variable is unset
    monkeypatch.delenv(_SPIFFE_ENDPOINT_SOCKET, raising=False)

    with pytest.raises(ArgumentError) as exception:
        ConfigSetter(None)

    assert str(exception.value) == 'SPIFFE endpoint socket: socket must be set'


def test_pass_socket_as_parameter() -> None:
    fake_socket = 'unix:///path/to/endpoint.sock'
    setter = ConfigSetter(spiffe_endpoint_socket=fake_socket)

    assert setter.get_config().spiffe_endpoint_socket == fake_socket


def test_read_socket_from_environment_variables() -> None:
    fake_socket = 'unix:///path/to/endpoint.sock'
    os.environ['SPIFFE_ENDPOINT_SOCKET'] = fake_socket

    setter = ConfigSetter(None)

    assert setter.get_config().spiffe_endpoint_socket == fake_socket


def test_socket_parameter_preponderance_over_environment_variable() -> None:
    fake_socket = 'unix:///path/to/endpoint.sock'
    os.environ['SPIFFE_ENDPOINT_SOCKET'] = 'env_var_socket'

    setter = ConfigSetter(spiffe_endpoint_socket=fake_socket)

    assert setter.get_config().spiffe_endpoint_socket == fake_socket


def test_path_scheme_is_valid_unix() -> None:
    fake_socket = 'unix:///path/to/endpoint.sock'

    setter = ConfigSetter(spiffe_endpoint_socket=fake_socket)

    assert setter.get_config().spiffe_endpoint_socket == fake_socket


def test_path_scheme_is_valid_tcp() -> None:
    fake_socket = 'tcp://127.0.0.1:8000'

    setter = ConfigSetter(spiffe_endpoint_socket=fake_socket)

    assert setter.get_config().spiffe_endpoint_socket == fake_socket


@pytest.mark.parametrize(
    'test_input,expected',
    [
        (
            'invalid-socket',
            'SPIFFE endpoint socket: scheme must be set',
        ),
        (
            'http://example.org',
            'SPIFFE endpoint socket: unsupported scheme',
        ),
        (
            'spiffe://example.org',
            'SPIFFE endpoint socket: unsupported scheme',
        ),
        (
            'unix://example.org',
            'SPIFFE endpoint socket: path must be set',
        ),
        (
            'unix://authority/path/to/socket',
            'SPIFFE endpoint socket: authority is not allowed',
        ),
        (
            'unix://authority:8000/path/to/socket',
            'SPIFFE endpoint socket: authority is not allowed',
        ),
        (
            'unix:///path/to/socket?query=true',
            'SPIFFE endpoint socket: query is not allowed',
        ),
        (
            'unix:///path/to/socket?#fragment',
            'SPIFFE endpoint socket: fragment is not allowed',
        ),
        (
            'unix://user:@/path/to/socket',
            'SPIFFE endpoint socket: username is not allowed',
        ),
        (
            'unix://:pass@/path/to/socket',
            'SPIFFE endpoint socket: password is not allowed',
        ),
        (
            'tcp://localhost:8000',
            'SPIFFE endpoint socket: host must be an IP address',
        ),
        (
            'tcp://127.0.0.1:8000/path',
            'SPIFFE endpoint socket: path is not allowed',
        ),
        (
            'tcp://127.0.0.1?query=true',
            'SPIFFE endpoint socket: query is not allowed',
        ),
        (
            'tcp://127.0.0.1?#fragment',
            'SPIFFE endpoint socket: fragment is not allowed',
        ),
        (
            'tcp://user:@192.168.0.100',
            'SPIFFE endpoint socket: username is not allowed',
        ),
        (
            'tcp://:pass@192.168.0.100',
            'SPIFFE endpoint socket: password is not allowed',
        ),
    ],
)
def test_invalid_endpoint_socket(test_input: str, expected: str) -> None:
    with pytest.raises(ArgumentError) as exception:
        ConfigSetter(spiffe_endpoint_socket=test_input)

    assert str(exception.value) == expected
