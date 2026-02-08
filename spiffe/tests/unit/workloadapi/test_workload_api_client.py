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

import os
from unittest.mock import patch

import pytest

from spiffe.errors import ArgumentError
from spiffe.workloadapi.workload_api_client import WorkloadApiClient

SPIFFE_SOCKET_ENV = 'SPIFFE_ENDPOINT_SOCKET'


# No SPIFFE_ENDPOINT_SOCKET, and no path passed, raises exception
def test_instantiate_default_without_var(monkeypatch: pytest.MonkeyPatch) -> None:
    # Ensure the SPIFFE_ENDPOINT_SOCKET environment variable is unset
    monkeypatch.delenv("SPIFFE_ENDPOINT_SOCKET", raising=False)
    with pytest.raises(ArgumentError) as exception:
        WorkloadApiClient(None)

    assert (
        str(exception.value)
        == 'Invalid WorkloadApiClient configuration: SPIFFE endpoint socket: socket must be set'
    )


# With SPIFFE_ENDPOINT_SOCKET, and no path passed, succeeds
def test_instantiate_default_with_var() -> None:
    os.environ[SPIFFE_SOCKET_ENV] = 'unix:///tmp/agent.sock'
    with patch.object(WorkloadApiClient, '_check_spiffe_socket_exists') as mock_check:
        mock_check.return_value = None
        wlapi = WorkloadApiClient(None)
        assert wlapi.get_spiffe_endpoint_socket() == 'unix:///tmp/agent.sock'

    del os.environ[SPIFFE_SOCKET_ENV]


# Pass socket path
def test_instantiate_socket_path() -> None:
    with patch.object(WorkloadApiClient, '_check_spiffe_socket_exists') as mock_check:
        mock_check.return_value = None
        wlapi = WorkloadApiClient(socket_path='unix:///tmp/agent.sock')
        assert wlapi.get_spiffe_endpoint_socket() == 'unix:///tmp/agent.sock'


# With bad SPIFFE_ENDPOINT_SOCKET, and no path passed, throws exception
def test_instantiate_default_with_bad_var() -> None:
    os.environ[SPIFFE_SOCKET_ENV] = '/invalid'
    with pytest.raises(ArgumentError) as exception:
        WorkloadApiClient(None)

    assert (
        str(exception.value)
        == 'Invalid WorkloadApiClient configuration: SPIFFE endpoint socket: scheme must be set'
    )
    del os.environ[SPIFFE_SOCKET_ENV]


def test_grpc_target_with_unix_prefix() -> None:
    """Test that socket path with 'unix:' prefix is normalized (unix:/// -> unix:/)."""
    assert WorkloadApiClient._grpc_target('unix:///tmp/agent.sock') == 'unix:/tmp/agent.sock'
    assert WorkloadApiClient._grpc_target('unix:/tmp/agent.sock') == 'unix:/tmp/agent.sock'


def test_grpc_target_without_unix_prefix() -> None:
    """Test that raw socket path is converted to 'unix:/path' for gRPC target."""
    assert WorkloadApiClient._grpc_target('/tmp/agent.sock') == 'unix:/tmp/agent.sock'


def test_strip_unix_scheme() -> None:
    """Test that unix scheme is stripped correctly for filesystem checks."""
    assert WorkloadApiClient._strip_unix_scheme('unix:///tmp/agent.sock') == '/tmp/agent.sock'
    assert WorkloadApiClient._strip_unix_scheme('/tmp/agent.sock') == '/tmp/agent.sock'


def test_grpc_target_rejects_non_unix() -> None:
    """Test that non-unix, non-path values are rejected."""
    with pytest.raises(ArgumentError):
        WorkloadApiClient._grpc_target('localhost:8081')
