""""
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
import pytest

from pyspiffe.exceptions import ArgumentError
from pyspiffe.workloadapi.default_workload_api_client import DefaultWorkloadApiClient

SPIFFE_SOCKET_ENV = 'SPIFFE_ENDPOINT_SOCKET'
WORKLOAD_API_CLIENT = DefaultWorkloadApiClient('unix:///dummy.path')


# No SPIFFE_ENDPOINT_SOCKET, and no path passed, raises exception
def test_instantiate_default_without_var():
    with pytest.raises(ArgumentError) as exception:
        DefaultWorkloadApiClient(None)

    assert (
        str(exception.value)
        == 'Invalid DefaultWorkloadApiClient configuration: SPIFFE endpoint socket: socket must be set.'
    )


# With SPIFFE_ENDPOINT_SOCKET, and no path passed, succeeds
def test_instantiate_default_with_var():
    os.environ[SPIFFE_SOCKET_ENV] = 'unix:///tmp/agent.sock'
    wlapi = DefaultWorkloadApiClient(None)
    del os.environ[SPIFFE_SOCKET_ENV]
    assert wlapi.get_spiffe_endpoint_socket() == 'unix:///tmp/agent.sock'


# Pass socket path
def test_instantiate_socket_path():
    wlapi = DefaultWorkloadApiClient(spiffe_socket='unix:///tmp/agent.sock')
    assert wlapi.get_spiffe_endpoint_socket() == 'unix:///tmp/agent.sock'


# With bad SPIFFE_ENDPOINT_SOCKET, and no path passed, throws exception
def test_instantiate_default_with_bad_var():
    os.environ[SPIFFE_SOCKET_ENV] = '/invalid'
    with pytest.raises(ArgumentError) as exception:
        DefaultWorkloadApiClient(None)

    assert (
        str(exception.value)
        == 'Invalid DefaultWorkloadApiClient configuration: SPIFFE endpoint socket: scheme must be set.'
    )
    del os.environ[SPIFFE_SOCKET_ENV]


# With bad socket path passed
def test_instantiate_bad_socket_path():
    with pytest.raises(ArgumentError) as exception:
        DefaultWorkloadApiClient(spiffe_socket='/invalid')

    assert (
        str(exception.value)
        == 'Invalid DefaultWorkloadApiClient configuration: SPIFFE endpoint socket: scheme must be set.'
    )


# Utility functions
def get_client():
    return DefaultWorkloadApiClient(spiffe_socket='unix:///tmp/agent.sock')
