import os
import pytest

from pyspiffe.workloadapi.default_workload_api_client import DefaultWorkloadApiClient

SPIFFE_SOCKET_ENV = 'SPIFFE_ENDPOINT_SOCKET'
WORKLOAD_API_CLIENT = DefaultWorkloadApiClient('unix:///dummy.path')


# No SPIFFE_ENDPOINT_SOCKET, and no path passed, raises exception
def test_instantiate_default_without_var():
    with pytest.raises(ValueError) as exception:
        DefaultWorkloadApiClient()

    assert (
        str(exception.value)
        == 'Invalid DefaultWorkloadApiClient configuration: SPIFFE endpoint socket: socket must be set.'
    )


# With SPIFFE_ENDPOINT_SOCKET, and no path passed, succeeds
def test_instantiate_default_with_var():
    os.environ[SPIFFE_SOCKET_ENV] = 'unix:///tmp/agent.sock'
    wlapi = DefaultWorkloadApiClient()
    del os.environ[SPIFFE_SOCKET_ENV]
    assert wlapi.get_spiffe_endpoint_socket() == 'unix:///tmp/agent.sock'


# Pass socket path
def test_instantiate_socket_path():
    wlapi = DefaultWorkloadApiClient(spiffe_socket='unix:///tmp/agent.sock')
    assert wlapi.get_spiffe_endpoint_socket() == 'unix:///tmp/agent.sock'


# With bad SPIFFE_ENDPOINT_SOCKET, and no path passed, throws exception
def test_instantiate_default_with_bad_var():
    os.environ[SPIFFE_SOCKET_ENV] = '/invalid'
    with pytest.raises(ValueError) as exception:
        DefaultWorkloadApiClient()

    assert (
        str(exception.value)
        == 'Invalid DefaultWorkloadApiClient configuration: SPIFFE endpoint socket: scheme must be set.'
    )
    del os.environ[SPIFFE_SOCKET_ENV]


# With bad socket path passed
def test_instantiate_bad_socket_path():
    with pytest.raises(ValueError) as exception:
        DefaultWorkloadApiClient(spiffe_socket='/invalid')

    assert (
        str(exception.value)
        == 'Invalid DefaultWorkloadApiClient configuration: SPIFFE endpoint socket: scheme must be set.'
    )


# Utility functions
def get_client():
    return DefaultWorkloadApiClient(spiffe_socket='unix:///tmp/agent.sock')
