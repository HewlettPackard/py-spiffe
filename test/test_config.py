import os
import pytest
from pyspiffe.config import ConfigSetter
from pyspiffe.exceptions import ArgumentError


@pytest.fixture(autouse=True)
def restore_env_vars():
    env_vars = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(env_vars)


def test_socket_must_be_set():
    with pytest.raises(ArgumentError) as exception:
        ConfigSetter(None)

    assert str(exception.value) == 'SPIFFE endpoint socket: socket must be set.'


def test_pass_socket_as_parameter():
    fake_socket = 'unix:///path/to/endpoint.sock'
    setter = ConfigSetter(spiffe_endpoint_socket=fake_socket)

    assert setter.get_config().spiffe_endpoint_socket == fake_socket


def test_read_socket_from_environment_variables():
    fake_socket = 'unix:///path/to/endpoint.sock'
    os.environ['SPIFFE_ENDPOINT_SOCKET'] = fake_socket

    setter = ConfigSetter(None)

    assert setter.get_config().spiffe_endpoint_socket == fake_socket


def test_socket_parameter_preponderance_over_environment_variable():
    fake_socket = 'unix:///path/to/endpoint.sock'
    os.environ['SPIFFE_ENDPOINT_SOCKET'] = 'env_var_socket'

    setter = ConfigSetter(spiffe_endpoint_socket=fake_socket)

    assert setter.get_config().spiffe_endpoint_socket == fake_socket


def test_path_scheme_is_valid_unix():
    fake_socket = 'unix:///path/to/endpoint.sock'

    setter = ConfigSetter(spiffe_endpoint_socket=fake_socket)

    assert setter.get_config().spiffe_endpoint_socket == fake_socket


def test_path_scheme_is_valid_tcp():
    fake_socket = 'tcp://127.0.0.1:8000'

    setter = ConfigSetter(spiffe_endpoint_socket=fake_socket)

    assert setter.get_config().spiffe_endpoint_socket == fake_socket


@pytest.mark.parametrize(
    'test_input,expected',
    [
        (
            'invalid-socket',
            'SPIFFE endpoint socket: scheme must be set.',
        ),
        (
            'http://example.org',
            'SPIFFE endpoint socket: unsupported scheme.',
        ),
        (
            'spiffe://example.org',
            'SPIFFE endpoint socket: unsupported scheme.',
        ),
        (
            'unix://example.org',
            'SPIFFE endpoint socket: path must be set.',
        ),
        (
            'unix://authority/path/to/socket',
            'SPIFFE endpoint socket: authority is not allowed.',
        ),
        (
            'unix://authority:8000/path/to/socket',
            'SPIFFE endpoint socket: authority is not allowed.',
        ),
        (
            'unix:///path/to/socket?query=true',
            'SPIFFE endpoint socket: query is not allowed.',
        ),
        (
            'unix:///path/to/socket?#fragment',
            'SPIFFE endpoint socket: fragment is not allowed.',
        ),
        (
            'unix://user:@/path/to/socket',
            'SPIFFE endpoint socket: username is not allowed.',
        ),
        (
            'unix://:pass@/path/to/socket',
            'SPIFFE endpoint socket: password is not allowed.',
        ),
        (
            'tcp://localhost:8000',
            'SPIFFE endpoint socket: host must be an IP address.',
        ),
        (
            'tcp://127.0.0.1:8000/path',
            'SPIFFE endpoint socket: path is not allowed.',
        ),
        (
            'tcp://127.0.0.1?query=true',
            'SPIFFE endpoint socket: query is not allowed.',
        ),
        (
            'tcp://127.0.0.1?#fragment',
            'SPIFFE endpoint socket: fragment is not allowed.',
        ),
        (
            'tcp://user:@192.168.0.100',
            'SPIFFE endpoint socket: username is not allowed.',
        ),
        (
            'tcp://:pass@192.168.0.100',
            'SPIFFE endpoint socket: password is not allowed.',
        ),
    ],
)
def test_invalid_endpoint_socket(test_input, expected):
    with pytest.raises(ArgumentError) as exception:
        ConfigSetter(spiffe_endpoint_socket=test_input)

    assert str(exception.value) == expected
