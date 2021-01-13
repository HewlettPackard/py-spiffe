import pytest
from pyspiffe.config import ConfigSetter
import os


def test_create():
    setter = ConfigSetter()

    assert setter != None


def test_default_values():
    setter = ConfigSetter()

    assert setter.get_config()['SPIFFE_ENDPOINT_SOCKET'] == None


def test_read_value_from_environment_variables():
    fake_socket = 'unix:///path/to/endpoint.sock'
    os.environ['SPIFFE_ENDPOINT_SOCKET'] = fake_socket

    setter = ConfigSetter()
    del os.environ['SPIFFE_ENDPOINT_SOCKET']

    assert setter.get_config()['SPIFFE_ENDPOINT_SOCKET'] == fake_socket


# Path Validation tests
def test_path_scheme_is_valid_unix():
    fake_socket = 'unix:///path/to/endpoint.sock'
    os.environ['SPIFFE_ENDPOINT_SOCKET'] = fake_socket

    setter = ConfigSetter()

    assert setter.get_config()['SPIFFE_ENDPOINT_SOCKET'] == fake_socket


def test_path_scheme_is_valid_tcp():
    fake_socket = 'tcp://127.0.0.1:8000'
    os.environ['SPIFFE_ENDPOINT_SOCKET'] = fake_socket

    setter = ConfigSetter()

    assert setter.get_config()['SPIFFE_ENDPOINT_SOCKET'] == fake_socket


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
def test_invalid_endpoint_socket(test_input, expected):
    with pytest.raises(ValueError) as exception:
        os.environ['SPIFFE_ENDPOINT_SOCKET'] = test_input
        ConfigSetter()

    assert str(exception.value) == expected
