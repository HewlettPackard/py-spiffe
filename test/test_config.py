from src.pyspiffe.config import ConfigSetter
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
