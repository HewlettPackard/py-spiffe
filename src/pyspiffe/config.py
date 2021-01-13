import os
import ipaddress
from urllib.parse import ParseResult, urlparse
from typing import Dict, List, Tuple


SPIFFE_ENDPOINT_SOCKET = 'SPIFFE_ENDPOINT_SOCKET'


class ConfigSetter:
    def __init__(self):
        self._apply_default_config()
        self._apply_environment_variables()

    def get_config(self) -> Dict:
        return self._config

    def _apply_default_config(self):
        self._config = {
            SPIFFE_ENDPOINT_SOCKET: None,
        }

    def _apply_environment_variables(self):
        endpoint_socket = os.environ.get(SPIFFE_ENDPOINT_SOCKET)

        if endpoint_socket is not None:
            SpiffeEndpointSocket.validate(endpoint_socket)
            self._config[SPIFFE_ENDPOINT_SOCKET] = endpoint_socket


class SpiffeEndpointSocket:
    @staticmethod
    def validate(socket: str):
        parsed_socket = urlparse(socket)

        if parsed_socket.scheme == '':
            raise ValueError('SPIFFE endpoint socket: scheme must be set')

        if parsed_socket.scheme == 'unix':
            SpiffeEndpointSocket.__validate_unix_socket(parsed_socket)
        elif parsed_socket.scheme == 'tcp':
            SpiffeEndpointSocket.__validate_tcp_socket(parsed_socket)
        else:
            raise ValueError('SPIFFE endpoint socket: unsupported scheme')

    @staticmethod
    def __validate_unix_socket(socket: ParseResult):
        if socket.path is None:
            raise ValueError('SPIFFE endpoint socket: path must be set')

        INVALID_COMPONENTS = [
            ('fragment', None),
            ('username', None),
            ('password', None),
            ('query', None),
            ('netloc', 'authority'),
        ]
        SpiffeEndpointSocket.__validate_forbidden_components(socket, INVALID_COMPONENTS)

    @staticmethod
    def __validate_tcp_socket(socket: ParseResult):
        try:
            ipaddress.ip_address(socket.hostname)
        except:
            raise ValueError('SPIFFE endpoint socket: host must be an IP address')

        INVALID_COMPONENTS = [
            ('path', None),
            ('fragment', None),
            ('username', None),
            ('password', None),
            ('query', None),
        ]
        SpiffeEndpointSocket.__validate_forbidden_components(socket, INVALID_COMPONENTS)

    @staticmethod
    def __validate_forbidden_components(
        socket: ParseResult, components: List[Tuple[str, str]]
    ):
        for component, description in components:
            try:
                attr = getattr(socket, component)
                if attr is not None and attr != '':
                    raise ValueError(
                        'SPIFFE endpoint socket: {} is not allowed'.format(
                            description or component
                        )
                    )
            except AttributeError:
                pass
