import os
import ipaddress
from urllib.parse import ParseResult, urlparse
from typing import Dict, List, Tuple


SPIFFE_ENDPOINT_SOCKET = 'SPIFFE_ENDPOINT_SOCKET'


class ConfigSetter:
    """
    Loads and validates configuration variables from the environment

    Raises:
        ValueError: if any variable from the environment has an invalid format
    """

    FORBIDDEN_SOCKET_COMPONENTS = [
        ('fragment', None),
        ('username', None),
        ('password', None),
        ('query', None),
    ]

    UNIX_FORBIDDEN_SOCKET_COMPONENTS = FORBIDDEN_SOCKET_COMPONENTS + [
        ('netloc', 'authority')
    ]

    TCP_FORBIDDEN_SOCKET_COMPONENTS = FORBIDDEN_SOCKET_COMPONENTS + [('path', None)]

    def __init__(self):
        self._apply_default_config()
        self._apply_environment_variables()

    def get_config(self) -> Dict:
        return self._config

    def _apply_default_config(self) -> None:
        self._config = {
            SPIFFE_ENDPOINT_SOCKET: None,
        }

    def _apply_environment_variables(self) -> None:
        endpoint_socket = os.environ.get(SPIFFE_ENDPOINT_SOCKET)

        if endpoint_socket:
            self._validate(endpoint_socket)
            self._config[SPIFFE_ENDPOINT_SOCKET] = endpoint_socket

    def _validate(self, socket: str) -> None:
        parsed_socket = urlparse(socket)

        if not parsed_socket.scheme:
            raise ValueError('SPIFFE endpoint socket: scheme must be set.')

        if parsed_socket.scheme == 'unix':
            self._validate_unix_socket(parsed_socket)
        elif parsed_socket.scheme == 'tcp':
            self._validate_tcp_socket(parsed_socket)
        else:
            raise ValueError('SPIFFE endpoint socket: unsupported scheme.')

    @classmethod
    def _validate_unix_socket(cls, socket: ParseResult) -> None:
        if not socket.path:
            raise ValueError('SPIFFE endpoint socket: path must be set.')

        cls._validate_forbidden_components(socket, cls.UNIX_FORBIDDEN_SOCKET_COMPONENTS)

    @classmethod
    def _validate_tcp_socket(cls, socket: ParseResult) -> None:
        try:
            ipaddress.ip_address(socket.hostname)
        except:
            raise ValueError('SPIFFE endpoint socket: host must be an IP address.')

        cls._validate_forbidden_components(socket, cls.TCP_FORBIDDEN_SOCKET_COMPONENTS)

    @classmethod
    def _validate_forbidden_components(
        cls, socket: ParseResult, components: List[Tuple[str, str]]
    ) -> None:
        for component, description in components:
            try:
                attr = getattr(socket, component)
                if attr is not None and attr != '':
                    raise ValueError(
                        'SPIFFE endpoint socket: {} is not allowed.'.format(
                            description or component
                        )
                    )
            except AttributeError:
                pass
