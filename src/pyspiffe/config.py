import os
import ipaddress
from urllib.parse import ParseResult, urlparse
from typing import List, Tuple


SPIFFE_ENDPOINT_SOCKET = 'SPIFFE_ENDPOINT_SOCKET'


class Config:
    """
    Represents the configuration for a Workload API client
    """

    def __init__(self, spiffe_endpoint_socket: str):
        self.spiffe_endpoint_socket = spiffe_endpoint_socket


class ConfigSetter:
    """
    Loads and validates configuration variables

    Raises:
        ValueError: if any configuration variable has an invalid format
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

    def __init__(self, spiffe_endpoint_socket: str = None) -> None:
        self.__apply_default_config()
        self.__apply_environment_variables()

        if spiffe_endpoint_socket:
            self.__raw_config[SPIFFE_ENDPOINT_SOCKET] = spiffe_endpoint_socket

        self.__validate()
        self.__config = Config(
            spiffe_endpoint_socket=self.__raw_config[SPIFFE_ENDPOINT_SOCKET]
        )

    def get_config(self) -> Config:
        return self.__config

    def __apply_default_config(self) -> None:
        self.__raw_config = {
            SPIFFE_ENDPOINT_SOCKET: None,
        }

    def __apply_environment_variables(self) -> None:
        endpoint_socket = os.environ.get(SPIFFE_ENDPOINT_SOCKET)

        if endpoint_socket:
            self.__raw_config[SPIFFE_ENDPOINT_SOCKET] = endpoint_socket

    def __validate(self) -> None:
        endpoint_socket = self.__raw_config[SPIFFE_ENDPOINT_SOCKET]
        if not endpoint_socket:
            raise ValueError('SPIFFE endpoint socket: socket must be set.')

        parsed_socket = urlparse(endpoint_socket)

        if not parsed_socket.scheme:
            raise ValueError('SPIFFE endpoint socket: scheme must be set.')

        if parsed_socket.scheme == 'unix':
            self.__validate_unix_socket(parsed_socket)
        elif parsed_socket.scheme == 'tcp':
            self._validate_tcp_socket(parsed_socket)
        else:
            raise ValueError('SPIFFE endpoint socket: unsupported scheme.')

    @classmethod
    def __validate_unix_socket(cls, socket: ParseResult) -> None:
        if not socket.path:
            raise ValueError('SPIFFE endpoint socket: path must be set.')

        cls.__validate_forbidden_components(
            socket, cls.UNIX_FORBIDDEN_SOCKET_COMPONENTS
        )

    @classmethod
    def _validate_tcp_socket(cls, socket: ParseResult) -> None:
        try:
            ipaddress.ip_address(socket.hostname)
        except ValueError:
            raise ValueError('SPIFFE endpoint socket: host must be an IP address.')

        cls.__validate_forbidden_components(socket, cls.TCP_FORBIDDEN_SOCKET_COMPONENTS)

    @classmethod
    def __validate_forbidden_components(
        cls, socket: ParseResult, components: List[Tuple[str, str]]
    ) -> None:
        for component, description in components:
            has_component = component in dir(socket) and getattr(socket, component)
            if has_component:
                raise ValueError(
                    'SPIFFE endpoint socket: {} is not allowed.'.format(
                        description or component
                    )
                )
