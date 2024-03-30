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

"""Module that contains Configuration related classes
"""

import os
import ipaddress
from urllib.parse import ParseResult, urlparse
from typing import List, Optional, Tuple, Dict, cast
from spiffe.errors import ArgumentError


_SPIFFE_ENDPOINT_SOCKET = 'SPIFFE_ENDPOINT_SOCKET'


class Config:
    """Represents the configuration for a Workload API client.

    Attributes:
        spiffe_endpoint_socket (str): Path to the Workload API UDS.
    """

    def __init__(self, spiffe_endpoint_socket: str) -> None:
        """Initializes the Config class.

        Args:
            spiffe_endpoint_socket: Path to Workload API UDS.
        """
        self.spiffe_endpoint_socket = spiffe_endpoint_socket


class ConfigSetter:
    """Loads and validates configuration variables."""

    _FORBIDDEN_SOCKET_COMPONENTS: List[Tuple[str, Optional[str]]] = [
        ('fragment', None),
        ('username', None),
        ('password', None),
        ('query', None),
    ]

    _UNIX_FORBIDDEN_SOCKET_COMPONENTS = _FORBIDDEN_SOCKET_COMPONENTS + [
        ('netloc', 'authority')
    ]

    _TCP_FORBIDDEN_SOCKET_COMPONENTS = _FORBIDDEN_SOCKET_COMPONENTS + [('path', None)]

    def __init__(self, spiffe_endpoint_socket: Optional[str]) -> None:
        """Initializes the ConfigSetter class.

        Args:
            spiffe_endpoint_socket: Path to Workload API UDS. If not specified,
                the SPIFFE_ENDPOINT_SOCKET environment variable must be set.

        Raises:
            ArgumentError: If any configuration variable has an invalid format.
        """
        self._apply_default_config()
        self._apply_environment_variables()

        if spiffe_endpoint_socket:
            self._raw_config[_SPIFFE_ENDPOINT_SOCKET] = spiffe_endpoint_socket

        self._validate()
        self._config = Config(
            spiffe_endpoint_socket=cast(str, self._raw_config[_SPIFFE_ENDPOINT_SOCKET])
        )

    def get_config(self) -> Config:
        return self._config

    def _apply_default_config(self) -> None:
        self._raw_config: Dict[str, Optional[str]] = {_SPIFFE_ENDPOINT_SOCKET: None}

    def _apply_environment_variables(self) -> None:
        endpoint_socket = os.environ.get(_SPIFFE_ENDPOINT_SOCKET)

        if endpoint_socket:
            self._raw_config[_SPIFFE_ENDPOINT_SOCKET] = endpoint_socket

    def _validate(self) -> None:
        endpoint_socket = self._raw_config[_SPIFFE_ENDPOINT_SOCKET]
        if not endpoint_socket:
            raise ArgumentError('SPIFFE endpoint socket: socket must be set')

        parsed_socket = urlparse(endpoint_socket)

        if not parsed_socket.scheme:
            raise ArgumentError('SPIFFE endpoint socket: scheme must be set')

        if parsed_socket.scheme == 'unix':
            self._validate_unix_socket(parsed_socket)
        elif parsed_socket.scheme == 'tcp':
            self._validate_tcp_socket(parsed_socket)
        else:
            raise ArgumentError('SPIFFE endpoint socket: unsupported scheme')

    @classmethod
    def _validate_unix_socket(cls, socket: ParseResult) -> None:
        if not socket.path:
            raise ArgumentError('SPIFFE endpoint socket: path must be set')

        cls._validate_forbidden_components(socket, cls._UNIX_FORBIDDEN_SOCKET_COMPONENTS)

    @classmethod
    def _validate_tcp_socket(cls, socket: ParseResult) -> None:
        if socket.hostname is None:
            raise ArgumentError('SPIFFE endpoint socket: host must be an IP address')

        try:
            ipaddress.ip_address(socket.hostname)
        except ValueError:
            raise ArgumentError('SPIFFE endpoint socket: host must be an IP address')

        cls._validate_forbidden_components(socket, cls._TCP_FORBIDDEN_SOCKET_COMPONENTS)

    @classmethod
    def _validate_forbidden_components(
        cls, socket: ParseResult, components: List[Tuple[str, Optional[str]]]
    ) -> None:
        for component, description in components:
            has_component = component in dir(socket) and getattr(socket, component)
            if has_component:
                raise ArgumentError(
                    'SPIFFE endpoint socket: {} is not allowed'.format(
                        description or component
                    )
                )
