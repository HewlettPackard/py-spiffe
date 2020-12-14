import os
from typing import Dict

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
        self._config[SPIFFE_ENDPOINT_SOCKET] = os.environ.get(SPIFFE_ENDPOINT_SOCKET)
