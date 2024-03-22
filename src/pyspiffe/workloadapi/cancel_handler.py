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

"""
This module provides a Cancel Handler.
"""

import threading
from typing import Callable, Optional


class CancelHandler:
    """Represents a handler to cancel operations."""

    def __init__(self, on_cancel: Optional[Callable[[], bool]]) -> None:
        """Create a CancelHandler.

        Args:
            on_cancel: The Callable that will be executed when the method 'cancel' is called. Can be 'None' and be set afterwards.
        """
        self._on_cancel = on_cancel
        self._lock = threading.Lock()

    def cancel(self) -> bool:
        """Executes the function set on the on_cancel and returns the result.

        In case the on_cancel is None, it returns False.
        """
        with self._lock:
            if self._on_cancel is None:
                return False
            return self._on_cancel()

    def set_handler(self, on_cancel: Callable[[], bool]) -> None:
        """Sets the cancel function on the handler."""
        with self._lock:
            self._on_cancel = on_cancel
