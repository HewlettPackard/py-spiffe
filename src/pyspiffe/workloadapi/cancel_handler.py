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
