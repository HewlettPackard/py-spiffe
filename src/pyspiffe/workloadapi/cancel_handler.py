import threading
from typing import Callable


class CancelHandler:
    """Represents a handler to cancel operations. """

    def __init__(self, on_cancel: Callable[[], bool] = None) -> None:
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
        with self._lock:
            self._on_cancel = on_cancel
