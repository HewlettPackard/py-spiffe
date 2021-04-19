from typing import Callable, Any


class Watcher:
    """ Watcher allows to register two Callables (aka callbacks) for `on_success` and `on_error`. """

    def __init__(self, on_success: Callable, on_error: Callable) -> None:
        self._on_success = on_success
        self._on_error = on_error

    def on_success(self, args: Any) -> None:
        """Executes the on_success Callable using the passed arguments. """
        self._on_success(args)

    def on_error(self, e: Exception) -> None:
        """Executes the on_error Callable passing the Exception. """
        self._on_error(e)
