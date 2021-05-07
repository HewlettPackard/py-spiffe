from pyspiffe.workloadapi.cancel_handler import CancelHandler


class Observer:
    def __init__(self):
        self.was_changed = False


ob = Observer()


def test_cancel_handler():
    cancel_handler = CancelHandler(lambda: on_event())

    result = cancel_handler.cancel()

    assert ob.was_changed
    assert result


def test_set_cancel_handler():
    cancel_handler = CancelHandler()
    cancel_handler.set_handler(lambda: on_event())

    result = cancel_handler.cancel()

    assert ob.was_changed
    assert result


def test_cancel_without_handler_returns_false():
    cancel_handler = CancelHandler()
    result = cancel_handler.cancel()
    assert not result


def on_event() -> bool:
    ob.was_changed = True
    return True
