from typing import Any

from pyspiffe.workloadapi.watcher import Watcher


class Observer:
    def __init__(self):
        self.was_changed = False


def test_on_success():
    ob = Observer()

    watcher = Watcher(lambda x: on_event(x), raise_error)
    watcher.on_success(ob)

    assert ob.was_changed


def test_on_error():
    ob = Observer()

    watcher = Watcher(raise_error, lambda x: on_event(x))
    watcher.on_error(ob)

    assert ob.was_changed


def on_event(o: Observer):
    o.was_changed = True


def raise_error(args: Any):
    raise RuntimeError('Unexpected call')
