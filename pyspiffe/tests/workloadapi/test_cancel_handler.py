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
    cancel_handler = CancelHandler(None)
    cancel_handler.set_handler(lambda: on_event())

    result = cancel_handler.cancel()

    assert ob.was_changed
    assert result


def test_cancel_without_handler_returns_false():
    cancel_handler = CancelHandler(None)
    result = cancel_handler.cancel()
    assert not result


def on_event() -> bool:
    ob.was_changed = True
    return True
