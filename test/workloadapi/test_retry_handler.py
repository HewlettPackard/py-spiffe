""""
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

from pyspiffe.workloadapi.workload_api_client import RetryHandler


class Observer:
    def __init__(self):
        self.was_changed = False


ob = Observer()


def change_parameter(o: Observer):
    o.was_changed = True


def test_retry_handler_execute_callable():
    retry_handler = RetryHandler()
    result = retry_handler.do_retry(change_parameter, [ob])
    assert ob.was_changed
    assert result
    assert retry_handler._retries_count == 1

    retry_handler.do_retry(change_parameter, [ob])
    assert retry_handler._retries_count == 2


def test_retry_handler_max_retries():
    retry_handler = RetryHandler(max_retries=1)
    retry_handler.do_retry(change_parameter, [ob])
    assert ob.was_changed
    assert retry_handler._retries_count == 1

    # second call do nothing
    ob.was_changed = False
    result = retry_handler.do_retry(change_parameter, [ob])
    assert not ob.was_changed
    assert not result
    assert retry_handler._retries_count == 1

    # resets handler
    retry_handler.reset()
    result = retry_handler.do_retry(change_parameter, [ob])
    assert ob.was_changed
    assert result


def test_reset_handler():
    retry_handler = RetryHandler()
    retry_handler.do_retry(change_parameter, [ob])
    assert retry_handler._retries_count == 1
    retry_handler.reset()
    assert retry_handler._retries_count == 0


def test_calculate_backoff_default_configuration():
    retry_handler = RetryHandler()
    backoff = retry_handler._calculate_backoff()
    assert backoff == 0.1

    retry_handler.do_retry(change_parameter, [ob])
    backoff = retry_handler._calculate_backoff()
    assert backoff == 0.2

    retry_handler.do_retry(change_parameter, [ob])
    backoff = retry_handler._calculate_backoff()
    assert backoff == 0.4

    retry_handler.do_retry(change_parameter, [ob])
    backoff = retry_handler._calculate_backoff()
    assert backoff == 0.8

    retry_handler.do_retry(change_parameter, [ob])
    backoff = retry_handler._calculate_backoff()
    assert backoff == 1.6


def test_calculate_backoff_custom_configuration():
    retry_handler = RetryHandler(
        base_backoff_in_seconds=0.2, backoff_factor=8, max_delay_in_seconds=2
    )
    backoff = retry_handler._calculate_backoff()
    assert backoff == 0.2

    retry_handler.do_retry(change_parameter, [ob])
    backoff = retry_handler._calculate_backoff()
    assert backoff == 1.6

    retry_handler.do_retry(change_parameter, [ob])
    backoff = retry_handler._calculate_backoff()
    assert backoff == 2
