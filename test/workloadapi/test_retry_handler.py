from pyspiffe.workloadapi.default_workload_api_client import RetryHandler


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
