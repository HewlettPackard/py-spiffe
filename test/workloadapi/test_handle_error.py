import pytest
import grpc
from pyspiffe.workloadapi.handle_error import handle_error
from pyspiffe.exceptions import PySpiffeError
from pyspiffe.workloadapi.exceptions import WorkloadApiError
from test.utils.utils import FakeCall


def test_handle_error():
    @handle_error(error_cls=PySpiffeError, default_msg='Error Msg')
    def func_that_works():
        return None

    res = func_that_works()

    assert res is None


def test_handle_error_on_workload_api_error():
    @handle_error(error_cls=PySpiffeError, default_msg='Error Msg')
    def func_that_raises_workload_api_error():
        raise WorkloadApiError('Workload API Error')

    with pytest.raises(WorkloadApiError) as exc_info:
        func_that_raises_workload_api_error()

    assert str(exc_info.value) == 'Workload API Error.'


def test_handle_error_on_py_spiffe_error():
    @handle_error(error_cls=PySpiffeError, default_msg='Error Msg')
    def func_that_raises_py_spiffe_error():
        raise PySpiffeError('PySPIFFE Error')

    with pytest.raises(PySpiffeError) as exc_info:
        func_that_raises_py_spiffe_error()

    assert str(exc_info.value) == 'PySPIFFE Error.'


def test_handle_error_on_grpc_error():
    @handle_error(error_cls=PySpiffeError, default_msg='Error Msg')
    def func_that_raises_grpc_error():
        raise grpc.RpcError('gRPC Error')

    with pytest.raises(PySpiffeError) as exc_info:
        func_that_raises_grpc_error()

    assert str(exc_info.value) == 'Error Msg.'


def test_handle_error_on_grpc_call_error():
    @handle_error(error_cls=PySpiffeError, default_msg='Error Msg')
    def func_that_raises_grpc_call_error():
        raise FakeCall()

    with pytest.raises(PySpiffeError) as exc_info:
        func_that_raises_grpc_call_error()

    assert str(exc_info.value) == 'Error details from Workload API.'


def test_handle_error_on_exception():
    @handle_error(error_cls=PySpiffeError, default_msg='Error Msg')
    def func_that_raises_exception():
        raise Exception('Some random message')

    with pytest.raises(PySpiffeError) as exc_info:
        func_that_raises_exception()

    assert str(exc_info.value) == 'Error Msg.'
