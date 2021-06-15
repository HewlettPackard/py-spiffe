from typing import Type
import grpc
import functools

from pyspiffe.exceptions import PySpiffeError, ArgumentError
from pyspiffe.workloadapi.exceptions import WorkloadApiError


DEFAULT_WL_API_ERROR_MESSAGE = 'Could not process response from the Workload API'


def handle_error(error_cls: Type[PySpiffeError]):
    def handler(func):
        @functools.wraps(func)
        def wrapper(*args, **kw):
            try:
                return func(*args, **kw)
            except WorkloadApiError as we:
                raise we
            except ArgumentError as ae:
                raise ae
            except PySpiffeError as pe:
                raise error_cls(str(pe))
            except grpc.RpcError as rpc_error:
                if isinstance(rpc_error, grpc.Call):
                    raise error_cls(str(rpc_error.details()))
                raise error_cls(DEFAULT_WL_API_ERROR_MESSAGE)
            except Exception as e:
                raise error_cls(str(e))

        return wrapper

    return handler
