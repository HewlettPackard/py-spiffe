from typing import Type
import grpc
import functools

from pyspiffe.exceptions import PySpiffeError
from pyspiffe.workloadapi.exceptions import WorkloadApiError


def handle_error(error_cls: Type[PySpiffeError], default_msg: str):
    def handler(func):
        @functools.wraps(func)
        def wrapper(*args, **kw):
            try:
                return func(*args, **kw)
            except WorkloadApiError as we:
                raise we
            except PySpiffeError as pe:
                raise error_cls(str(pe))
            except grpc.RpcError as rpc_error:
                if isinstance(rpc_error, grpc.Call):
                    raise error_cls(str(rpc_error.details()))
                raise error_cls(default_msg)
            except Exception:
                raise error_cls(default_msg)

        return wrapper

    return handler
