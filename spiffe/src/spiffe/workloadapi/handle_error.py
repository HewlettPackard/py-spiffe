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

from typing import Type
import grpc
import functools

from spiffe.errors import PySpiffeError, ArgumentError
from spiffe.workloadapi.errors import WorkloadApiError


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
