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

"""Base class for interceptors that operate on all RPC types."""

from typing import Callable, Iterator, Optional, Protocol, TypeVar

import grpc

_TRequest = TypeVar("_TRequest")
_TResponse = TypeVar("_TResponse")


class _InterceptorFn(Protocol):
    def __call__(
        self,
        client_call_details: grpc.ClientCallDetails,
        request_iterator: Iterator[_TRequest],
        request_streaming: bool,
        response_streaming: bool,
    ) -> tuple[
        grpc.ClientCallDetails,
        Iterator[_TRequest],
        Optional[Callable[[_TResponse], _TResponse]],
    ]: ...


class _GenericClientInterceptor(
    grpc.UnaryUnaryClientInterceptor,
    grpc.UnaryStreamClientInterceptor,
    grpc.StreamUnaryClientInterceptor,
    grpc.StreamStreamClientInterceptor,
):
    def __init__(self, interceptor_function: _InterceptorFn) -> None:
        self._fn = interceptor_function

    def intercept_unary_unary(
        self,
        continuation: Callable[[grpc.ClientCallDetails, _TRequest], _TResponse],
        client_call_details: grpc.ClientCallDetails,
        request: _TRequest,
    ) -> _TResponse:
        new_details, new_request_iterator, postprocess = self._fn(
            client_call_details, iter((request,)), False, False
        )
        response = continuation(new_details, next(new_request_iterator))
        return postprocess(response) if postprocess else response

    def intercept_unary_stream(
        self,
        continuation: Callable[[grpc.ClientCallDetails, _TRequest], _TResponse],
        client_call_details: grpc.ClientCallDetails,
        request: _TRequest,
    ) -> _TResponse:
        new_details, new_request_iterator, postprocess = self._fn(
            client_call_details, iter((request,)), False, True
        )
        response_it = continuation(new_details, next(new_request_iterator))
        return postprocess(response_it) if postprocess else response_it

    def intercept_stream_unary(
        self,
        continuation: Callable[[grpc.ClientCallDetails, Iterator[_TRequest]], _TResponse],
        client_call_details: grpc.ClientCallDetails,
        request_iterator: Iterator[_TRequest],
    ) -> _TResponse:
        new_details, new_request_iterator, postprocess = self._fn(
            client_call_details, request_iterator, True, False
        )
        response = continuation(new_details, new_request_iterator)
        return postprocess(response) if postprocess else response

    def intercept_stream_stream(
        self,
        continuation: Callable[[grpc.ClientCallDetails, Iterator[_TRequest]], _TResponse],
        client_call_details: grpc.ClientCallDetails,
        request_iterator: Iterator[_TRequest],
    ) -> _TResponse:
        new_details, new_request_iterator, postprocess = self._fn(
            client_call_details, request_iterator, True, True
        )
        response_it = continuation(new_details, new_request_iterator)
        return postprocess(response_it) if postprocess else response_it


def create(intercept_call: _InterceptorFn) -> _GenericClientInterceptor:
    return _GenericClientInterceptor(intercept_call)
