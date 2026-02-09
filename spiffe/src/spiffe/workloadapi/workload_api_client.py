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

from __future__ import annotations

import logging
import os
import threading
from typing import Optional, List, Mapping, Callable, Dict, Set, Iterator, Protocol, TypeVar

import grpc
from grpc import StatusCode

from spiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from spiffe.bundle.jwt_bundle.jwt_bundle_set import JwtBundleSet
from spiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from spiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from spiffe.config import ConfigSetter
from spiffe.errors import ArgumentError
from spiffe._proto import (
    workload_pb2,
)
from spiffe._proto import workload_pb2_grpc
from spiffe.spiffe_id.spiffe_id import SpiffeId
from spiffe.spiffe_id.spiffe_id import TrustDomain
from spiffe.svid.jwt_svid import JwtSvid
from spiffe.svid.x509_svid import X509Svid
from spiffe.workloadapi.errors import (
    FetchX509SvidError,
    FetchX509BundleError,
    FetchJwtSvidError,
    FetchJwtBundleError,
    ValidateJwtSvidError,
    WorkloadApiError,
)
from spiffe.workloadapi.grpc import header_manipulator_client_interceptor
from spiffe.workloadapi.handle_error import handle_error
from spiffe.workloadapi.x509_context import X509Context

"""
This module provides a Workload API client.
"""

WORKLOAD_API_HEADER_KEY = 'workload.spiffe.io'
WORKLOAD_API_HEADER_VALUE = 'true'

_logger = logging.getLogger(__name__)

# GRPC Error Codes that the client will not retry on:
#  - INVALID_ARGUMENT is not retried according to the SPIFFE spec because the request is invalid
#  - CANCELLED is not retried because it occurs when the caller has canceled the operation.
_NON_RETRYABLE_CODES = {grpc.StatusCode.CANCELLED, grpc.StatusCode.INVALID_ARGUMENT}

__all__ = ['WorkloadApiClient', 'RetryPolicy']

_T_co = TypeVar("_T_co", covariant=True)


class _CancelableIterator(Protocol[_T_co]):
    def __iter__(self) -> Iterator[_T_co]: ...

    def __next__(self) -> _T_co: ...

    def cancel(self) -> bool: ...


class _WorkloadApiStub(Protocol):
    FetchX509SVID: grpc.UnaryStreamMultiCallable[
        workload_pb2.X509SVIDRequest, workload_pb2.X509SVIDResponse
    ]
    FetchX509Bundles: grpc.UnaryStreamMultiCallable[
        workload_pb2.X509BundlesRequest, workload_pb2.X509BundlesResponse
    ]
    FetchJWTSVID: grpc.UnaryUnaryMultiCallable[
        workload_pb2.JWTSVIDRequest, workload_pb2.JWTSVIDResponse
    ]
    FetchJWTBundles: grpc.UnaryStreamMultiCallable[
        workload_pb2.JWTBundlesRequest, workload_pb2.JWTBundlesResponse
    ]
    ValidateJWTSVID: grpc.UnaryUnaryMultiCallable[
        workload_pb2.ValidateJWTSVIDRequest, workload_pb2.ValidateJWTSVIDResponse
    ]


class RetryPolicy:
    """Defines the retry policy using an exponential backoff strategy."""

    UNLIMITED_RETRIES = 0  # Signifies unlimited retries

    def __init__(
        self,
        max_retries: int = UNLIMITED_RETRIES,
        base_backoff_in_seconds: float = 0.1,
        backoff_factor: int = 2,
        max_backoff: float = 5,
    ) -> None:
        self.max_retries = max_retries
        self.base_backoff = base_backoff_in_seconds
        self.backoff_factor = backoff_factor
        self.max_backoff = max_backoff


class RetryHandler:
    def __init__(self, retry_policy: Optional[RetryPolicy] = None) -> None:
        self.retry_policy: RetryPolicy = (
            retry_policy if retry_policy is not None else RetryPolicy()
        )
        self.attempt: int = 0

    def should_retry(self, error_code: StatusCode) -> bool:
        """Determines whether the operation should be retried based on the error code and attempt count."""
        if error_code in _NON_RETRYABLE_CODES:
            return False
        # Allow unlimited retries when max_retries is set to UNLIMITED_RETRIES (0)
        if (
            self.retry_policy.max_retries != RetryPolicy.UNLIMITED_RETRIES
            and self.attempt >= self.retry_policy.max_retries
        ):
            return False
        return True

    def get_backoff(self) -> float:
        """Calculates the backoff time for the current attempt, then increments the attempt counter."""
        # int.__pow__ is annotated as returning Any to avoid false positives
        # (positive int -> int, negative int -> float) so coerce to int since we
        # know it's a positive integer.
        growth: int = self.retry_policy.backoff_factor**self.attempt
        backoff_time = min(
            self.retry_policy.base_backoff * growth,
            self.retry_policy.max_backoff,
        )
        self.attempt += 1
        return backoff_time

    def reset(self) -> None:
        """Resets the attempt counter to zero."""
        self.attempt = 0


class StreamCancelHandler:
    def __init__(self) -> None:
        self.response_iterator: Optional[_CancelableIterator[object]] = None
        self._cancel_event = threading.Event()
        self._lock = threading.Lock()

    def set_iterator(self, iterator: _CancelableIterator[object]) -> None:
        with self._lock:
            self.response_iterator = iterator
            # If already cancelled, cancel the iterator immediately to avoid race
            if self._cancel_event.is_set():
                try:
                    iterator.cancel()
                except Exception:
                    pass

    def cancel(self) -> None:
        self._cancel_event.set()
        with self._lock:
            if self.response_iterator:
                self.response_iterator.cancel()

    def is_cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def wait_cancelled(self, timeout: float) -> bool:
        """Waits until the handler is cancelled or timeout is reached."""
        return self._cancel_event.wait(timeout)


class WorkloadApiClient:
    """A SPIFFE Workload API Client."""

    def __init__(self, socket_path: Optional[str] = None) -> None:
        """
        Creates a new Workload API Client.

        This client interfaces with the Workload API using a Unix Domain Socket (UDS). If `socket_path` is not explicitly provided,
        the client attempts to use the path specified by the `SPIFFE_ENDPOINT_SOCKET` environment variable.

        Parameters:
            socket_path (Optional[str]): The file path to the Workload API UDS. If omitted, the client looks for the
                                        path in the `SPIFFE_ENDPOINT_SOCKET` environment variable.

        Raises:
            ArgumentError: If `socket_path` is not provided and no path is found in the `SPIFFE_ENDPOINT_SOCKET`
                           environment variable, or if the provided `socket_path` is invalid.
        """
        try:
            self._config = ConfigSetter(spiffe_endpoint_socket=socket_path).get_config()
            self._check_spiffe_socket_exists(self._config.spiffe_endpoint_socket)
        except ArgumentError as e:
            raise ArgumentError('Invalid WorkloadApiClient configuration: {}'.format(str(e)))

        self._channel = self._get_spiffe_grpc_channel()
        self._spiffe_workload_api_stub: _WorkloadApiStub = (
            # grpc doesn't generate types, see https://github.com/grpc/grpc/pull/37877.
            workload_pb2_grpc.SpiffeWorkloadAPIStub(self._channel)  # type: ignore[no-untyped-call]
        )

    @handle_error(error_cls=FetchX509SvidError)
    def fetch_x509_svid(self) -> X509Svid:
        """Fetches the default X509-SVID, i.e. the first in the list returned by the Workload API.

        Returns:
            X509Svid: Instance of X509Svid object.

        Raises:
            FetchX509SvidError: When there is an error fetching the X.509 SVID from the Workload API, or when the
                                response payload cannot be processed to be converted to a X509Svid object.
        """
        response = self._call_fetch_x509_svid()

        svid = response.svids[0]

        return self._create_x509_svid(svid)

    @handle_error(error_cls=FetchX509SvidError)
    def fetch_x509_svids(self) -> List[X509Svid]:
        """Fetches all X509-SVIDs.

        Returns:
            X509Svid: List of of X509Svid object.

        Raises:
            FetchX509SvidError: When there is an error fetching the X.509 SVID from the Workload API, or when the
                                response payload cannot be processed to be converted to a X509Svid object.
        """
        response = self._call_fetch_x509_svid()

        result = []
        for svid in response.svids:
            result.append(self._create_x509_svid(svid))

        return result

    @handle_error(error_cls=FetchX509SvidError)
    def fetch_x509_context(self) -> X509Context:
        """Fetches an X.509 context (X.509 SVIDs and X.509 Bundles keyed by TrustDomain).

        Returns:
            X509Context: An object containing a List of X509Svids and a X509BundleSet.

        Raises:
            FetchX509SvidError: When there is an error fetching the X.509 SVID from the Workload API, or when the
                                response payload cannot be processed to be converted to a X509Svid object.

            FetchX509BundleError: When there is an error fetching the X.509 Bundles from the Workload API, or when the
                                  response payload cannot be processed to be converted to a X509Bundle objects.
        """
        response = self._call_fetch_x509_svid()
        return self._process_x509_context(response)

    @handle_error(error_cls=FetchX509BundleError)
    def fetch_x509_bundles(self) -> X509BundleSet:
        """Fetches X.509 bundles, keyed by trust domain.

        Returns:
            X509BundleSet: Set of X509Bundle objects.

        Raises:
            FetchX509BundleError: When there is an error fetching the X.509 Bundles from the Workload API, or when the
                                  response payload cannot be processed to be converted to a X509Bundle objects.
        """
        response = self._call_fetch_x509_bundles()
        return self._create_x509_bundle_set(response.bundles)

    @handle_error(error_cls=FetchJwtSvidError)
    def fetch_jwt_svid(
        self, audience: Set[str], subject: Optional[SpiffeId] = None
    ) -> JwtSvid:
        """Fetches a SPIFFE JWT-SVID.

        Args:
            audience: Set of audiences for the JWT SVID.
            subject: SPIFFE ID subject for the JWT.

        Returns:
            JwtSvid: Instance of JwtSvid object.
        Raises:
            ArgumentError: In case audience is empty.
            FetchJwtSvidError: In case there is an error in fetching the JWT-SVID from the Workload API.
        """
        if not audience:
            raise ArgumentError('Parameter audiences cannot be empty')

        subject_str = str(subject) if subject is not None else ''
        response = self._spiffe_workload_api_stub.FetchJWTSVID(
            workload_pb2.JWTSVIDRequest(
                audience=audience,
                spiffe_id=subject_str,
            )
        )

        if len(response.svids) == 0:
            raise FetchJwtSvidError('JWT SVID response is empty')

        svid = response.svids[0].svid
        return JwtSvid.parse_insecure(svid, audience)

    @handle_error(error_cls=FetchJwtSvidError)
    def fetch_jwt_svids(
        self, audience: Set[str], subject: Optional[SpiffeId] = None
    ) -> List[JwtSvid]:
        """Fetches all SPIFFE JWT-SVIDs.

        Args:
            audience: List of audiences for the JWT SVID.
            subject: SPIFFE ID subject for the JWT.

        Raises:
            ArgumentError: In case audience is empty.
            FetchJwtSvidError: In case there is an error in fetching the JWT-SVID from the Workload API.
        """
        if not audience:
            raise ArgumentError('Parameter audiences cannot be empty')

        subject_str = str(subject) if subject is not None else ''
        response = self._spiffe_workload_api_stub.FetchJWTSVID(
            workload_pb2.JWTSVIDRequest(
                audience=audience,
                spiffe_id=subject_str,
            )
        )

        if len(response.svids) == 0:
            raise FetchJwtSvidError('JWT SVID response is empty')

        svids = []
        for s in response.svids:
            svids.append(JwtSvid.parse_insecure(s.svid, audience))

        return svids

    @handle_error(error_cls=FetchJwtBundleError)
    def fetch_jwt_bundles(self) -> JwtBundleSet:
        """Fetches the JWT bundles for JWT-SVID validation, keyed by trust domain.

        Returns:
            JwtBundleSet: Set of JwtBundle objects.

        Raises:
            FetchJwtBundleError: In case there is an error in fetching the JWT-Bundle from the Workload API or
                                in case the set of jwt_authorities cannot be parsed from the Workload API Response.
        """
        response = self._call_fetch_jwt_bundles()
        jwt_bundles: Dict[TrustDomain, JwtBundle] = self._create_td_jwt_bundle_dict(response)
        return JwtBundleSet(jwt_bundles)

    @handle_error(error_cls=ValidateJwtSvidError)
    def validate_jwt_svid(self, token: str, audience: str) -> JwtSvid:
        """Validates the JWT-SVID token. The parsed and validated JWT-SVID is returned.

        Args:
            token: JWT to validate.
            audience: expected audience to validate against.

        Returns:
            JwtSvid: If the token and audience could be validated.

        Raises:
            ArgumentError: In case token or audience is empty.
            ValidateJwtSvidError: In case an error occurs calling the Workload API or
                                in case the response from the Workload API cannot be processed.
        """
        if not token:
            raise ArgumentError('Token cannot be empty')
        if not audience:
            raise ArgumentError('Audience cannot be empty')

        self._spiffe_workload_api_stub.ValidateJWTSVID(
            workload_pb2.ValidateJWTSVIDRequest(
                audience=audience,
                svid=token,
            )
        )
        return JwtSvid.parse_insecure(token, {audience})

    def stream_x509_contexts(
        self,
        on_success: Callable[[X509Context], None],
        on_error: Callable[[Exception], None],
        retry_connect: bool = True,
        retry_policy: Optional[RetryPolicy] = None,
    ) -> StreamCancelHandler:
        """
        Establishes a streaming gRPC connection to receive continuous updates of X.509 contexts from the Workload API.

        This method asynchronously listens for X.509 context updates, invoking `on_success` with each new context received.
        If an error occurs during streaming or processing, `on_error` is called with the encountered exception. The method
        supports automatic reconnection attempts based on the specified `retry_policy`.

        Parameters:
            on_success (Callable[[X509Context], None]): Callback for each update received.
            on_error (Callable[[Exception], None]): Callback for handling streaming or processing errors.
            retry_connect (bool, optional): Enables automatic retries on connection failures. Defaults to True.
            retry_policy (Optional[RetryPolicy], optional): Custom retry behavior; uses default if None.

        Returns:
            StreamCancelHandler: A handler that can be used to cancel the streaming operation.

        Usage example:
            cancel_handler = client.stream_x509_contexts(on_success, on_error)
            # To cancel the streaming:
            cancel_handler.cancel()
        """
        cancel_handler = StreamCancelHandler()
        retry_handler = RetryHandler(retry_policy) if retry_connect else None

        def watch_target() -> None:
            self._watch_x509_context_updates(
                cancel_handler, retry_handler, on_success, on_error
            )

        t = threading.Thread(target=watch_target, daemon=True)
        t.start()

        return cancel_handler

    def stream_jwt_bundles(
        self,
        on_success: Callable[[JwtBundleSet], None],
        on_error: Callable[[Exception], None],
        retry_connect: bool = True,
        retry_policy: Optional[RetryPolicy] = None,
    ) -> StreamCancelHandler:
        """
        Establishes a streaming gRPC connection to receive continuous updates of Jwt Bundles from the Workload API.

        This method asynchronously listens for Jwt Bundles updates, invoking `on_success` with each new update received.
        If an error occurs during streaming or processing, `on_error` is called with the encountered exception. The method
        supports automatic reconnection attempts based on the specified `retry_policy`.

        Parameters:
            on_success (Callable[[X509Context], None]): Callback for each update received.
            on_error (Callable[[Exception], None]): Callback for handling streaming or processing errors.
            retry_connect (bool, optional): Enables automatic retries on connection failures. Defaults to True.
            retry_policy (Optional[RetryPolicy], optional): Custom retry behavior; uses default if None.

        Returns:
            StreamCancelHandler: A handler that can be used to cancel the streaming operation.

        Usage example:
            cancel_handler = client.stream_x509_contexts(on_success, on_error)
            # To cancel the streaming:
            cancel_handler.cancel()
        """
        cancel_handler = StreamCancelHandler()
        retry_handler = RetryHandler(retry_policy) if retry_connect else None

        def watch_target() -> None:
            self._watch_jwt_bundles_updates(
                cancel_handler, retry_handler, on_success, on_error
            )

        t = threading.Thread(target=watch_target, daemon=True)
        t.start()

        return cancel_handler

    def get_spiffe_endpoint_socket(self) -> str:
        """Returns the spiffe endpoint socket config for this WorkloadApiClient.

        Returns:
            str: spiffe endpoint socket configuration value.
        """

        return self._config.spiffe_endpoint_socket

    def close(self) -> None:
        """Closes the WorkloadClient along with the current connections."""
        self._channel.close()

    # Private methods
    def _watch_x509_context_updates(
        self,
        cancel_handler: StreamCancelHandler,
        retry_handler: Optional[RetryHandler],
        on_success: Callable[[X509Context], None],
        on_error: Callable[[Exception], None],
    ) -> None:
        while True:
            if cancel_handler.is_cancelled():
                break
            try:
                response_iterator = self._spiffe_workload_api_stub.FetchX509SVID(
                    workload_pb2.X509SVIDRequest()
                )
                cancel_handler.set_iterator(response_iterator)

                for item in response_iterator:
                    if cancel_handler.is_cancelled():
                        break
                    x509_context = self._process_x509_context(item)
                    on_success(x509_context)

                if retry_handler:
                    retry_handler.reset()
                break

            except grpc.RpcError as grpc_err:
                if retry_handler is None or not retry_handler.should_retry(grpc_err.code()):
                    on_error(WorkloadApiError(f"gRPC error: {str(grpc_err.code())}"))
                    break

                backoff = retry_handler.get_backoff()
                if cancel_handler.wait_cancelled(backoff):
                    break

            except Exception as err:
                on_error(WorkloadApiError(str(err)))
                break  # Exit on unexpected errors

    def _watch_jwt_bundles_updates(
        self,
        cancel_handler: StreamCancelHandler,
        retry_handler: Optional[RetryHandler],
        on_success: Callable[[JwtBundleSet], None],
        on_error: Callable[[Exception], None],
    ) -> None:
        while True:
            if cancel_handler.is_cancelled():
                break
            try:
                response_iterator = self._spiffe_workload_api_stub.FetchJWTBundles(
                    workload_pb2.JWTBundlesRequest()
                )
                cancel_handler.set_iterator(response_iterator)

                for item in response_iterator:
                    if cancel_handler.is_cancelled():
                        break
                    jwt_bundles = self._process_jwt_bundles(item)
                    on_success(jwt_bundles)

                if retry_handler:
                    retry_handler.reset()
                break

            except grpc.RpcError as grpc_err:
                if retry_handler is None or not retry_handler.should_retry(grpc_err.code()):
                    on_error(WorkloadApiError(f"gRPC error: {str(grpc_err.code())}"))
                    break

                backoff = retry_handler.get_backoff()
                if cancel_handler.wait_cancelled(backoff):
                    break

            except Exception as err:
                on_error(WorkloadApiError(str(err)))
                break  # Exit on unexpected errors

    def _process_x509_context(
        self, x509_svid_response: workload_pb2.X509SVIDResponse
    ) -> X509Context:
        svids = []
        bundle_set = self._create_x509_bundle_set(x509_svid_response.federated_bundles)
        for svid in x509_svid_response.svids:
            x509_svid = self._create_x509_svid(svid)
            svids.append(x509_svid)

            trust_domain = x509_svid.spiffe_id.trust_domain
            bundle_set.put(X509Bundle.parse_raw(trust_domain, svid.bundle))

        return X509Context(svids, bundle_set)

    def _process_jwt_bundles(
        self, jwt_bundles_response: workload_pb2.JWTBundlesResponse
    ) -> JwtBundleSet:
        return self._create_jwt_bundle_set(jwt_bundles_response.bundles)

    def _get_spiffe_grpc_channel(self) -> grpc.Channel:
        target = self._grpc_target(self._config.spiffe_endpoint_socket)
        grpc_insecure_channel = grpc.insecure_channel(target)
        spiffe_client_interceptor = (
            header_manipulator_client_interceptor.header_adder_interceptor(
                WORKLOAD_API_HEADER_KEY, WORKLOAD_API_HEADER_VALUE
            )
        )

        return grpc.intercept_channel(grpc_insecure_channel, spiffe_client_interceptor)

    def _call_fetch_x509_svid(self) -> workload_pb2.X509SVIDResponse:
        response = self._spiffe_workload_api_stub.FetchX509SVID(workload_pb2.X509SVIDRequest())
        try:
            item = next(response)
        except StopIteration:
            raise FetchX509SvidError('X.509 SVID response is invalid')
        if len(item.svids) == 0:
            raise FetchX509SvidError('X.509 SVID response is empty')
        return item

    def _call_fetch_x509_bundles(self) -> workload_pb2.X509BundlesResponse:
        response = self._spiffe_workload_api_stub.FetchX509Bundles(
            workload_pb2.X509BundlesRequest()
        )
        try:
            item = next(response)
        except StopIteration:
            raise FetchX509BundleError('X.509 Bundles response is invalid')
        if len(item.bundles) == 0:
            raise FetchX509BundleError('X.509 Bundles response is empty')
        return item

    def _call_fetch_jwt_bundles(self) -> workload_pb2.JWTBundlesResponse:
        response = self._spiffe_workload_api_stub.FetchJWTBundles(
            workload_pb2.JWTBundlesRequest()
        )
        try:
            item = next(response)
        except StopIteration:
            raise FetchJwtBundleError('JWT Bundles response is invalid')
        if len(item.bundles) == 0:
            raise FetchJwtBundleError('JWT Bundles response is empty')
        return item

    @staticmethod
    def _create_x509_bundle_set(resp_bundles: Mapping[str, bytes]) -> X509BundleSet:
        x509_bundles = [
            X509Bundle.parse_raw(TrustDomain(td), resp_bundles[td]) for td in resp_bundles
        ]
        return X509BundleSet.of(x509_bundles)

    @staticmethod
    def _create_jwt_bundle_set(resp_bundles: Mapping[str, bytes]) -> JwtBundleSet:
        jwt_bundles = [
            JwtBundle.parse(TrustDomain(td), bundle) for td, bundle in resp_bundles.items()
        ]
        return JwtBundleSet.of(jwt_bundles)

    @staticmethod
    def _create_x509_svid(svid: workload_pb2.X509SVID) -> X509Svid:
        cert = svid.x509_svid
        key = svid.x509_svid_key
        return X509Svid.parse_raw(cert, key)

    @staticmethod
    def _create_td_jwt_bundle_dict(
        jwt_bundle_response: workload_pb2.JWTBundlesResponse,
    ) -> Dict[TrustDomain, JwtBundle]:
        return {
            TrustDomain(td): JwtBundle.parse(TrustDomain(td), jwk_set)
            for td, jwk_set in jwt_bundle_response.bundles.items()
        }

    def __enter__(self) -> 'WorkloadApiClient':
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()

    @staticmethod
    def _check_spiffe_socket_exists(spiffe_socket: str) -> None:
        path_to_check = WorkloadApiClient._strip_unix_scheme(spiffe_socket)
        if not path_to_check:
            raise ArgumentError('SPIFFE endpoint socket is empty')
        if not os.path.exists(path_to_check):
            raise ArgumentError(f'SPIFFE socket file "{path_to_check}" does not exist.')

    @staticmethod
    def _grpc_target(value: str) -> str:
        """Returns the gRPC target for UDS, normalizing unix:/// to unix:/."""
        if value.startswith('unix:'):
            path = value[5:]
            if path.startswith('/'):
                path = '/' + path.lstrip('/')
            return f'unix:{path}'
        if value.startswith('/'):
            return f'unix:{value}'
        raise ArgumentError(
            f'Invalid SPIFFE endpoint socket "{value}": only unix domain sockets are supported'
        )

    @staticmethod
    def _strip_unix_scheme(value: str) -> str:
        """Strips unix: scheme and normalizes leading slashes for filesystem checks."""
        path = value[5:] if value.startswith('unix:') else value
        if path.startswith('/'):
            path = '/' + path.lstrip('/')
        return path
