"""
This module provides a Workload API client.
"""
from typing import Optional, List, Mapping
import threading
import time
from typing import Optional, List, Set, Mapping, Iterator, Callable

import grpc

from pyspiffe.workloadapi.cancel_handler import CancelHandler
from pyspiffe.workloadapi.x509_context import X509Context
from pyspiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from pyspiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from pyspiffe.bundle.jwt_bundle.jwt_bundle_set import JwtBundleSet
from pyspiffe.config import ConfigSetter
from pyspiffe.exceptions import ArgumentError
from pyspiffe.proto.spiffe import (
    workload_pb2_grpc,
    workload_pb2,
)
from pyspiffe.spiffe_id.trust_domain import TrustDomain
from pyspiffe.workloadapi.exceptions import (
    FetchX509SvidError,
    FetchX509BundleError,
    FetchJwtSvidError,
    ValidateJwtSvidError,
)
from pyspiffe.workloadapi.grpc import header_manipulator_client_interceptor
from pyspiffe.svid.x509_svid import X509Svid
from pyspiffe.svid.jwt_svid import JwtSvid
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.svid.exceptions import JwtSvidError

from pyspiffe.workloadapi.workload_api_client import (
    WorkloadApiClient,
    WORKLOAD_API_HEADER_KEY,
    WORKLOAD_API_HEADER_VALUE,
)

# GRPC Error Codes that the client will not retry on:
#  - INVALID_ARGUMENT is not retried according to the SPIFFE spec because the request is invalid
#  - CANCELLED is not retried because it occurs when the caller has canceled the operation.
_NON_RETRYABLE_CODES = {grpc.StatusCode.CANCELLED, grpc.StatusCode.INVALID_ARGUMENT}


class _RetryHandler:
    def __init__(
        self,
        max_retries: int = 0,
        base_backoff_in_seconds: float = 0.1,
        backoff_factor: int = 2,
        max_delay_in_seconds: int = 60,
    ) -> None:
        self._max_retries = max_retries
        self._base_backoff = base_backoff_in_seconds
        self._backoff_factor = backoff_factor
        self._max_delay_in_seconds = max_delay_in_seconds
        self._retries_count = 0
        self._lock = threading.RLock()

    def do_retry(self, fn: Callable, params: List) -> bool:
        with self._lock:
            if self._max_retries and self._retries_count > self._max_retries:
                return False
            self._retries_count += 1
            backoff = self._calculate_backoff()

        time.sleep(backoff)
        fn(*params)
        return True

    def reset(self):
        with self._lock:
            self._retries_count = 0

    def _calculate_backoff(self) -> float:
        with self._lock:
            backoff = self._base_backoff * pow(
                self._backoff_factor, self._retries_count
            )
            if backoff < self._max_delay_in_seconds:
                return backoff
            return self._max_delay_in_seconds


class DefaultWorkloadApiClient(WorkloadApiClient):
    """Default implementation for a SPIFFE Workload API Client."""

    def __init__(self, spiffe_socket: str = None) -> None:
        """Creates a new Workload API Client.

        Args:
            spiffe_socket: Path to Workload API UDS. If not specified, the SPIFFE_ENDPOINT_SOCKET environment variable
                           must be set.

        Returns:
            DefaultWorkloadApiClient: New Workload API Client object.

        Raises:
            ArgumentError: If spiffe_socket_path is invalid or not provided and SPIFFE_ENDPOINT_SOCKET environment variable doesn't exist.
        """

        try:
            self._config = ConfigSetter(
                spiffe_endpoint_socket=spiffe_socket
            ).get_config()
        except ArgumentError as e:
            raise ArgumentError(
                'Invalid DefaultWorkloadApiClient configuration: {}'.format(str(e))
            )

        self._channel = self._get_spiffe_grpc_channel()
        self._spiffe_workload_api_stub = workload_pb2_grpc.SpiffeWorkloadAPIStub(
            self._channel
        )

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

    def watch_x509_context(
        self,
        on_success: Callable[[X509Context], None],
        on_error: Callable[[Exception], None],
        retry_connect: bool = True,
    ) -> CancelHandler:
        """Watches for X.509 context updates.

           This method returns immediately and spawns a new thread to handle the connection with the Workload API. That thread
           will keep running until the client calls the method `cancel` on the returned CancelHandler, or in case
           `retry_connect` is false and there is an error returned by the Workload API.

           A new Stream to the Workload API is opened for each call to this method, so that the client starts getting
           updates immediately after the Stream is ready and doesn't have to wait until the Workload API dispatches
           the next update based on the SVIDs TTL.

           In case of an error, if `retry_connect` is True and the error was not grpc.StatusCode.CANCELLED
           or grpc.StatusCode.INVALID_ARGUMENT, it will attempt to establish a new connection
           to the Workload API, using an exponential backoff policy to perform the retries, starting with a delay of 0.1 seconds,
           incrementing it then to 0.2, 0.4, 0.8, 1.6 and so on (until the max backoff of 60 seconds). It retries indefinitely.

           # TODO: make the backoff policy configurable

        Args:
            on_success: A Callable accepting a X509Context as argument and returning None, to be executed when a new update
                        is fetched from the Workload API,

            on_error: A Callable accepting an Exception as argument and returning None, to be executed when there is
                      an error on the connection with the Workload API.

            retry_connect: Enable retries when the connection with the Workload API returns an error.
                           Default: True

        Returns:
            CancelHandler: An object on which it can be called the method `cancel` to close the stream connection with
                           the Workload API.
        """

        cancel_handler = CancelHandler()
        retry_handler = _RetryHandler()

        # start listening for updates in a separate thread
        t = threading.Thread(
            target=self._call_watch_x509_context,
            args=(cancel_handler, retry_handler, on_success, on_error, retry_connect),
        )
        t.setDaemon(True)
        t.start()

        # this handler is initialized later after the call to the Workload API
        return cancel_handler

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

    def fetch_x509_bundles(self) -> X509BundleSet:
        """Fetches X.509 bundles, keyed by trust domain.

        Returns:
            X509BundleSet: Set of X509Bundle objects.

        Raises:
            FetchX509BundleError: When there is an error fetching the X.509 Bundles from the Workload API, or when the
                                  response payload cannot be processed to be converted to a X509Bundle objects.
        """
        response = self._call_fetch_x509_bundles()
        return self._create_bundle_set(response.bundles)

    def fetch_jwt_svid(
        self, audiences: List[str], subject: Optional[SpiffeId] = None
    ) -> JwtSvid:
        """Fetches a SPIFFE JWT-SVID.

        Args:
            audiences: List of audiences for the JWT SVID.
            subject: SPIFFE ID subject for the JWT.

        Returns:
            JwtSvid: Instance of JwtSvid object.
        Raises:
            ArgumentError: In case audience is empty.
            FetchJwtSvidError: In case there is an error in fetching the JWTSVID from the Workload API.
        """
        if not audiences:
            raise ArgumentError('Parameter audiences cannot be empty')
        try:
            response = self._call_fetch_jwt_svids(audiences, str(subject))
            svid = response.svids[0].svid
            return JwtSvid.parse_insecure(svid, audiences)
        except JwtSvidError as e:
            raise FetchJwtSvidError(str(e))

    def fetch_jwt_bundles(self) -> JwtBundleSet:
        """Fetches the JWT bundles for JWT-SVID validation, keyed by trust
        domain.

        Returns:
            JwtBundleSet: Set of JwtBundle objects.
        """

        pass

    def validate_jwt_svid(self, token: str, audience: str) -> JwtSvid:
        """Validates the JWT-SVID token. The parsed and validated JWT-SVID is returned.

        Args:
            token: JWT to validate.
            audience: Audience to validate against.

        Returns:
            JwtSvid: If the token and audience could be validated.
            ArgumentError: In case token or audience is empty.
        """
        if not token:
            raise ArgumentError('Token cannot be empty')
        if not audience:
            raise ArgumentError('Audience cannot be empty')

        try:
            request = workload_pb2.ValidateJWTSVIDRequest(
                audience=audience,
                svid=token,
            )

            self._spiffe_workload_api_stub.ValidateJWTSVID(request)
        except Exception as e:
            raise ValidateJwtSvidError(str(e))

        return JwtSvid.parse_insecure(token, [audience])

    def get_spiffe_endpoint_socket(self) -> str:
        """Returns the spiffe endpoint socket config for this WorkloadApiClient.

        Returns:
            str: spiffe endpoint socket configuration value.
        """

        return self._config.spiffe_endpoint_socket

    def close(self) -> None:
        """Closes the WorkloadClient along with the current connections. """
        self._channel.close()

    def _get_spiffe_grpc_channel(self) -> grpc.Channel:
        grpc_insecure_channel = grpc.insecure_channel(
            self._config.spiffe_endpoint_socket
        )
        spiffe_client_interceptor = (
            header_manipulator_client_interceptor.header_adder_interceptor(
                WORKLOAD_API_HEADER_KEY, WORKLOAD_API_HEADER_VALUE
            )
        )

        return grpc.intercept_channel(grpc_insecure_channel, spiffe_client_interceptor)

    def _call_fetch_x509_svid(self) -> workload_pb2.X509SVIDResponse:
        try:
            response = self._spiffe_workload_api_stub.FetchX509SVID(
                workload_pb2.X509SVIDRequest()
            )
            item = next(response)
        except Exception:
            raise FetchX509SvidError('X.509 SVID response is invalid')
        if len(item.svids) == 0:
            raise FetchX509SvidError('X.509 SVID response is empty')
        return item

    def _call_fetch_x509_bundles(self) -> workload_pb2.X509BundlesResponse:
        try:
            response = self._spiffe_workload_api_stub.FetchX509Bundles(
                workload_pb2.X509BundlesRequest()
            )
            item = next(response)
        except Exception:
            raise FetchX509BundleError('X.509 Bundles response is invalid')
        if len(item.bundles) == 0:
            raise FetchX509BundleError('X.509 Bundles response is empty')
        return item

    def _create_bundle_set(self, resp_bundles: Mapping[str, bytes]) -> X509BundleSet:
        x509_bundles = [
            self._create_x509_bundle(TrustDomain(td), resp_bundles[td])
            for td in resp_bundles
        ]
        return X509BundleSet.of(x509_bundles)

    @staticmethod
    def _create_x509_svid(svid: workload_pb2.X509SVID) -> X509Svid:
        cert = svid.x509_svid
        key = svid.x509_svid_key
        try:
            return X509Svid.parse_raw(cert, key)
        except Exception as e:
            raise FetchX509SvidError(str(e))

    @staticmethod
    def _create_x509_bundle(trust_domain: TrustDomain, bundle: bytes) -> X509Bundle:
        try:
            return X509Bundle.parse_raw(trust_domain, bundle)
        except Exception as e:
            raise FetchX509BundleError(str(e))

    def _call_fetch_jwt_svids(
        self, audience: List[str], spiffe_id: Optional[str] = None
    ) -> workload_pb2.JWTSVIDResponse:

        try:
            request = workload_pb2.JWTSVIDRequest()
            request.audience.extend(audience)
            if spiffe_id:
                request.spiffe_id = spiffe_id
            response = self._spiffe_workload_api_stub.FetchJWTSVID(request)
            item = next(response)
        except Exception as e:
            raise FetchJwtSvidError(str(e))
        if len(item.svids) == 0:
            raise FetchJwtSvidError('JWT SVID response is empty')
        return item

    def _process_x509_context(
        self, x509_svid_response: workload_pb2.X509SVIDResponse
    ) -> X509Context:
        svids = []
        bundle_set = self._create_bundle_set(x509_svid_response.federated_bundles)
        for svid in x509_svid_response.svids:
            x509_svid = self._create_x509_svid(svid)
            svids.append(x509_svid)

            trust_domain = x509_svid.spiffe_id().trust_domain()
            bundle_set.put(self._create_x509_bundle(trust_domain, svid.bundle))

        return X509Context(svids, bundle_set)

    def _call_watch_x509_context(
        self,
        cancel_handler: CancelHandler,
        retry_handler: _RetryHandler,
        on_success: Callable[[X509Context], None],
        on_error: Callable[[Exception], None],
        retry_connect: bool,
    ) -> None:

        response_iterator = self._spiffe_workload_api_stub.FetchX509SVID(
            workload_pb2.X509SVIDRequest()
        )

        # register the cancel function on the cancel handler returned to the user
        cancel_handler.set_handler(lambda: response_iterator.cancel())

        self._handle_x509_context_response(
            cancel_handler,
            retry_handler,
            response_iterator,
            on_success,
            on_error,
            retry_connect,
        )

    def _handle_x509_context_response(
        self,
        cancel_handler: CancelHandler,
        retry_handler: _RetryHandler,
        response_iterator: Iterator[workload_pb2.X509SVIDResponse],
        on_success: Callable[[X509Context], None],
        on_error: Callable[[Exception], None],
        retry_connect: bool,
    ) -> None:
        try:
            for item in response_iterator:
                x509_context = self._process_x509_context(item)
                retry_handler.reset()
                on_success(x509_context)

        except grpc.RpcError as grpc_err:
            self._handle_grpc_error(
                cancel_handler,
                retry_handler,
                grpc_err,
                on_success,
                on_error,
                retry_connect,
            )
        except Exception as err:
            error = FetchX509SvidError(format(str(err)))
            on_error(error)

    def _handle_grpc_error(
        self,
        cancel_handler: CancelHandler,
        retry_handler: _RetryHandler,
        grpc_error: grpc.RpcError,
        on_success: Callable[[X509Context], None],
        on_error: Callable[[Exception], None],
        retry_connect: bool,
    ):
        grpc_error_code = grpc_error.code()
        error = FetchX509SvidError(str(grpc_error_code))
        on_error(error)

        if retry_connect and grpc_error_code not in _NON_RETRYABLE_CODES:
            retry_handler.do_retry(
                self._call_watch_x509_context,
                [cancel_handler, retry_handler, on_success, on_error, retry_connect],
            )
