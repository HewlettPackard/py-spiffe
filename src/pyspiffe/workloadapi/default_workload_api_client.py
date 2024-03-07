"""
This module provides a Workload API client.
"""

import logging
import threading
import time
from typing import Optional, List, Mapping, Iterator, Callable, Dict

import grpc
from pyspiffe.workloadapi.cancel_handler import CancelHandler
from pyspiffe.workloadapi.x509_context import X509Context
from pyspiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from pyspiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from pyspiffe.bundle.jwt_bundle.jwt_bundle_set import JwtBundleSet
from pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from pyspiffe.config import ConfigSetter
from pyspiffe.exceptions import ArgumentError
from pyspiffe.proto.spiffe import (
    workload_pb2_grpc,
    workload_pb2,
)
from pyspiffe.spiffe_id.spiffe_id import TrustDomain
from pyspiffe.workloadapi.handle_error import handle_error
from pyspiffe.workloadapi.exceptions import (
    FetchX509SvidError,
    FetchX509BundleError,
    FetchJwtSvidError,
    FetchJwtBundleError,
    ValidateJwtSvidError,
)
from pyspiffe.workloadapi.grpc import header_manipulator_client_interceptor
from pyspiffe.svid.x509_svid import X509Svid
from pyspiffe.svid.jwt_svid import JwtSvid
from pyspiffe.spiffe_id.spiffe_id import SpiffeId

from pyspiffe.workloadapi.workload_api_client import (
    WorkloadApiClient,
    WORKLOAD_API_HEADER_KEY,
    WORKLOAD_API_HEADER_VALUE,
)

_logger = logging.getLogger(__name__)

__all__ = ['DefaultWorkloadApiClient']


# GRPC Error Codes that the client will not retry on:
#  - INVALID_ARGUMENT is not retried according to the SPIFFE spec because the request is invalid
#  - CANCELLED is not retried because it occurs when the caller has canceled the operation.
_NON_RETRYABLE_CODES = {grpc.StatusCode.CANCELLED, grpc.StatusCode.INVALID_ARGUMENT}


class RetryHandler:
    """Handler that performs retries using an exponential backoff policy."""

    UNLIMITED_RETRIES = 0

    def __init__(
        self,
        max_retries: int = UNLIMITED_RETRIES,
        base_backoff_in_seconds: float = 0.1,
        backoff_factor: int = 2,
        max_delay_in_seconds: float = 60,
    ) -> None:
        """Creates a RetryHandler that keeps track of retries and allows the execution of a callable using an
           exponential backoff policy.

        Args:
            max_retries: The maximum number of times that the handler will retry. Default: 0 (no maximum).
            base_backoff_in_seconds: The initial delay in seconds and base number that will be multiplied by an exponential factor in each
                                     retry backoff calculation.
            max_delay_in_seconds: The maximum delay expressed in seconds.
            backoff_factor: Base of the exponential calculation: base_backoff * pow(backoff_factor, retry_number).
        """
        self._max_retries = max_retries
        self._base_backoff = base_backoff_in_seconds
        self._backoff_factor = backoff_factor
        self._max_delay_in_seconds = max_delay_in_seconds
        self._retries_count = 0
        self._lock = threading.RLock()

    def do_retry(self, fn: Callable, params: List) -> bool:
        """Executes the callable after after a backoff delay calculated based on an exponential policy."""
        with self._lock:
            if self._max_retries and self._retries_count >= self._max_retries:
                return False
            self._retries_count += 1
            backoff = self._calculate_backoff()

        time.sleep(backoff)
        fn(*params)
        return True

    def reset(self):
        """Resets the handler setting the retries counting to zero."""
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

    def __init__(self, spiffe_socket: Optional[str]) -> None:
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
                        is fetched from the Workload API.

            on_error: A Callable accepting an Exception as argument and returning None, to be executed when there is
                      an error on the connection with the Workload API after what there is no retries.

            retry_connect: Enable retries when the connection with the Workload API returns an error.
                           Default: True.

        Returns:
            CancelHandler: An object on which it can be called the method `cancel` to close the stream connection with
                           the Workload API.
        """

        cancel_handler = CancelHandler(None)

        retry_handler = RetryHandler() if retry_connect else None

        # start listening for updates in a separate thread
        t = threading.Thread(
            target=self._call_watch_x509_context,
            args=(cancel_handler, retry_handler, on_success, on_error),
            daemon=True,
        )
        t.start()

        # this handler is initialized later after the call to the Workload API
        return cancel_handler

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
        return self._create_bundle_set(response.bundles)

    @handle_error(error_cls=FetchJwtSvidError)
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
            FetchJwtSvidError: In case there is an error in fetching the JWT-SVID from the Workload API.
        """
        if not audiences:
            raise ArgumentError('Parameter audiences cannot be empty')

        subject_str = str(subject) if subject is not None else ''
        response = self._spiffe_workload_api_stub.FetchJWTSVID(
            request=workload_pb2.JWTSVIDRequest(
                audience=audiences,
                spiffe_id=subject_str,
            )
        )

        if len(response.svids) == 0:
            raise FetchJwtSvidError('JWT SVID response is empty')

        svid = response.svids[0].svid
        return JwtSvid.parse_insecure(svid, audiences)

    @handle_error(error_cls=FetchJwtBundleError)
    def fetch_jwt_bundles(self) -> JwtBundleSet:
        """Fetches the JWT bundles for JWT-SVID validation, keyed by trust domain.

        Returns:
            JwtBundleSet: Set of JwtBundle objects.

        Raises:
            FetchJwtBundleError: In case there is an error in fetching the JWT-Bundle from the Workload API or
                                in case the set of jwt_authorities cannot be parsed from the Workload API Response.
        """

        responses = self._spiffe_workload_api_stub.FetchJWTBundles(
            workload_pb2.JWTBundlesRequest(), timeout=10
        )
        res = next(responses)
        jwt_bundles: Dict[TrustDomain, JwtBundle] = self._create_td_jwt_bundle_dict(res)
        if not jwt_bundles:
            raise FetchJwtBundleError('JWT Bundles response is empty')

        return JwtBundleSet(jwt_bundles)

    def watch_jwt_bundles(
        self,
        on_success: Callable[[JwtBundleSet], None],
        on_error: Callable[[Exception], None],
        retry_connect: bool = True,
    ) -> CancelHandler:
        """Watches for changes to the JWT bundles.

        This method returns immediately and spawns a new thread to handle the connection with the Workload API. That thread
        will keep running until the client calls the method `cancel` on the returned CancelHandler, or in case
        `retry_connect` is false and there is an error returned by the Workload API.

        A new Stream to the Workload API is opened for each call to this method, so that the client starts getting
        updates immediately after the Stream is ready and doesn't have to wait until the Workload API dispatches
        the next update based on the SVIDs TTL.

        Args:
            on_success: A Callable accepting a JwtBundleSet as argument and returning None, to be executed when a new
                        update is fetched from the Workload API.

            on_error: A Callable accepting an Exception as argument and returning None, to be executed when there is
                      an error on the connection with the Workload API.

            retry_connect: Enable retries when the connection with the Workload API returns an error. Default: True.

        Returns:
            CancelHandler: An object on which it can be called the method `cancel` to close the stream connection with
                           the Workload API.
        """

        cancel_handler = CancelHandler(None)

        retry_handler = RetryHandler() if retry_connect else None

        # start listening for updates in a separate thread
        t = threading.Thread(
            target=self._call_watch_jwt_bundles,
            args=(cancel_handler, retry_handler, on_success, on_error),
            daemon=True,
        )
        t.start()

        # this handler is initialized later after the call to the Workload API
        return cancel_handler

    @handle_error(error_cls=ValidateJwtSvidError)
    def validate_jwt_svid(self, token: str, audience: str) -> JwtSvid:
        """Validates the JWT-SVID token. The parsed and validated JWT-SVID is returned.

        Args:
            token: JWT to validate.
            audience: Audience to validate against.

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
            request=workload_pb2.ValidateJWTSVIDRequest(
                audience=audience,
                svid=token,
            )
        )

        return JwtSvid.parse_insecure(token, [audience])

    def get_spiffe_endpoint_socket(self) -> str:
        """Returns the spiffe endpoint socket config for this WorkloadApiClient.

        Returns:
            str: spiffe endpoint socket configuration value.
        """

        return self._config.spiffe_endpoint_socket

    def close(self) -> None:
        """Closes the WorkloadClient along with the current connections."""
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
        response = self._spiffe_workload_api_stub.FetchX509SVID(
            workload_pb2.X509SVIDRequest()
        )
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

    def _create_bundle_set(self, resp_bundles: Mapping[str, bytes]) -> X509BundleSet:
        x509_bundles = [
            self._create_x509_bundle(TrustDomain.parse(td), resp_bundles[td])
            for td in resp_bundles
        ]
        return X509BundleSet.of(x509_bundles)

    @staticmethod
    def _create_x509_svid(svid: workload_pb2.X509SVID) -> X509Svid:
        cert = svid.x509_svid
        key = svid.x509_svid_key
        return X509Svid.parse_raw(cert, key)

    @staticmethod
    def _create_x509_bundle(trust_domain: TrustDomain, bundle: bytes) -> X509Bundle:
        try:
            return X509Bundle.parse_raw(trust_domain, bundle)
        except Exception as e:
            raise FetchX509BundleError(str(e))

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
        retry_handler: Optional[RetryHandler],
        on_success: Callable[[X509Context], None],
        on_error: Callable[[Exception], None],
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
        )

    def _handle_x509_context_response(
        self,
        cancel_handler: CancelHandler,
        retry_handler: Optional[RetryHandler],
        response_iterator: Iterator[workload_pb2.X509SVIDResponse],
        on_success: Callable[[X509Context], None],
        on_error: Callable[[Exception], None],
    ) -> None:
        try:
            for item in response_iterator:
                x509_context = self._process_x509_context(item)
                if retry_handler:
                    retry_handler.reset()
                on_success(x509_context)

        except grpc.RpcError as grpc_err:
            self._handle_grpc_error(
                cancel_handler,
                retry_handler,
                grpc_err,
                on_success,
                on_error,
            )
        except Exception as err:
            error = FetchX509SvidError(format(str(err)))
            on_error(error)

    def _handle_grpc_error(
        self,
        cancel_handler: CancelHandler,
        retry_handler: Optional[RetryHandler],
        grpc_error: grpc.RpcError,
        on_success: Callable[[X509Context], None],
        on_error: Callable[[Exception], None],
    ):
        grpc_error_code = grpc_error.code()

        if retry_handler and grpc_error_code not in _NON_RETRYABLE_CODES:
            _logger.error(
                'Error connecting to the Workload API: {}'.format(str(grpc_error_code))
            )
            retry_handler.do_retry(
                self._call_watch_x509_context,
                [cancel_handler, retry_handler, on_success, on_error],
            )
        else:
            # don't retry, instead report error to user on the on_error callback
            error = FetchX509SvidError(str(grpc_error_code))
            on_error(error)

    def _call_watch_jwt_bundles(
        self,
        cancel_handler: CancelHandler,
        retry_handler: Optional[RetryHandler],
        on_success: Callable[[JwtBundleSet], None],
        on_error: Callable[[Exception], None],
    ) -> None:
        try:
            response_iterator = self._spiffe_workload_api_stub.FetchJWTBundles(
                workload_pb2.JWTBundlesRequest()
            )

            # register the cancel function on the cancel handler returned to the user
            cancel_handler.set_handler(lambda: response_iterator.cancel())

            for item in response_iterator:
                jwt_bundles = self._create_td_jwt_bundle_dict(item)
                if retry_handler:
                    retry_handler.reset()
                on_success(JwtBundleSet(jwt_bundles))
        except grpc.RpcError as rpc_error:
            if isinstance(rpc_error, grpc.Call):
                on_error(FetchJwtBundleError(str(rpc_error.details())))
                if retry_handler and rpc_error.code() not in _NON_RETRYABLE_CODES:
                    retry_handler.do_retry(
                        self._call_watch_jwt_bundles,
                        [cancel_handler, retry_handler, on_success, on_error],
                    )
            else:
                on_error(
                    FetchJwtBundleError('Cannot process response from Workload API')
                )
        except Exception as error:
            on_error(FetchJwtBundleError(str(error)))

    @staticmethod
    def _create_td_jwt_bundle_dict(
        jwt_bundle_response: workload_pb2.JWTBundlesResponse,
    ) -> Dict[TrustDomain, JwtBundle]:
        jwt_bundles = {}
        for td, jwk_set in jwt_bundle_response.bundles.items():
            jwt_bundles[TrustDomain.parse(td)] = JwtBundle.parse(
                TrustDomain.parse(td), jwk_set
            )

        return jwt_bundles
