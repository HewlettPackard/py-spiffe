"""
This module defines the default source implementation for JWT Bundles and SVIDs.
"""
import logging
import threading
from contextlib import suppress
from typing import Optional, List

from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from pyspiffe.bundle.jwt_bundle.jwt_bundle.jwt_bundle_set import JwtBundleSet
from pyspiffe.spiffe_id.trust_domain import TrustDomain
from pyspiffe.svid.jwt_svid import JwtSvid
from pyspiffe.workloadapi.default_workload_api_client import DefaultWorkloadApiClient
from pyspiffe.workloadapi.workload_api_client import WorkloadApiClient
from pyspiffe.workloadapi.jwt_source import JwtSource
from pyspiffe.workloadapi.exceptions import JwtSourceError


class DefaultJwtSource(JwtSource):
    """Default implementation of JwtSource. This class may be used by clients to get updated JWT-SVIDs and JWT bundles without the need to contact WorkloadAPI.
    DefaultJwtSource treates updates from WorkloadAPI and keeps JWT-SVID and JWT bundles updated.
    """

    def __init__(
        self,
        audiences: List[str],
        workload_api_client: WorkloadApiClient = None,
        spiffe_socket: str = None,
        timeout_in_seconds: float = None,
        subject: Optional[SpiffeId] = None,
    ) -> None:
        """Creates a new JwtSource.
           It blocks until the initial update has been received from the Workload API or until timeout_in_seconds is reached.
           In case the underlying Workload API connection returns an unretryable error, the source will be closed and
           no methods on the source will be available.
        Args:
            workload_api_client: A WorkloadApiClient that will be used to fetch the JWT materials from the Workload API.
                                 In case it's not provided, a default client will be created.
            spiffe_socket: Path to Workload API UDS. This will be used in case a the workload_api_client is not provided.
                           If not specified, the SPIFFE_ENDPOINT_SOCKET environment variable will be used and thus, must be set.
            timeout_in_seconds: Time to wait for the first update of the Workload API. If no timeout is provided, and
                                the connection with the Workload API fails, it will block indefinitely while
                                the connection is retried.
            audiences: List of audiences for the JWT SVID.
            subject: SPIFFE ID subject for the JWT.
        Returns:
            DefaultJwtSource: New DefaultJwtSource object, initialized with the JwtContext fetched from the Workload API.
        Raises:
            ArgumentError: If spiffe_socket_path is invalid or not provided and SPIFFE_ENDPOINT_SOCKET env variable is not set.
            JwtSourceError: In case a timeout was configured and it was reached during the source initialization waiting
                             for the first update from the Workload API.
        """

        self._initialized = threading.Event()
        self._lock = threading.Lock()
        self._closed = False
        self._audiences = audiences
        self._subject = subject
        self._workload_api_client = (
            workload_api_client
            if workload_api_client
            else DefaultWorkloadApiClient(spiffe_socket)
        )

        # set the watcher that will keep the source updated and log the underlying errors
        self._client_cancel_handler = self._workload_api_client.fetch_jwt_bundles(
            self._set_context, self._log_error
        )

        self._initialized.wait(timeout_in_seconds)

        if not self._initialized.is_set():
            self._client_cancel_handler.cancel()
            raise JwtSourceError(
                'Could not initialize JWT Source: reached timeout waiting for the first update'
            )

    def get_jwt_svid(self) -> JwtSvid:
        """Returns an JWT-SVID from the source.

        Raises:
            JwtSourceError: In case this JWT Source is closed.
        """
        with self._lock:
            if self._closed:
                raise JwtSourceError('Cannot get JWT SVID: source is closed')
            return self._jwt_svid

    def get_bundle_for_trust_domain(
        self, trust_domain: TrustDomain
    ) -> Optional[JwtBundle]:
        """Returns the JWT bundle for the given trust domain.

        Raises:
            JwtSourceError: In case this JWT Source is closed.
        """
        with self._lock:
            if self._closed:
                raise JwtSourceError('Cannot get JWT Bundle: source is closed')
            return self._jwt_bundle_set.get(trust_domain)

    def close(self) -> None:
        """Closes this JwtSource closing the underlying connection with the Workload API. Once the source is closed,
        no methods can be called on it.

        IMPORTANT: client code must call this method when the JwtSource is not needed anymore as the connection with Workload API will
        only be closed when this method is invoked.
        """
        with self._lock:
            # the cancel method throws a grpc exception, that can be discarded
            with suppress(Exception):
                self._client_cancel_handler.cancel()
            # TODO: double check this: prevents blocking on the constructor
            self._initialized.set()
            self._closed = True

    def _set_context(self, jwt_bundle_set: JwtBundleSet) -> None:
        try:
            _jwt_svid = self._workload_api_client.fetch_jwt_svid(
                self._audiences, self._subject
            )
            with self._lock:
                self._jwt_svid = _jwt_svid
                self._jwt_bundle_set = jwt_bundle_set
                self._initialized.set()
        except Exception as err:
            logging.error('JWT Source: error setting JWT context: {}.'.format(str(err)))
            logging.error('JWT Source: closing due to invalid state.')
            self.close()

    def _log_error(self, err: Exception) -> None:
        logging.error('JWT Source: Workload API client error: {}.'.format(str(err)))
        logging.error('JWT Source: closing.')
        self.close()