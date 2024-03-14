""""
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

"""
This module defines the default source implementation for JWT Bundles and SVIDs.
"""

import logging
import threading
from typing import Optional, Set

from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from pyspiffe.bundle.jwt_bundle.jwt_bundle_set import JwtBundleSet
from pyspiffe.spiffe_id.spiffe_id import TrustDomain
from pyspiffe.svid.jwt_svid import JwtSvid
from pyspiffe.workloadapi.default_workload_api_client import DefaultWorkloadApiClient
from pyspiffe.workloadapi.workload_api_client import WorkloadApiClient
from pyspiffe.workloadapi.jwt_source import JwtSource
from pyspiffe.workloadapi.exceptions import JwtSourceError
from pyspiffe.exceptions import ArgumentError

_logger = logging.getLogger(__name__)


class DefaultJwtSource(JwtSource):
    """Default implementation of JwtSource. This class may be used by clients to get updated JWT-SVIDs and JWT bundles.

    DefaultJwtSource treates updates from Workload API and keeps JWT bundles updated.
    """

    def __init__(
        self,
        workload_api_client: Optional[WorkloadApiClient],
        spiffe_socket_path: Optional[str],
        timeout_in_seconds: Optional[float],
    ) -> None:
        """Creates a new DefaultJwtSource.

           It blocks until the initial update has been received from the Workload API or until timeout_in_seconds is reached.
           In case the underlying Workload API connection returns an unretryable error, the source will be closed and
           no methods on the source will be available.

        Args:
            workload_api_client: A WorkloadApiClient object that will be used to fetch the JWT materials from the Workload API.
                                 In case it's not provided, a default client will be created.
            spiffe_socket_path: Path to Workload API UDS. This will be used in case a the workload_api_client is not provided.
                           If not specified, the SPIFFE_ENDPOINT_SOCKET environment variable will be used and thus, must be set.
            timeout_in_seconds: Time to wait for the first update of the Workload API. If not provided, and
                                the connection with the Workload API fails, it will block indefinitely while
                                the connection is retried.

        Returns:
            DefaultJwtSource: New DefaultJwtSource object, initialized with the JwtBundleSet fetched from the Workload API.

        Raises:
            ArgumentError: If spiffe_socket_path is invalid or not provided and SPIFFE_ENDPOINT_SOCKET env variable is not set.
            JwtSourceError: In case a timeout was configured and it was reached during the source initialization waiting
                             for the first update from the Workload API.
        """

        self._initialized = threading.Event()
        self._lock = threading.Lock()
        self._closed = False
        self._workload_api_client = (
            workload_api_client
            if workload_api_client
            else DefaultWorkloadApiClient(spiffe_socket_path)
        )

        # set the watcher that will keep the source updated and log the underlying errors
        self._client_cancel_handler = self._workload_api_client.watch_jwt_bundles(
            self._set_jwt_data, self._on_error
        )
        self._initialized.wait(timeout_in_seconds)

        if not self._initialized.is_set():
            self._client_cancel_handler.cancel()
            raise JwtSourceError(
                'Could not initialize JWT Source: reached timeout waiting for the first update'
            )

    def get_jwt_svid(
        self, audiences: Set[str], subject: Optional[SpiffeId] = None
    ) -> JwtSvid:
        """Returns an JWT-SVID from the source.

        Args:
            audiences: List of audiences for the JWT SVID.
            subject: SPIFFE ID subject for the JWT.

        Raises:
            ArgumentError: In case audiences is empty.
            FetchJwtSvidError: In case there is an error in fetching the JWT-SVID from the Workload API.
        """
        if not audiences:
            raise ArgumentError('Audience cannot be empty')

        jwt_svid = self._workload_api_client.fetch_jwt_svid(audiences, subject)
        return jwt_svid

    def get_jwt_bundle(self, trust_domain: TrustDomain) -> Optional[JwtBundle]:
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
            try:
                self._client_cancel_handler.cancel()
            except Exception as err:
                _logger.exception(
                    'JWT Source: Exception canceling the Workload API client connection: {}'.format(
                        str(err)
                    )
                )
            self._initialized.set()
            self._closed = True

    def is_closed(self) -> bool:
        """Returns True if the connection to Workload API is closed."""
        with self._lock:
            return self._closed

    def _set_jwt_data(self, jwt_bundle_set: JwtBundleSet) -> None:
        with self._lock:
            self._jwt_bundle_set = jwt_bundle_set
            self._initialized.set()

    def _on_error(self, error: Exception) -> None:
        self._log_error(error)
        self.close()

    def _log_error(self, err: Exception) -> None:
        _logger.error('JWT Source: Workload API client error: {}'.format(str(err)))
        _logger.error('JWT Source: closing.')
