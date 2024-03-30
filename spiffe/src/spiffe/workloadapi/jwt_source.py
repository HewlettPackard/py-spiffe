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

import logging
import threading
from typing import Optional, Set, Callable, List

from spiffe.spiffe_id.spiffe_id import SpiffeId
from spiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from spiffe.bundle.jwt_bundle.jwt_bundle_set import JwtBundleSet
from spiffe.spiffe_id.spiffe_id import TrustDomain
from spiffe.svid.jwt_svid import JwtSvid
from spiffe.workloadapi.workload_api_client import WorkloadApiClient
from spiffe.workloadapi.errors import JwtSourceError
from spiffe.errors import ArgumentError

"""
This module defines the default source implementation for JWT Bundles and SVIDs.
"""

_logger = logging.getLogger(__name__)

__all__ = ['JwtSource']


class JwtSource:
    """
    JWTSource acts as a source for JWT-SVIDs and JWT bundles, automatically maintained through
    updates from the Workload API.
    """

    def __init__(
        self,
        workload_api_client: Optional[WorkloadApiClient] = None,
        socket_path: Optional[str] = None,
        timeout_in_seconds: Optional[float] = None,
    ) -> None:
        """Creates a new JwtSource.

           It blocks until the initial update has been received from the Workload API or until timeout_in_seconds is reached.
           In case the underlying Workload API connection returns an unretryable error, the source will be closed and
           no methods on the source will be available.

        Args:
            workload_api_client: A WorkloadApiClient object that will be used to fetch the JWT materials from the Workload API.
                                 In case it's not provided, a default client will be created.
            socket_path: Path to Workload API UDS. This will be used in case a the workload_api_client is not provided.
                           If not specified, the SPIFFE_ENDPOINT_SOCKET environment variable will be used and thus, must be set.
            timeout_in_seconds: Time to wait for the first update of the Workload API. If not provided, and
                                the connection with the Workload API fails, it will block indefinitely while
                                the connection is retried.

        Returns:
            JwtSource: New DefaultJwtSource object, initialized with the JwtBundleSet fetched from the Workload API.

        Raises:
            ArgumentError: If spiffe_socket_path is invalid or not provided and SPIFFE_ENDPOINT_SOCKET env variable is not set.
            JwtSourceError: In case a timeout was configured and it was reached during the source initialization waiting
                             for the first update from the Workload API.
        """

        self._initialization_event = threading.Event()
        self._error: Optional[Exception] = None
        self._closed = False
        self._lock = threading.Lock()
        self._subscribers: List[Callable] = []
        self._subscribers_lock = threading.Lock()

        self._workload_api_client = (
            workload_api_client if workload_api_client else WorkloadApiClient(socket_path)
        )

        # Start the watcher in a separate thread
        threading.Thread(target=self._start_watcher).start()

        # Wait for the first update or an error
        initialized = self._initialization_event.wait(timeout=timeout_in_seconds)

        if not initialized or self._error:
            self._closed = True
            if self._error:
                if self._error:
                    raise JwtSourceError(
                        f"Failed to create JwtSource: {self._error}"
                    ) from self._error
                else:
                    raise JwtSourceError(
                        "Failed to initialize JwtSource: Timeout waiting for the first update."
                    )

    @property
    def bundles(self) -> Set[JwtBundle]:
        """Returns the set of all JwtBundles."""
        with self._lock:
            if self._closed:
                raise JwtSourceError('Cannot get Jwt Bundles: source is closed')
            return self._jwt_bundle_set.bundles

    def fetch_svid(self, audience: Set[str], subject: Optional[SpiffeId] = None) -> JwtSvid:
        """Fetches an JWT-SVID from the source.

        Args:
            audience: List of audiences for the JWT SVID.
            subject: SPIFFE ID subject for the JWT.

        Raises:
            ArgumentError: In case audiences is empty.
            FetchJwtSvidError: In case there is an error in fetching the JWT-SVID from the Workload API.
        """
        if not audience:
            raise ArgumentError('Audience cannot be empty')

        jwt_svid = self._workload_api_client.fetch_jwt_svid(audience, subject)
        return jwt_svid

    def fetch_svids(self, audiences: Set[str], subject: Optional[SpiffeId] = None) -> JwtSvid:
        """Fetches all JWT-SVIDs from the source.

        Args:
            audiences: List of audiences for the JWT SVID.
            subject: SPIFFE ID subject for the JWT.

        Raises:
            ArgumentError: In case audiences is empty.
            FetchJwtSvidError: In case there is an error in fetching the JWT-SVID from the Workload API.
        """
        if not audiences:
            raise ArgumentError('Audience cannot be empty')

        jwt_svid = self._workload_api_client.fetch_jwt_svids(audiences, subject)
        return jwt_svid

    def get_bundle_for_trust_domain(self, trust_domain: TrustDomain) -> Optional[JwtBundle]:
        """Returns the JWT bundle for the given trust domain.

        Raises:
            JwtSourceError: In case this JWT Source is closed.
        """
        with self._lock:
            if self._closed:
                raise JwtSourceError('Cannot get JWT Bundle: source is closed')
            return self._jwt_bundle_set.get_bundle_for_trust_domain(trust_domain)

    def close(self) -> None:
        """Closes this JwtSource closing the underlying connection with the Workload API. Once the source is closed,
        no methods can be called on it.

        IMPORTANT: client code must call this method when the JwtSource is not needed anymore as the connection with Workload API will
        only be closed when this method is invoked.
        """
        _logger.info("Closing JWT Source")
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
            self._closed = True

    def is_closed(self) -> bool:
        """Checks if the source has been closed, disallowing further operations."""
        with self._lock:
            return self._closed

    def subscribe_for_updates(self, callback: Callable[[], None]) -> None:
        """
        Allows clients to register a callback function for updates on the source.

        Args:
            callback (Callable[[], None]): The callback function to register.
        """
        with self._subscribers_lock:
            self._subscribers.append(callback)

    def unsubscribe_for_updates(self, callback: Callable[[], None]) -> None:
        """
        Allows clients to unregister a previously registered callback function.

        Args:
            callback (Callable[[], None]): The callback function to unregister.
        """
        with self._subscribers_lock:
            self._subscribers.remove(callback)

    def _start_watcher(self) -> None:
        self._client_cancel_handler = self._workload_api_client.stream_jwt_bundles(
            self._set_jwt_bundle_set, self._on_error
        )

    def _set_jwt_bundle_set(self, jwt_bundle_set: JwtBundleSet) -> None:
        _logger.debug('JWT Source: setting new bundle update')
        with self._lock:
            self._jwt_bundle_set = jwt_bundle_set

        # Signal that the JwtSource has been successfully initialized
        self._initialization_event.set()
        self._notify_subscribers()

    def _notify_subscribers(self) -> None:
        with self._subscribers_lock:
            for callback in self._subscribers:
                try:
                    callback()
                except Exception as err:
                    _logger.exception(f"An error occurred while notifying a subscriber: {err}")

    def _on_error(self, error: Exception) -> None:
        self._log_error(error)
        self._error = error
        self._initialization_event.set()

    @staticmethod
    def _log_error(err: Exception) -> None:
        _logger.error(f"JWT Source Error: {err}")

    def __enter__(self) -> 'JwtSource':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
