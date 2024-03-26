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
from typing import Optional, Callable, List, Set

from spiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from spiffe.spiffe_id.spiffe_id import TrustDomain
from spiffe.svid.x509_svid import X509Svid
from spiffe.workloadapi.errors import X509SourceError
from spiffe.workloadapi.workload_api_client import WorkloadApiClient
from spiffe.workloadapi.x509_context import X509Context

_logger = logging.getLogger(__name__)

"""
This module provides an implementation of an X.509 Source.
"""


class X509Source:
    """Source of X509-SVIDs and X.509 bundles maintained via the Workload API."""

    def __init__(
        self,
        workload_api_client: Optional[WorkloadApiClient] = None,
        spiffe_socket_path: Optional[str] = None,
        timeout_in_seconds: Optional[float] = None,
        picker: Optional[Callable[[List[X509Svid]], X509Svid]] = None,
    ) -> None:
        """Creates a new X509Source.

           It blocks until the initial update has been received from the Workload API or until timeout_in_seconds is reached.

           In case the underlying Workload API connection returns an unretryable error, the source will be closed and
           no methods on the source will be available.


        Args:
            workload_api_client: A WorkloadApiClient that will be used to fetch the X.509 materials from the Workload API.
                                 In case it's not provided, a default client will be created.

            spiffe_socket_path: Path to Workload API UDS. This will be used in case a the workload_api_client is not provided.
                           If not specified, the SPIFFE_ENDPOINT_SOCKET environment variable must be set.

            timeout_in_seconds: Time to wait for the first update of the Workload API. If no timeout is provided, and
                                the connection with the Workload API fails, it will block Indefinitely while
                                the connection is retried.

            picker: Function to choose the X.509 SVID from the list returned by the Workload API.
                    If it is not set, the default SVID is picked. If the picker function throws an error,
                    it will render the X509Source invalid and it will be closed.

        Returns:
            X509Source: New X509Source object, initialized with the X509Context fetched from the Workload API.

        Raises:
            ArgumentError: If spiffe_socket_path is invalid or not provided and SPIFFE_ENDPOINT_SOCKET env variable is not set.

            X509SourceError: In case a timeout was configured and it was reached during the source initialization waiting
                             for the first update from the Workload API.
        """

        self._initialized = threading.Event()
        self._lock = threading.Lock()
        self._closed = False
        self._workload_api_client = (
            workload_api_client
            if workload_api_client
            else WorkloadApiClient(spiffe_socket_path)
        )
        self._picker = picker

        self._subscribers: List[Callable] = []
        self._subscribers_lock = threading.Lock()

        # set the watcher that will keep the source updated and log the underlying errors
        self._client_cancel_handler = self._workload_api_client.watch_x509_context(
            self._set_context, self._on_error
        )

        self._initialized.wait(timeout_in_seconds)

        if not self._initialized.is_set():
            self._client_cancel_handler.cancel()
            raise X509SourceError(
                'Could not initialize X.509 Source: reached timeout waiting for the first update'
            )

    @property
    def svid(self) -> X509Svid:
        """Returns an X509-SVID from the source."""
        with self._lock:
            if self._closed:
                raise X509SourceError('Cannot get X.509 SVID: source is closed')
            return self._x509_svid

    @property
    def bundles(self) -> Set[X509Bundle]:
        """Returns the set of all X509Bundles."""
        with self._lock:
            if self._closed:
                raise X509SourceError('Cannot get X.509 Bundles: source is closed')
            return self._x509_bundle_set.bundles

    def get_bundle_for_trust_domain(
        self, trust_domain: TrustDomain
    ) -> Optional[X509Bundle]:
        """Returns the X.509 bundle for the given trust domain."""
        with self._lock:
            if self._closed:
                raise X509SourceError('Cannot get X.509 Bundle: source is closed')
            return self._x509_bundle_set.get_bundle_for_trust_domain(trust_domain)

    def close(self) -> None:
        """Closes this X509Source closing the underlying connection with the Workload API. Once the source is closed,
        no methods can be called on it.

        It is recommended that when an instance of an X509Source is no longer used the close() method be called on it,
        in order to liberate the resources used by the underlying connection with the Workload API.
        """
        _logger.info("Closing X.509 Source")
        with self._lock:
            try:
                self._client_cancel_handler.cancel()
            except Exception as err:
                _logger.exception(
                    'Exception canceling the Workload API client connection: {}'.format(
                        str(err)
                    )
                )
            # prevents blocking on the constructor
            self._initialized.set()
            self._closed = True

    def is_closed(self) -> bool:
        """Returns True if the connection to Workload API is closed."""
        with self._lock:
            return self._closed

    def subscribe_for_updates(self, callback: Callable) -> None:
        """
        Allows clients to register a callback function for updates on the source.
        """
        with self._subscribers_lock:
            self._subscribers.append(callback)

    def _set_context(self, x509_context: X509Context) -> None:
        if self._picker:
            try:
                svid = self._picker(x509_context.x509_svids)
            except Exception as err:
                _logger.error(
                    'X.509 Source: error picking X.509-SVID: {}.'.format(str(err))
                )
                _logger.error('X.509 Source: closing due to invalid state.')
                self.close()
                return
        else:
            svid = x509_context.default_svid

        _logger.debug('X.509 Source: setting new update')
        with self._lock:
            self._x509_svid = svid
            self._x509_bundle_set = x509_context.x509_bundle_set
            self._initialized.set()

        self._notify_subscribers()

    def _notify_subscribers(self) -> None:
        with self._subscribers_lock:
            for callback in self._subscribers:
                callback()

    def _on_error(self, error: Exception) -> None:
        self._log_error(error)
        self.close()

    @staticmethod
    def _log_error(err: Exception) -> None:
        _logger.error('X.509 Source: Workload API client error: {}.'.format(str(err)))

    def __enter__(self) -> 'X509Source':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
