"""
This module contains the Workload API abstraction.
"""
from abc import ABC, abstractmethod
from typing import Optional, List, Set, Callable

from pyspiffe.bundle.jwt_bundle.jwt_bundle_set import JwtBundleSet
from pyspiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from pyspiffe.svid.jwt_svid import JwtSvid
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.svid.x509_svid import X509Svid
from pyspiffe.workloadapi.cancel_handler import CancelHandler
from pyspiffe.workloadapi.x509_context import X509Context

WORKLOAD_API_HEADER_KEY = 'workload.spiffe.io'
WORKLOAD_API_HEADER_VALUE = 'true'


class WorkloadApiClient(ABC):
    """Abstract class definition for a SPIFFE Workload API Client."""

    @abstractmethod
    def fetch_x509_svid(self) -> X509Svid:
        """Fetches the default X509-SVID, i.e. the first in the list returned by the Workload API.

        Returns:
            X509Svid: Instance of X509Svid object.
        """

    @abstractmethod
    def fetch_x509_svids(self) -> List[X509Svid]:
        """Fetches all X509-SVIDs.

        Returns:
            A list of of X509Svid objects.
        """

    @abstractmethod
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

        Args:
            on_success: A Callable accepting a X509Context as argument and returning None, to be executed when a new update
                        is fetched from the Workload API.

            on_error: A Callable accepting an Exception as argument and returning None, to be executed when there is
                      an error on the connection with the Workload API.

            retry_connect: Enable retries when the connection with the Workload API returns an error.
                           Default: True.

        Returns:
            CancelHandler: An object on which it can be called the method `cancel` to close the stream connection with
                           the Workload API.
        """

    @abstractmethod
    def fetch_x509_context(self) -> X509Context:
        """Fetches an X.509 context (X.509 SVIDs and X.509 Bundles)

        Returns:
            X509Context: An object containing a list X509Svids and a X509BundleSet.
        """

    @abstractmethod
    def fetch_x509_bundles(self) -> X509BundleSet:
        """Fetches X.509 bundles, keyed by trust domain.

        Returns:
            X509BundleSet: Set of X509Bundle objects.
        """

    @abstractmethod
    def fetch_jwt_svid(
        self, audiences: Set[str], subject: Optional[SpiffeId] = None
    ) -> JwtSvid:
        """Fetches a SPIFFE JWT-SVID.

        Args:
            audiences: Set of audiences for the JWT SVID.
            subject: SPIFFE ID subject for the JWT SVID.

        Returns:
            JwtSvid: Instance of JwtSvid object.
        """

    @abstractmethod
    def fetch_jwt_bundles(self) -> JwtBundleSet:
        """Fetches the JWT bundles for JWT-SVID validation, keyed by trust
        domain.

        Returns:
            JwtBundleSet: Set of JwtBundle objects.
        """

    @abstractmethod
    def validate_jwt_svid(self, token: str, audience: str) -> JwtSvid:
        """Validates the JWT-SVID token. The parsed and validated JWT-SVID is
        returned.

        Args:
            token: JWT to validate.
            audience: Audience to validate against.

        Returns:
            JwtSvid: If the token and audience could be validated.
        """

    @abstractmethod
    def close(self) -> None:
        """Closes the WorkloadClient along with the current connections."""
