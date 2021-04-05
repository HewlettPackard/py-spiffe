"""
This module contains the Workload API abstraction.
"""
from abc import ABC, abstractmethod
from typing import Optional, List, Set

from pyspiffe.bundle.jwt_bundle.jwt_bundle_set import JwtBundleSet
from pyspiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from pyspiffe.svid.jwt_svid import JwtSvid
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.svid.x509_svid import X509Svid
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
            subject: SpiffeId subject for the JWT SVID.

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
