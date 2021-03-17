from typing import Optional, Set
from abc import ABC, abstractmethod
from pyspiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from pyspiffe.bundle.jwt_bundle.jwt_bundle_set import JwtBundleSet
from pyspiffe.svid.x509_svid import X509Svid
from pyspiffe.svid.jwt_svid import JwtSvid

WORKLOAD_API_HEADER = 'workload.spiffe.io'
HEADER_TRUE_VALUE = 'true'


class WorkloadApiClient(ABC):
    """Abstract class definition for a SPIFFE Workload API Client."""

    @abstractmethod
    def fetch_x509_svid(self) -> X509Svid:
        """Fetches a SPIFFE X.509-SVID.

        Returns:
            X509Svid: Instance of X509Svid object.
        """

    @abstractmethod
    def fetch_x509_bundles(self) -> X509BundleSet:
        """Fetches X.509 bundles, keyed by trust domain.

        Returns:
            X509BundleSet: Set of X509Bundle objects.
        """

    @abstractmethod
    def fetch_jwt_svid(
        self, audiences: Set[str], subject: Optional[str] = None
    ) -> JwtSvid:
        """Fetches a SPIFFE JWT-SVID.

        Args:
            audiences: Set of audiences for the JWT.
            subject: SPIFFE ID Subject for the JWT.

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
