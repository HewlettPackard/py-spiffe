from typing import Optional, Set
from pyspiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from pyspiffe.bundle.jwt_bundle.jwt_bundle_set import JwtBundleSet
from pyspiffe.config import ConfigSetter
from pyspiffe.svid.x509_svid import X509Svid
from pyspiffe.svid.jwt_svid import JwtSvid

from pyspiffe.workloadapi.workload_api_client import WorkloadApiClient


class DefaultWorkloadApiClient(WorkloadApiClient):
    """Default implementation for a SPIFFE Workload API Client."""

    def __init__(self, spiffe_socket: str = None) -> None:
        """Creates a new Workload API Client.

        Args:
            spiffe_socket: Path to Workload API UDS. If
                not specified, the SPIFFE_ENDPOINT_SOCKET environment variable
                must be set.

        Returns:
            DefaultWorkloadApiClient: New Workload API Client object.

        Raises:
            ValueError: If spiffe_socket_path is invalid or not provided and
                SPIFFE_ENDPOINT_SOCKET environment variable doesn't exist.
        """

        try:
            self._config = ConfigSetter(
                spiffe_endpoint_socket=spiffe_socket
            ).get_config()
        except ValueError:
            raise ValueError(
                'SPIFFE socket argument or environment variable invalid in DefaultWorkloadApiClient.'
            )

    def get_spiffe_endpoint_socket(self) -> str:
        """Returns the spiffe endpoint socket config for this WorkloadApiClient.

        Returns:
            str: spiffe endpoint socket configuration value.
        """

        return self._config.spiffe_endpoint_socket

    def fetch_x509_svid(self) -> X509Svid:
        """Fetches a SPIFFE X.509-SVID.

        Returns:
            X509Svid: Instance of X509Svid object.
        """

        pass

    def fetch_x509_bundles(self) -> X509BundleSet:
        """Fetches X.509 bundles, keyed by trust domain.

        Returns:
            X509BundleSet: Set of X509Bundle objects.
        """

        pass

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

        pass

    def fetch_jwt_bundles(self) -> JwtBundleSet:
        """Fetches the JWT bundles for JWT-SVID validation, keyed by trust
        domain.

        Returns:
            JwtBundleSet: Set of JwtBundle objects.
        """

        pass

    def validate_jwt_svid(self, token: str, audience: str) -> JwtSvid:
        """Validates the JWT-SVID token. The parsed and validated JWT-SVID is
        returned.

        Args:
            token: JWT to validate.
            audience: Audience to validate against.

        Returns:
            JwtSvid: If the token and audience could be validated.
        """

        pass
