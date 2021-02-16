from typing import cast

from pyspiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from pyspiffe.bundle.jwt_bundle.jwt_bundle_set import JwtBundleSet
from pyspiffe.config import ConfigSetter
from pyspiffe.svid.x509_svid import X509Svid
from pyspiffe.svid.jwt_svid import JwtSvid

from pyspiffe.workloadapi.workload_api_client import WorkloadApiClient
from pyspiffe.grpc.default_grpc_client import GrpcClient, DefaultGrpcClient


class DefaultWorkloadApiClient(WorkloadApiClient):
    """Default implementation for a SPIFFE Workload API Client."""

    def __init__(
        self,
        spiffe_socket: str = None,
        grpc_client: GrpcClient = cast(GrpcClient, DefaultGrpcClient),
    ) -> None:
        """Creates a new Workload API Client.

        Args:
            spiffe_socket (str, optional): Path to Workload API UDS. If
                not specified, the SPIFFE_ENDPOINT_SOCKET environment variable
                must be set.
            grpc_client (GrpcClient, optional): GrpcClient implementation to
                use. If not specified, uses DefaultGrpcClient.

        Returns:
            DefaultWorkloadApiClient: New Workload API Client object.

        Raises:
            ValueError: If spiffe_socket_path is invalid or not provided and
                SPIFFE_ENDPOINT_SOCKET environment variable doesn't exist
        """

        try:
            self._config = ConfigSetter(
                spiffe_endpoint_socket=spiffe_socket
            ).get_config()
        except ValueError:
            raise ValueError(
                'SPIFFE socket argument or environment variable invalid in DefaultWorkloadApiClient.'
            )

        self._channel = grpc_client.insecure_channel(
            spiffe_socket=self._config.spiffe_endpoint_socket
        )

    def get_spiffe_endpoint_socket(self) -> str:
        """Returns the spiffe endpoint socket config for this WorkloadApiClient.

        Returns:
            str: spiffe endpoint socket configuration value
        """

        return self._config.spiffe_endpoint_socket

    def fetch_x509_svid(self) -> X509Svid:
        """Fetches a SPIFFE X.509-SVID.

        Returns:
            X509Svid: Instance of X509Svid object
        """

        pass

    def fetch_x509_bundles(self) -> X509BundleSet:
        """Fetches X.509 bundles, keyed by trust domain.

        Returns:
            X509BundleSet: Set of X509Bundle objects
        """

        pass

    def fetch_jwt_svid(self, audiences: str, subject: str = None) -> JwtSvid:
        """Fetches a SPIFFE JWT-SVID.

        Args:
            audiences (set of str): Set of audiences for the JWT.
            subject (str, optional): SPIFFE ID Subject for the JWT.

        Returns:
            JwtSvid: Instance of JwtSvid object
        """

        pass

    def fetch_jwt_bundles(self) -> JwtBundleSet:
        """Fetches the JWT bundles for JWT-SVID validation, keyed by trust
        domain.

        Returns:
            JwtBundleSet: Set of JwtBundle objects
        """

        pass

    def validate_jwt_svid(self, token: str, audience: str) -> JwtSvid:
        """Validates the JWT-SVID token. The parsed and validated JWT-SVID is
        returned.

        Args:
            token (str): JWT to validate.
            audience (str): Audience to validate against.

        Returns:
            JwtSvid: If the token and audience could be validated.
        """

        pass
