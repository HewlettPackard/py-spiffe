import os

from pyspiffe.workloadapi.workload_api_client import WorkloadApiClient
from pyspiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from pyspiffe.bundle.jwt_bundle.jwt_bundle_set import JwtBundleSet
from pyspiffe.svid.x509_svid import X509Svid
from pyspiffe.svid.jwt_svid import JwtSvid


class DefaultWorkloadApiClient(WorkloadApiClient):
    """
    Default implementation for a SPIFFE Workload API Client.
    """

    def __init__(self, spiffe_socket_path=None):
        """
        Create a new Workload API Client.

        Args:
            spiffe_socket_path (str, optional): Path to Workload API UDS. If
                not specified, the SPIFFE_ENDPOINT_SOCKET environment variable
                must be set.

        Returns:
            DefaultWorkloadApiClient: New Workload API Client object.

        Raises:
            RuntimeError if spiffe_socket_path is not provided and
                SPIFFE_ENDPOINT_SOCKET environment variable doesn't exist
        """

        if spiffe_socket_path is None:
            try:
                self.spiffe_socket_path = os.environ['SPIFFE_ENDPOINT_SOCKET']
            except KeyError:
                raise RuntimeError(
                    'SPIFFE_ENDPOINT_SOCKET environment variable not specified to DefaultWorkloadApiClient')
        else:
            self.spiffe_socket_path = spiffe_socket_path

    def fetch_x509_svid(self) -> X509Svid:
        """
        Fetches a SPIFFE X.509-SVID

        Returns:
            X509Svid: Instance of X509Svid object
        """

        pass

    def fetch_x509_bundles(self) -> X509BundleSet:
        """
        Fetches X.509 bundles, keyed by trust domain.

        Returns:
            X509BundleSet: Set of X509Bundle objects
        """

        pass

    def fetch_jwt_svid(self, audiences, subject=None) -> JwtSvid:
        """
        Fetches a SPIFFE JWT-SVID

        Args:
            audiences (set of str): Set of audiences for the JWT.
            subject (str, optional): SPIFFE ID Subject for the JWT.

        Returns:
            JwtSvid: Instance of JwtSvid object
        """

        pass

    def fetch_jwt_bundles(self) -> JwtBundleSet:
        """
        Fetches the JWT bundles for JWT-SVID validation, keyed by trust
        domain.

        Returns:
            JwtBundleSet: Set of JwtBundle objects
        """

        pass

    def validate_jwt_svid(self, token, audience) -> JwtSvid:
        """
        Validates the JWT-SVID token. The parsed and validated JWT-SVID is
        returned.

        Args:
            token (str): JWT to validate.
            audience (str): Audience to validate against.

        Returns:
            JwtSvid: If the token and audience could be validated.
        """

        pass
