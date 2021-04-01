from typing import Optional, Tuple, List

import grpc

from pyspiffe.utils.exceptions import normalized_exception_message
from pyspiffe.workloadapi.x509_context import X509Context
from pyspiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from pyspiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from pyspiffe.bundle.jwt_bundle.jwt_bundle_set import JwtBundleSet
from pyspiffe.config import ConfigSetter
from pyspiffe.proto.spiffe import (
    workload_pb2_grpc,
    workload_pb2,
)
from pyspiffe.spiffe_id.trust_domain import TrustDomain
from pyspiffe.workloadapi.exceptions import (
    FetchX509SvidError,
    FetchX509BundleError,
    FetchJwtSvidError,
)
from pyspiffe.workloadapi.grpc import header_manipulator_client_interceptor
from pyspiffe.svid.x509_svid import X509Svid
from pyspiffe.svid.jwt_svid import JwtSvid
from pyspiffe.svid.exceptions import JwtSvidError

from pyspiffe.workloadapi.workload_api_client import (
    WorkloadApiClient,
    WORKLOAD_API_HEADER_KEY,
    WORKLOAD_API_HEADER_VALUE,
)


class DefaultWorkloadApiClient(WorkloadApiClient):
    """Default implementation for a SPIFFE Workload API Client."""

    def __init__(self, spiffe_socket: str = None) -> None:
        """Creates a new Workload API Client.

        Args:
            spiffe_socket: Path to Workload API UDS. If not specified, the SPIFFE_ENDPOINT_SOCKET environment variable
                           must be set.

        Returns:
            DefaultWorkloadApiClient: New Workload API Client object.

        Raises:
            ValueError: If spiffe_socket_path is invalid or not provided and SPIFFE_ENDPOINT_SOCKET environment variable doesn't exist.
        """

        try:
            self._config = ConfigSetter(
                spiffe_endpoint_socket=spiffe_socket
            ).get_config()
        except ValueError as e:
            raise ValueError(
                'Invalid DefaultWorkloadApiClient configuration: {}'.format(str(e))
            )

        self._spiffe_workload_api_stub = workload_pb2_grpc.SpiffeWorkloadAPIStub(
            self._get_spiffe_grpc_channel()
        )

    def fetch_x509_svid(self) -> X509Svid:
        """Fetches the default X509-SVID, i.e. the first in the list returned by the Workload API.

        Returns:
            X509Svid: Instance of X509Svid object.

        Raises:
            FetchX509SvidError: When there is an error fetching the X.509 SVID from the Workload API, or when the
                                response payload cannot be processed to be converted to a X509Svid object.
        """

        response = self._call_fetch_x509_svid()

        svid = response.svids[0]

        return self._create_x509_svid(svid)

    def fetch_x509_svids(self) -> List[X509Svid]:
        """Fetches all X509-SVIDs.

        Returns:
            X509Svid: List of of X509Svid object.

        Raises:
            FetchX509SvidError: When there is an error fetching the X.509 SVID from the Workload API, or when the
                                response payload cannot be processed to be converted to a X509Svid object.
        """

        response = self._call_fetch_x509_svid()

        result = []
        for svid in response.svids:
            result.append(self._create_x509_svid(svid))

        return result

    def fetch_x509_context(self) -> X509Context:
        """Fetches an X.509 context (X.509 SVIDs and X.509 Bundles keyed by TrustDomain).

        Returns:
            X509Context: An object containing a List of X509Svids and a X509BundleSet.

        Raises:
            FetchX509SvidError: When there is an error fetching the X.509 SVID from the Workload API, or when the
                                response payload cannot be processed to be converted to a X509Svid object.

            FetchX509BundleError: When there is an error fetching the X.509 Bundles from the Workload API, or when the
                                  response payload cannot be processed to be converted to a X509Bundle objects.
        """
        response = self._call_fetch_x509_svid()

        svids = []
        bundle_set = self._create_bundle_set(response.federated_bundles)
        for svid in response.svids:
            x509_svid = self._create_x509_svid(svid)
            svids.append(x509_svid)

            trust_domain = x509_svid.spiffe_id().trust_domain()
            bundle_set.put(self._create_x509_bundle(trust_domain, svid.bundle))

        return X509Context(svids, bundle_set)

    def fetch_x509_bundles(self) -> X509BundleSet:
        """Fetches X.509 bundles, keyed by trust domain.

        Returns:
            X509BundleSet: Set of X509Bundle objects.

        Raises:
            FetchX509BundleError: When there is an error fetching the X.509 Bundles from the Workload API, or when the
                                  response payload cannot be processed to be converted to a X509Bundle objects.
        """
        response = self._call_fetch_x509_bundles()
        return self._create_bundle_set(response.bundles)

    def fetch_jwt_svid(
        self, audiences: List[str], subject: Optional[str] = None
    ) -> JwtSvid:
        """Fetches a SPIFFE JWT-SVID.

        Args:
            audiences: List of audiences for the JWT SVID.
            subject: Subject for the JWT SVID.

        Returns:
            JwtSvid: Instance of JwtSvid object.

        Raises:
            ValueError: In case audience is empty.
            FetchJwtSvidError: In case there is an error in fetching the JWTSVID from agent.
        """
        if not audiences:
            raise ValueError('Parameter audiences cannot be empty.')
        try:
            response = self._call_fetch_jwt_svids(audiences, subject)
            svid = response.svids[0].svid
            return JwtSvid.parse_insecure(svid, audiences)
        except JwtSvidError as e:
            raise FetchJwtSvidError(
                'JWT SVID received from agent is invalid. ' + str(e)
            )

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

    def get_spiffe_endpoint_socket(self) -> str:
        """Returns the spiffe endpoint socket config for this WorkloadApiClient.

        Returns:
            str: spiffe endpoint socket configuration value.
        """

        return self._config.spiffe_endpoint_socket

    def _get_spiffe_grpc_channel(self):
        grpc_insecure_channel = grpc.insecure_channel(
            self._config.spiffe_endpoint_socket
        )
        spiffe_client_interceptor = (
            header_manipulator_client_interceptor.header_adder_interceptor(
                WORKLOAD_API_HEADER_KEY, WORKLOAD_API_HEADER_VALUE
            )
        )

        return grpc.intercept_channel(grpc_insecure_channel, spiffe_client_interceptor)

    def _call_fetch_x509_svid(self) -> workload_pb2.X509SVIDResponse:
        try:
            response = self._spiffe_workload_api_stub.FetchX509SVID(
                workload_pb2.X509SVIDRequest()
            )
            item = next(response)
        except Exception:
            raise FetchX509SvidError('X.509 SVID response is invalid')
        if len(item.svids) == 0:
            raise FetchX509SvidError('X.509 SVID response is empty')
        return item

    def _call_fetch_x509_bundles(self) -> workload_pb2.X509BundlesResponse:
        try:
            response = self._spiffe_workload_api_stub.FetchX509Bundles(
                workload_pb2.X509BundlesRequest()
            )
            item = next(response)
        except Exception:
            raise FetchX509BundleError('X.509 Bundles response is invalid')
        if len(item.bundles) == 0:
            raise FetchX509BundleError('X.509 Bundles response is empty')
        return item

    def _create_bundle_set(self, resp_bundles: Any) -> X509BundleSet:
        x509_bundles = [
            self._create_x509_bundle(TrustDomain(td), resp_bundles[td])
            for td in resp_bundles
        ]
        return X509BundleSet.of(x509_bundles)

    @staticmethod
    def _create_x509_svid(svid: Any) -> X509Svid:
        cert = svid.x509_svid
        key = svid.x509_svid_key
        try:
            return X509Svid.parse_raw(cert, key)
        except Exception as e:
            raise FetchX509SvidError(normalized_exception_message(e))

    @staticmethod
    def _create_x509_bundle(trust_domain: TrustDomain, bundle: Any) -> X509Bundle:
        try:
            return X509Bundle.parse_raw(trust_domain, bundle)
        except Exception as e:
            raise FetchX509BundleError(normalized_exception_message(e))

    def _call_fetch_jwt_svids(
        self, audience: List[str], spiffe_id: Optional[str] = None
    ) -> workload_pb2.JWTSVIDResponse:

        try:
            request = workload_pb2.JWTSVIDRequest()
            for aud in audience:
                request.audience.append(aud)
            if spiffe_id:
                request.spiffe_id = spiffe_id
            response = self._spiffe_workload_api_stub.FetchJWTSVID(request)
            item = next(response)
        except Exception as e:
            raise FetchJwtSvidError('JWT SVID response is invalid. ' + str(e))
        if len(item.svids) == 0:
            raise FetchJwtSvidError('JWT SVID response is empty.')
        return item
