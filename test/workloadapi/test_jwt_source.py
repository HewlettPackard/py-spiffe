import pytest

from test.svid.test_utils import create_jwt, DEFAULT_AUDIENCE
from pyspiffe.spiffe_id.trust_domain import TrustDomain
from pyspiffe.proto.spiffe import workload_pb2
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.workloadapi.default_jwt_source import DefaultJwtSource
from pyspiffe.workloadapi.exceptions import JwtSourceError
from pyspiffe.workloadapi.default_workload_api_client import DefaultWorkloadApiClient
from test.utils.utils import (
    JWKS_1_EC_KEY,
    JWKS_2_EC_1_RSA_KEYS,
)


WORKLOAD_API_CLIENT = DefaultWorkloadApiClient('unix:///dummy.path')


def test_get_jwt_svid(mocker):
    spiffe_id = SpiffeId.parse('spiffe://test.com/my_service')
    jwt_svid = create_jwt(spiffe_id=str(spiffe_id))

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(
            svids=[
                workload_pb2.JWTSVID(
                    spiffe_id=str(spiffe_id),
                    svid=jwt_svid,
                )
            ]
        )
    )
    jwt_source = DefaultJwtSource(DEFAULT_AUDIENCE, WORKLOAD_API_CLIENT)
    jwt_svid = jwt_source.get_jwt_svid()

    assert jwt_svid.spiffe_id() == spiffe_id


def test_get_jwt_svid_none(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(svids=[])
    )
    jwt_source = DefaultJwtSource(DEFAULT_AUDIENCE, WORKLOAD_API_CLIENT)
    jwt_svid = jwt_source.get_jwt_svid()

    assert jwt_svid is None


def test_get_jwt_svid_exception(mocker):

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(svids=[])
    )
    jwt_source = DefaultJwtSource(DEFAULT_AUDIENCE, WORKLOAD_API_CLIENT)
    jwt_source.close()

    with pytest.raises(JwtSourceError) as exception:
        jwt_svid = jwt_source.get_jwt_svid()

    assert jwt_svid is None
    assert str(exception.value) == 'Cannot get JWT SVID: source is closed'


def test_close(mocker):

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(svids=[])
    )
    jwt_source = DefaultJwtSource(DEFAULT_AUDIENCE, WORKLOAD_API_CLIENT)
    jwt_source.close()

    assert jwt_source.is_closed()


def test_close_twice(mocker):

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(svids=[])
    )
    jwt_source = DefaultJwtSource(DEFAULT_AUDIENCE, WORKLOAD_API_CLIENT)
    jwt_source.close()
    jwt_source.close()

    assert jwt_source.is_closed()


def test_is_closed(mocker):

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(svids=[])
    )
    jwt_source = DefaultJwtSource(DEFAULT_AUDIENCE, WORKLOAD_API_CLIENT)
    assert not jwt_source.is_close()
    jwt_source.close()
    assert jwt_source.is_close()


def test_get_bundle_for_trust_domain(mocker):
    bundles = {'example.org': JWKS_1_EC_KEY, 'domain.test': JWKS_2_EC_1_RSA_KEYS}

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.JWTBundlesResponse(
                    bundles=bundles,
                ),
            ]
        )
    )
    jwt_source = DefaultJwtSource(DEFAULT_AUDIENCE, WORKLOAD_API_CLIENT)

    jwt_bundle = jwt_source.get_bundle_for_trust_domain(TrustDomain('example.org'))
    assert jwt_bundle
    assert len(jwt_bundle.jwt_authorities()) == 1

    federated_jwt_bundle = jwt_source.get_bundle_for_trust_domain(
        TrustDomain('domain.test')
    )
    assert federated_jwt_bundle
    assert len(federated_jwt_bundle.jwt_authorities()) == 3


def test_get_bundle_for_trust_domain_exception(mocker):

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(svids=[])
    )

    jwt_source = DefaultJwtSource(DEFAULT_AUDIENCE, WORKLOAD_API_CLIENT)
    jwt_source.close()

    with pytest.raises(JwtSourceError) as exception:
        jwt_bundle = jwt_source.get_bundle_for_trust_domain(TrustDomain('example.org'))
    assert jwt_bundle is None
    assert str(exception.value) == 'Cannot get JWT Bundle: source is closed'
