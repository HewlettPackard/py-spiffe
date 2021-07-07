import pytest

from test.svid.test_utils import create_jwt, DEFAULT_AUDIENCE
from pyspiffe.spiffe_id.spiffe_id import TrustDomain
from pyspiffe.proto.spiffe import workload_pb2
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.workloadapi.default_jwt_source import DefaultJwtSource
from pyspiffe.workloadapi.exceptions import JwtSourceError, FetchJwtSvidError
from test.workloadapi.test_default_workload_api_client import WORKLOAD_API_CLIENT
from pyspiffe.exceptions import ArgumentError
from test.utils.utils import (
    JWKS_1_EC_KEY,
    JWKS_2_EC_1_RSA_KEYS,
)

SPIFFE_ID = SpiffeId.parse('spiffe://example.org/my_service')


def mock_client_get_jwt_svid(mocker):
    jwt_svid = create_jwt(spiffe_id=str(SPIFFE_ID))

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(
            svids=[
                workload_pb2.JWTSVID(
                    spiffe_id=str(SPIFFE_ID),
                    svid=jwt_svid,
                )
            ]
        )
    )


def mock_client_fetch_jwt_bundles(mocker):
    jwt_bundles = {'example.org': JWKS_1_EC_KEY, 'domain.prod': JWKS_2_EC_1_RSA_KEYS}
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        return_value=[
            workload_pb2.JWTBundlesResponse(bundles=jwt_bundles),
            workload_pb2.JWTBundlesResponse(bundles=jwt_bundles),
        ]
    )


def test_get_jwt_svid(mocker):
    mock_client_get_jwt_svid(mocker)
    mock_client_fetch_jwt_bundles(mocker)

    jwt_source = DefaultJwtSource(WORKLOAD_API_CLIENT)
    jwt_svid = jwt_source.get_jwt_svid(DEFAULT_AUDIENCE, subject=SPIFFE_ID)

    assert jwt_svid.spiffe_id == SPIFFE_ID
    assert jwt_svid.audience == DEFAULT_AUDIENCE


def test_get_jwt_svid_no_subject(mocker):
    mock_client_get_jwt_svid(mocker)
    mock_client_fetch_jwt_bundles(mocker)

    jwt_source = DefaultJwtSource(WORKLOAD_API_CLIENT)
    jwt_svid = jwt_source.get_jwt_svid(DEFAULT_AUDIENCE)

    assert jwt_svid.spiffe_id == SPIFFE_ID
    assert jwt_svid.audience == DEFAULT_AUDIENCE


def test_get_jwt_svid_exception(mocker):
    mock_client_get_jwt_svid(mocker)
    mock_client_fetch_jwt_bundles(mocker)

    jwt_source = DefaultJwtSource(WORKLOAD_API_CLIENT)
    with pytest.raises(ArgumentError) as exception:
        _ = jwt_source.get_jwt_svid("")

    assert str(exception.value) == 'Audience cannot be empty.'


def test_error_new(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        side_effect=Exception('Mocked Error')
    )
    mock_client_fetch_jwt_bundles(mocker)
    jwt_source = DefaultJwtSource(WORKLOAD_API_CLIENT)
    with pytest.raises(FetchJwtSvidError) as exception:
        _ = jwt_source.get_jwt_svid(DEFAULT_AUDIENCE)

    assert str(exception.value) == 'Error fetching JWT SVID: Mocked Error.'


def test_close(mocker):
    mock_client_get_jwt_svid(mocker)
    mock_client_fetch_jwt_bundles(mocker)

    jwt_source = DefaultJwtSource(WORKLOAD_API_CLIENT)
    jwt_source.close()

    assert jwt_source.is_closed()


def test_close_twice(mocker):
    mock_client_get_jwt_svid(mocker)
    mock_client_fetch_jwt_bundles(mocker)

    jwt_source = DefaultJwtSource(WORKLOAD_API_CLIENT)
    jwt_source.close()
    jwt_source.close()

    assert jwt_source.is_closed()


def test_is_closed(mocker):

    mock_client_get_jwt_svid(mocker)
    mock_client_fetch_jwt_bundles(mocker)

    jwt_source = DefaultJwtSource(WORKLOAD_API_CLIENT)
    assert not jwt_source.is_closed()
    jwt_source.close()
    assert jwt_source.is_closed()


def get_jwt_bundle(mocker):
    mock_client_get_jwt_svid(mocker)
    mock_client_fetch_jwt_bundles(mocker)
    jwt_source = DefaultJwtSource(WORKLOAD_API_CLIENT)

    jwt_bundle = jwt_source.get_jwt_bundle(TrustDomain.parse('example.org'))
    assert jwt_bundle
    assert len(jwt_bundle.jwt_authorities()) == 1


def test_get_jwt_bundle_exception(mocker):

    jwt_bundles = {'example.org': JWKS_1_EC_KEY, 'domain.prod': JWKS_2_EC_1_RSA_KEYS}
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        return_value=[
            workload_pb2.JWTBundlesResponse(bundles=jwt_bundles),
        ],
        side_effect=Exception('Mocked Error'),
    )

    jwt_source = DefaultJwtSource(WORKLOAD_API_CLIENT)

    with pytest.raises(JwtSourceError) as exception:
        _ = jwt_source.get_jwt_bundle(TrustDomain.parse('example.org'))

    assert (
        str(exception.value)
        == 'JWT Source error: Cannot get JWT Bundle: source is closed.'
    )
