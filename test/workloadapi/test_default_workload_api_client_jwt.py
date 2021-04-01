import pytest
import datetime
from calendar import timegm
from cryptography.hazmat.primitives.asymmetric import rsa
from test.svid.test_utils import get_keys_pems, create_jwt

from pyspiffe.proto.spiffe import workload_pb2
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.workloadapi.default_workload_api_client import DefaultWorkloadApiClient
from pyspiffe.workloadapi.exceptions import FetchJwtSvidError


rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_key_pem, public_rsa_key_pem = get_keys_pems(rsa_key)


def test_fetch_jwt_svid_aud_sub(mocker):
    client = DefaultWorkloadApiClient('unix:///dummy.path')
    spiffe_id = 'spiffe://test.orgcom/my_service'
    audience = ['spire', 'test', 'valid']
    jwt_svid = create_jwt(rsa_key_pem, 'kid1', 'RS256', audience, spiffe_id)

    client._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.JWTSVIDResponse(
                    svids=[
                        workload_pb2.JWTSVID(
                            spiffe_id=spiffe_id,
                            svid=jwt_svid,
                        )
                    ]
                )
            ]
        )
    )

    svid = client.fetch_jwt_svid(audiences=audience, subject=spiffe_id)
    utc_time = timegm(datetime.datetime.utcnow().utctimetuple())
    assert svid.spiffe_id == SpiffeId.parse(spiffe_id)
    assert svid.token == jwt_svid
    assert svid.claims['aud'] == audience
    assert int(svid.expiry) > utc_time


def test_fetch_jwt_svid_aud(mocker):
    client = DefaultWorkloadApiClient('unix:///dummy.path')
    audience = ['spire', 'test', 'valid']
    spiffe_id = 'spiffe://test.orgcom/my_service'
    jwt_svid = create_jwt(rsa_key_pem, 'kid1', 'RS256', audience, spiffe_id)

    client._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.JWTSVIDResponse(
                    svids=[
                        workload_pb2.JWTSVID(
                            svid=jwt_svid,
                        )
                    ]
                )
            ]
        )
    )

    svid = client.fetch_jwt_svid(audiences=audience)
    utc_time = timegm(datetime.datetime.utcnow().utctimetuple())
    assert svid.spiffe_id == SpiffeId.parse(spiffe_id)
    assert svid.token == jwt_svid
    assert svid.claims['aud'] == audience
    assert int(svid.expiry) > utc_time


@pytest.mark.parametrize(
    'test_input_audience, expected',
    [
        (None, 'Parameter audiences cannot be empty.'),
        ([], 'Parameter audiences cannot be empty.'),
    ],
)
def test_fecth_jwt_svid_no_audience(test_input_audience, expected):
    client = DefaultWorkloadApiClient('unix:///dummy.path')
    with pytest.raises(ValueError) as exception:
        client.fetch_jwt_svid(audiences=test_input_audience)

    assert str(exception.value) == expected


def test_fecth_jwt_svid_fetch_error():
    client = DefaultWorkloadApiClient('unix:///dummy.path')
    audience = ['spire', 'test', 'valid']
    with pytest.raises(FetchJwtSvidError) as exception:
        client.fetch_jwt_svid(audiences=audience)

    assert str(exception.value).startswith('JWT SVID response is invalid.')


def test_fetch_jwt_svid_wrong_token(mocker):
    client = DefaultWorkloadApiClient('unix:///dummy.path')
    audience = ['spire', 'test', 'valid']
    spiffe_id = ''
    jwt_svid = create_jwt(rsa_key_pem, 'kid1', 'RS256', audience, spiffe_id)

    client._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.JWTSVIDResponse(
                    svids=[
                        workload_pb2.JWTSVID(
                            svid=jwt_svid,
                        )
                    ]
                )
            ]
        )
    )
    with pytest.raises(FetchJwtSvidError) as exception:
        client.fetch_jwt_svid(audiences=audience)

    assert str(exception.value).startswith('JWT SVID received from agent is invalid.')


def test_fetch_jwt_svid_no_token_returned(mocker):
    client = DefaultWorkloadApiClient('unix:///dummy.path')
    audience = ['spire', 'test', 'valid']
    client._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=iter([workload_pb2.JWTSVIDResponse(svids=[])])
    )
    with pytest.raises(FetchJwtSvidError) as exception:
        client.fetch_jwt_svid(audiences=audience)

    assert str(exception.value) == 'JWT SVID response is empty.'


"""


# TODO: Implement using WorkloadApi Mock
def test_fetch_jwt_bundles():
    wlapi = get_client()
    wlapi.fetch_jwt_bundles()

# TODO: Implement using WorkloadApi Mock
def test_validate_jwt_svid():
    wlapi = get_client()
    token = 'TODO'
    audiences = 'foo'
    wlapi.validate_jwt_svid(token=token, audience=audiences)

"""
