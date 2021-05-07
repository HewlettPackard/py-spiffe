import pytest
import datetime
from calendar import timegm
from test.svid.test_utils import create_jwt, DEFAULT_AUDIENCE
from test.workloadapi.test_default_workload_api_client import WORKLOAD_API_CLIENT

from pyspiffe.proto.spiffe import workload_pb2
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.exceptions import ArgumentError
from pyspiffe.workloadapi.exceptions import FetchJwtSvidError, ValidateJwtSvidError


def test_fetch_jwt_svid_aud_sub(mocker):
    spiffe_id = SpiffeId.parse('spiffe://test.com/my_service')
    jwt_svid = create_jwt(spiffe_id=str(spiffe_id))

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(
            svids=[
                workload_pb2.JWTSVID(
                    spiffe_id=str(spiffe_id),
                    svid=jwt_svid,
                )
            ]
        )
    )

    svid = WORKLOAD_API_CLIENT.fetch_jwt_svid(
        audiences=DEFAULT_AUDIENCE, subject=spiffe_id
    )
    utc_time = timegm(datetime.datetime.utcnow().utctimetuple())
    assert svid.spiffe_id == spiffe_id
    assert svid.token == jwt_svid
    assert svid.claims['aud'] == DEFAULT_AUDIENCE
    assert int(svid.expiry) > utc_time


def test_fetch_jwt_svid_aud(mocker):
    spiffe_id = 'spiffe://test.com/my_service'
    jwt_svid = create_jwt(spiffe_id=spiffe_id)

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(
            svids=[
                workload_pb2.JWTSVID(
                    svid=jwt_svid,
                )
            ]
        )
    )

    svid = WORKLOAD_API_CLIENT.fetch_jwt_svid(audiences=DEFAULT_AUDIENCE)
    utc_time = timegm(datetime.datetime.utcnow().utctimetuple())
    assert svid.spiffe_id == SpiffeId.parse(spiffe_id)
    assert svid.token == jwt_svid
    assert svid.claims['aud'] == DEFAULT_AUDIENCE
    assert int(svid.expiry) > utc_time


@pytest.mark.parametrize(
    'test_input_audience, expected',
    [
        (None, 'Parameter audiences cannot be empty.'),
        ([], 'Parameter audiences cannot be empty.'),
    ],
)
def test_fetch_jwt_svid_no_audience(test_input_audience, expected):
    with pytest.raises(ArgumentError) as exception:
        WORKLOAD_API_CLIENT.fetch_jwt_svid(audiences=test_input_audience)

    assert str(exception.value) == expected


def test_fetch_jwt_svid_fetch_error(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        side_effect=Exception('Mocked Error')
    )

    with pytest.raises(FetchJwtSvidError) as exception:
        WORKLOAD_API_CLIENT.fetch_jwt_svid(audiences=DEFAULT_AUDIENCE)

    assert str(exception.value) == 'Error fetching JWT SVID: Mocked Error.'


def test_fetch_jwt_svid_wrong_token(mocker):
    jwt_svid = create_jwt(spiffe_id='')

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(
            svids=[
                workload_pb2.JWTSVID(
                    svid=jwt_svid,
                )
            ]
        )
    )
    with pytest.raises(FetchJwtSvidError) as exception:
        WORKLOAD_API_CLIENT.fetch_jwt_svid(audiences=DEFAULT_AUDIENCE)

    assert (
        str(exception.value) == 'Error fetching JWT SVID: Missing required claim: sub.'
    )


def test_fetch_jwt_svid_no_token_returned(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(svids=[])
    )
    with pytest.raises(FetchJwtSvidError) as exception:
        WORKLOAD_API_CLIENT.fetch_jwt_svid(audiences=DEFAULT_AUDIENCE)

    assert (
        str(exception.value) == 'Error fetching JWT SVID: JWT SVID response is empty.'
    )


"""
# TODO: Implement using WorkloadApi Mock
def test_fetch_jwt_bundles():
    wlapi = get_client()
    wlapi.fetch_jwt_bundles()
"""


def test_validate_jwt_svid(mocker):
    audience = 'spire'
    spiffe_id = 'spiffe://test.com/my_service'
    jwt_svid = create_jwt(audience=[audience], spiffe_id=spiffe_id)

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.ValidateJWTSVID = mocker.Mock(
        return_value=workload_pb2.ValidateJWTSVIDResponse(
            spiffe_id=spiffe_id,
        )
    )

    svid = WORKLOAD_API_CLIENT.validate_jwt_svid(token=jwt_svid, audience=audience)

    assert svid.spiffe_id == SpiffeId.parse(spiffe_id)
    assert svid.token == jwt_svid
    assert svid.claims['aud'] == [audience]
    assert svid.audience == [audience]


@pytest.mark.parametrize(
    'test_input_token, test_input_audience, expected',
    [
        (None, 'audience', 'Token cannot be empty.'),
        ('', 'audience', 'Token cannot be empty.'),
        ('token', None, 'Audience cannot be empty.'),
        ('token', '', 'Audience cannot be empty.'),
    ],
)
def test_validate_jwt_svid_invalid_input(
    test_input_token, test_input_audience, expected
):
    with pytest.raises(ArgumentError) as exception:
        WORKLOAD_API_CLIENT.validate_jwt_svid(
            token=test_input_token,
            audience=test_input_audience,
        )

    assert str(exception.value) == expected


def test_validate_jwt_svid_raise_error(mocker):
    jwt_svid = create_jwt()

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.ValidateJWTSVID = mocker.Mock(
        side_effect=Exception('Mocked error')
    )

    with pytest.raises(ValidateJwtSvidError) as exception:
        WORKLOAD_API_CLIENT.validate_jwt_svid(token=jwt_svid, audience='audience')

    assert str(exception.value) == 'JWT SVID is not valid: Mocked error.'
