from typing import Any, Iterable, List
import time
import pytest
import datetime
import grpc
import threading
from calendar import timegm
from test.svid.test_utils import create_jwt, DEFAULT_AUDIENCE
from test.workloadapi.test_default_workload_api_client import WORKLOAD_API_CLIENT
from pyspiffe.spiffe_id.spiffe_id import TrustDomain
from pyspiffe.proto.spiffe import workload_pb2
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.svid.jwt_svid import JwtSvid
from pyspiffe.exceptions import ArgumentError
from pyspiffe.workloadapi.exceptions import (
    FetchJwtSvidError,
    ValidateJwtSvidError,
    FetchJwtBundleError,
)
from test.utils.utils import (
    FakeCall,
    JWKS_1_EC_KEY,
    JWKS_2_EC_1_RSA_KEYS,
    JWKS_MISSING_KEY_ID,
    ResponseHolder,
    handle_success,
    handle_error,
    assert_error,
)


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
    assert_jwt_svid(svid, spiffe_id, jwt_svid, DEFAULT_AUDIENCE)


def test_fetch_jwt_svid_aud(mocker):
    spiffe_id = SpiffeId.parse('spiffe://test.com/my_service')
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
    assert_jwt_svid(svid, spiffe_id, jwt_svid, DEFAULT_AUDIENCE)


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


def test_fetch_jwt_svids_aud_sub(mocker):
    spiffe_id = SpiffeId.parse('spiffe://test.com/my_service')
    extra_spiffe_id = SpiffeId.parse('spiffe://test.com/extra_service')
    jwt_svid = create_jwt(spiffe_id=str(spiffe_id))
    extra_jwt_svid = create_jwt(spiffe_id=str(extra_spiffe_id))

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(
            svids=[
                workload_pb2.JWTSVID(
                    spiffe_id=str(spiffe_id),
                    svid=jwt_svid,
                ),
                workload_pb2.JWTSVID(
                    spiffe_id=str(extra_spiffe_id),
                    svid=extra_jwt_svid,
                ),
            ]
        )
    )

    svids = WORKLOAD_API_CLIENT.fetch_jwt_svids(
        audiences=DEFAULT_AUDIENCE, subject=spiffe_id
    )
    assert len(svids) == 1
    assert_jwt_svid(svids[0], spiffe_id, jwt_svid, DEFAULT_AUDIENCE)


def test_fetch_jwt_svids_aud(mocker):
    spiffe_id = SpiffeId.parse('spiffe://test.com/my_service')
    extra_spiffe_id = SpiffeId.parse('spiffe://test.com/extra_service')
    jwt_svid = create_jwt(spiffe_id=str(spiffe_id))
    extra_jwt_svid = create_jwt(spiffe_id=str(extra_spiffe_id))

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(
            svids=[
                workload_pb2.JWTSVID(
                    spiffe_id=str(spiffe_id),
                    svid=jwt_svid,
                ),
                workload_pb2.JWTSVID(
                    spiffe_id=str(extra_spiffe_id),
                    svid=extra_jwt_svid,
                ),
            ]
        )
    )

    svids = WORKLOAD_API_CLIENT.fetch_jwt_svids(audiences=DEFAULT_AUDIENCE)
    assert len(svids) == 2
    assert_jwt_svid(svids[0], spiffe_id, jwt_svid, DEFAULT_AUDIENCE)
    assert_jwt_svid(svids[1], extra_spiffe_id, extra_jwt_svid, DEFAULT_AUDIENCE)


@pytest.mark.parametrize(
    'test_input_audience, expected',
    [
        (None, 'Parameter audiences cannot be empty.'),
        ([], 'Parameter audiences cannot be empty.'),
    ],
)
def test_fetch_jwt_svids_no_audience(test_input_audience, expected):
    with pytest.raises(ArgumentError) as exception:
        WORKLOAD_API_CLIENT.fetch_jwt_svids(audiences=test_input_audience)

    assert str(exception.value) == expected


def test_fetch_jwt_svids_fetch_error(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        side_effect=Exception('Mocked Error')
    )

    with pytest.raises(FetchJwtSvidError) as exception:
        WORKLOAD_API_CLIENT.fetch_jwt_svids(audiences=DEFAULT_AUDIENCE)

    assert str(exception.value) == 'Error fetching JWT SVID: Mocked Error.'


def test_fetch_jwt_svids_no_token_returned(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(svids=[])
    )
    svids = WORKLOAD_API_CLIENT.fetch_jwt_svids(audiences=DEFAULT_AUDIENCE)
    assert len(svids) == 0


def test_fetch_jwt_bundles(mocker):
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

    jwt_bundle_set = WORKLOAD_API_CLIENT.fetch_jwt_bundles()

    jwt_bundle = jwt_bundle_set.get(TrustDomain.parse('example.org'))
    assert jwt_bundle
    assert len(jwt_bundle.jwt_authorities()) == 1

    federated_jwt_bundle = jwt_bundle_set.get(TrustDomain.parse('domain.test'))
    assert federated_jwt_bundle
    assert len(federated_jwt_bundle.jwt_authorities()) == 3


def test_fetch_jwt_bundles_empty_response(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.JWTBundlesResponse(
                    bundles={},
                ),
            ]
        )
    )

    with pytest.raises(FetchJwtBundleError) as exc_info:
        WORKLOAD_API_CLIENT.fetch_jwt_bundles()

    assert (
        str(exc_info.value)
        == 'Error fetching JWT Bundle: JWT Bundles response is empty.'
    )


def test_fetch_jwt_bundles_error_parsing_jwks(mocker):
    bundles = {'example.org': JWKS_1_EC_KEY, 'domain.test': JWKS_MISSING_KEY_ID}

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.JWTBundlesResponse(
                    bundles=bundles,
                ),
            ]
        )
    )

    with pytest.raises(FetchJwtBundleError) as exc_info:
        WORKLOAD_API_CLIENT.fetch_jwt_bundles()

    assert (
        str(exc_info.value)
        == 'Error fetching JWT Bundle: Error parsing JWT bundle: Error adding authority from JWKS: keyID cannot be empty.'
    )


def test_fetch_jwt_bundles_raise_grpc_call(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=FakeCall()
    )

    with pytest.raises(FetchJwtBundleError) as exc_info:
        WORKLOAD_API_CLIENT.fetch_jwt_bundles()

    assert (
        str(exc_info.value)
        == 'Error fetching JWT Bundle: Error details from Workload API.'
    )


def test_fetch_jwt_bundles_raise_grpc_error(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=grpc.RpcError('Mocked gRPC error')
    )

    with pytest.raises(FetchJwtBundleError) as exc_info:
        WORKLOAD_API_CLIENT.fetch_jwt_bundles()

    assert (
        str(exc_info.value)
        == 'Error fetching JWT Bundle: Could not process response from the Workload API.'
    )


def test_fetch_jwt_bundles_raise_error(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=Exception('Mocked error')
    )

    with pytest.raises(FetchJwtBundleError) as exc_info:
        WORKLOAD_API_CLIENT.fetch_jwt_bundles()

    assert str(exc_info.value) == 'Error fetching JWT Bundle: Mocked error.'


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


def test_watch_jwt_bundle_success(mocker):
    jwt_bundles = {'example.org': JWKS_1_EC_KEY, 'domain.prod': JWKS_2_EC_1_RSA_KEYS}
    jwt_bundles_2 = {'domain.dev': JWKS_1_EC_KEY}

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        return_value=delayed_responses(
            [
                workload_pb2.JWTBundlesResponse(bundles=jwt_bundles),
                workload_pb2.JWTBundlesResponse(bundles=jwt_bundles_2),
            ]
        )
    )

    event = threading.Event()
    response_holder = ResponseHolder()

    WORKLOAD_API_CLIENT.watch_jwt_bundles(
        on_success=lambda r: handle_success(r, response_holder, event),
        on_error=lambda e: handle_error(e, response_holder, event),
    )

    event.wait(3)  # add timeout to prevent test from hanging

    assert not response_holder.error
    jwt_bundle_set = response_holder.success
    assert jwt_bundle_set
    jwt_bundle_1 = jwt_bundle_set.get(TrustDomain.parse('example.org'))
    assert jwt_bundle_1
    assert len(jwt_bundle_1.jwt_authorities()) == 1

    jwt_bundle_2 = jwt_bundle_set.get(TrustDomain.parse('domain.prod'))
    assert jwt_bundle_2
    assert len(jwt_bundle_2.jwt_authorities()) == 3

    # Wait to receive the second response from delayed_responses()
    time.sleep(1)

    assert not response_holder.error
    jwt_bundle_set = response_holder.success
    jwt_bundle = jwt_bundle_set.get(TrustDomain.parse('domain.dev'))
    assert jwt_bundle
    assert len(jwt_bundle.jwt_authorities()) == 1


def delayed_responses(responses: List[Any]) -> Iterable:
    for res in responses:
        yield res
        time.sleep(0.5)


def test_watch_jwt_bundle_retry_on_grpc_error(mocker):
    grpc_error = FakeCall()
    jwt_bundles = {'example.org': JWKS_1_EC_KEY, 'domain.prod': JWKS_2_EC_1_RSA_KEYS}

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=[
            grpc_error,
            delayed_responses([workload_pb2.JWTBundlesResponse(bundles=jwt_bundles)]),
        ]
    )

    expected_error = FetchJwtBundleError(grpc_error.details())
    event = threading.Event()
    response_holder = ResponseHolder()

    WORKLOAD_API_CLIENT.watch_jwt_bundles(
        on_success=lambda r: handle_success(r, response_holder, event),
        on_error=lambda e: assert_error(e, expected_error),
    )

    event.wait(3)  # add timeout to prevent test from hanging
    # Wait to receive the response from delayed_responses()
    time.sleep(1)

    jwt_bundle_set = response_holder.success
    assert jwt_bundle_set
    jwt_bundle_1 = jwt_bundle_set.get(TrustDomain.parse('example.org'))
    assert jwt_bundle_1
    assert len(jwt_bundle_1.jwt_authorities()) == 1

    jwt_bundle_2 = jwt_bundle_set.get(TrustDomain.parse('domain.prod'))
    assert jwt_bundle_2
    assert len(jwt_bundle_2.jwt_authorities()) == 3


def test_watch_jwt_bundle_no_retry_on_grpc_error(mocker):
    grpc_error = FakeCall()
    grpc_error._code = grpc.StatusCode.INVALID_ARGUMENT

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=[
            grpc_error,
        ]
    )

    expected_error = FetchJwtBundleError(grpc_error.details())
    event = threading.Event()
    response_holder = ResponseHolder()

    WORKLOAD_API_CLIENT.watch_jwt_bundles(
        on_success=lambda r: handle_success(r, response_holder, event),
        on_error=lambda e: handle_error(e, response_holder, event),
    )

    event.wait(3)  # add timeout to prevent test from hanging

    assert not response_holder.success
    assert response_holder.error
    assert_error(response_holder.error, expected_error)


def test_watch_jwt_bundle_no_retry_on_grpc_error_no_call(mocker):
    grpc_error = grpc.RpcError
    jwt_bundles = {'example.org': JWKS_1_EC_KEY, 'domain.prod': JWKS_2_EC_1_RSA_KEYS}

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=[
            grpc_error,
            delayed_responses([workload_pb2.JWTBundlesResponse(bundles=jwt_bundles)]),
        ]
    )

    expected_error = FetchJwtBundleError('Cannot process response from Workload API.')
    event = threading.Event()
    response_holder = ResponseHolder()

    WORKLOAD_API_CLIENT.watch_jwt_bundles(
        on_success=lambda r: handle_success(r, response_holder, event),
        on_error=lambda e: handle_error(e, response_holder, event),
    )

    event.wait(3)  # add timeout to prevent test from hanging

    assert not response_holder.success
    assert response_holder.error
    assert_error(response_holder.error, expected_error)


def test_watch_jwt_bundle_no_retry_on_error(mocker):
    some_error = Exception('Some Error')

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=some_error,
    )

    expected_error = FetchJwtBundleError(str(some_error))
    event = threading.Event()
    response_holder = ResponseHolder()

    WORKLOAD_API_CLIENT.watch_jwt_bundles(
        on_success=lambda r: handle_success(r, response_holder, event),
        on_error=lambda e: handle_error(e, response_holder, event),
    )

    event.wait(3)  # add timeout to prevent test from hanging

    assert not response_holder.success
    assert response_holder.error
    assert_error(response_holder.error, expected_error)


def assert_jwt_svid(
    jwt_svid: JwtSvid, spiffe_id: SpiffeId, token: str, audience: List[str]
):
    utc_time = timegm(datetime.datetime.utcnow().utctimetuple())
    assert jwt_svid.spiffe_id == spiffe_id
    assert jwt_svid.token == token
    assert jwt_svid.claims['aud'] == audience
    assert int(jwt_svid.expiry) > utc_time
