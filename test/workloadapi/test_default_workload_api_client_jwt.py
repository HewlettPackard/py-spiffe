""""
(C) Copyright 2021 Hewlett Packard Enterprise Development LP

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

from typing import Any, Iterable, List
import time
from unittest.mock import patch

import pytest
import datetime
import grpc
import threading
from calendar import timegm

from src.pyspiffe.workloadapi.default_workload_api_client import (
    DefaultWorkloadApiClient,
)
from test.utils.jwt_utils import generate_test_jwt_token, TEST_AUDIENCE
from pyspiffe.spiffe_id.spiffe_id import TrustDomain
from pyspiffe.proto.spiffe import workload_pb2
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
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


@pytest.fixture
def client():
    with patch.object(
        DefaultWorkloadApiClient, '_check_spiffe_socket_exists'
    ) as mock_check:
        mock_check.return_value = None
        client_instance = DefaultWorkloadApiClient('unix:///dummy.path')
    return client_instance


def test_fetch_jwt_svid_aud_sub(mocker, client):
    spiffe_id = SpiffeId('spiffe://test.com/my_service')
    jwt_svid = generate_test_jwt_token(spiffe_id=str(spiffe_id))

    client._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(
            svids=[
                workload_pb2.JWTSVID(
                    spiffe_id=str(spiffe_id),
                    svid=jwt_svid,
                )
            ]
        )
    )

    svid = client.fetch_jwt_svid(audiences=TEST_AUDIENCE, subject=spiffe_id)
    utc_time = timegm(datetime.datetime.utcnow().utctimetuple())
    assert svid._spiffe_id == spiffe_id
    assert svid._token == jwt_svid
    assert svid.audience == TEST_AUDIENCE
    assert int(svid._expiry) > utc_time


def test_fetch_jwt_svid_aud(mocker, client):
    spiffe_id = 'spiffe://test.com/my_service'
    jwt_svid = generate_test_jwt_token(spiffe_id=spiffe_id)

    client._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(
            svids=[
                workload_pb2.JWTSVID(
                    svid=jwt_svid,
                )
            ]
        )
    )

    svid = client.fetch_jwt_svid(audiences=TEST_AUDIENCE)
    utc_time = timegm(datetime.datetime.utcnow().utctimetuple())
    assert svid._spiffe_id == SpiffeId(spiffe_id)
    assert svid._token == jwt_svid
    assert svid.audience == TEST_AUDIENCE
    assert int(svid._expiry) > utc_time


def test_fetch_jwt_svids(mocker, client):
    spiffe_id = 'spiffe://test.com/my_service'
    jwt_svid = generate_test_jwt_token(spiffe_id=spiffe_id)
    spiffe_id2 = 'spiffe://test.com/my_service2'
    jwt_svid2 = generate_test_jwt_token(spiffe_id=spiffe_id2)

    client._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(
            svids=[
                workload_pb2.JWTSVID(
                    svid=jwt_svid,
                ),
                workload_pb2.JWTSVID(
                    svid=jwt_svid2,
                ),
            ]
        )
    )

    svids = client.fetch_jwt_svids(audiences=TEST_AUDIENCE)
    utc_time = timegm(datetime.datetime.utcnow().utctimetuple())

    svid = svids[0]
    assert svid._spiffe_id == SpiffeId(spiffe_id)
    assert svid._token == jwt_svid
    assert svid.audience == TEST_AUDIENCE
    assert int(svid._expiry) > utc_time

    svid = svids[1]
    assert svid._spiffe_id == SpiffeId(spiffe_id2)
    assert svid._token == jwt_svid2
    assert svid.audience == TEST_AUDIENCE
    assert int(svid._expiry) > utc_time


@pytest.mark.parametrize(
    'test_input_audience, expected',
    [
        (None, 'Parameter audiences cannot be empty.'),
        ([], 'Parameter audiences cannot be empty.'),
    ],
)
def test_fetch_jwt_svid_no_audience(test_input_audience, expected, client):
    with pytest.raises(ArgumentError) as exception:
        client.fetch_jwt_svid(audiences=test_input_audience)

    assert str(exception.value) == expected


def test_fetch_jwt_svid_fetch_error(mocker, client):
    client._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        side_effect=Exception('Mocked Error')
    )

    with pytest.raises(FetchJwtSvidError) as exception:
        client.fetch_jwt_svid(audiences=TEST_AUDIENCE)

    assert str(exception.value) == 'Error fetching JWT SVID: Mocked Error.'


def test_fetch_jwt_svid_wrong_token(mocker, client):
    jwt_svid = generate_test_jwt_token(spiffe_id='')

    client._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(
            svids=[
                workload_pb2.JWTSVID(
                    svid=jwt_svid,
                )
            ]
        )
    )
    with pytest.raises(FetchJwtSvidError) as exception:
        client.fetch_jwt_svid(audiences=TEST_AUDIENCE)

    assert (
        str(exception.value) == 'Error fetching JWT SVID: Missing required claim: sub.'
    )


def test_fetch_jwt_svid_no_token_returned(mocker, client):
    client._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(svids=[])
    )
    with pytest.raises(FetchJwtSvidError) as exception:
        client.fetch_jwt_svid(audiences=TEST_AUDIENCE)

    assert (
        str(exception.value) == 'Error fetching JWT SVID: JWT SVID response is empty.'
    )


def test_fetch_jwt_bundles(mocker, client):
    bundles = {'example.org': JWKS_1_EC_KEY, 'domain.test': JWKS_2_EC_1_RSA_KEYS}

    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.JWTBundlesResponse(
                    bundles=bundles,
                ),
            ]
        )
    )

    jwt_bundle_set = client.fetch_jwt_bundles()

    jwt_bundle = jwt_bundle_set.get_bundle_for_trust_domain(TrustDomain('example.org'))
    assert jwt_bundle
    assert len(jwt_bundle.jwt_authorities) == 1

    federated_jwt_bundle = jwt_bundle_set.get_bundle_for_trust_domain(
        TrustDomain('domain.test')
    )
    assert federated_jwt_bundle
    assert len(federated_jwt_bundle.jwt_authorities) == 3


def test_fetch_jwt_bundles_empty_response(mocker, client):
    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.JWTBundlesResponse(
                    bundles={},
                ),
            ]
        )
    )

    with pytest.raises(FetchJwtBundleError) as exc_info:
        client.fetch_jwt_bundles()

    assert (
        str(exc_info.value)
        == 'Error fetching JWT Bundle: JWT Bundles response is empty.'
    )


def test_fetch_jwt_bundles_error_parsing_jwks(mocker, client):
    bundles = {'example.org': JWKS_1_EC_KEY, 'domain.test': JWKS_MISSING_KEY_ID}

    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.JWTBundlesResponse(
                    bundles=bundles,
                ),
            ]
        )
    )

    with pytest.raises(FetchJwtBundleError) as exc_info:
        client.fetch_jwt_bundles()

    assert (
        str(exc_info.value)
        == 'Error fetching JWT Bundle: Error parsing JWT bundle: Error adding authority from JWKS: keyID cannot be empty.'
    )


def test_fetch_jwt_bundles_raise_grpc_call(mocker, client):
    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=FakeCall()
    )

    with pytest.raises(FetchJwtBundleError) as exc_info:
        client.fetch_jwt_bundles()

    assert (
        str(exc_info.value)
        == 'Error fetching JWT Bundle: Error details from Workload API.'
    )


def test_fetch_jwt_bundles_raise_grpc_error(mocker, client):
    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=grpc.RpcError('Mocked gRPC error')
    )

    with pytest.raises(FetchJwtBundleError) as exc_info:
        client.fetch_jwt_bundles()

    assert (
        str(exc_info.value)
        == 'Error fetching JWT Bundle: Could not process response from the Workload API.'
    )


def test_fetch_jwt_bundles_raise_error(mocker, client):
    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=Exception('Mocked error')
    )

    with pytest.raises(FetchJwtBundleError) as exc_info:
        client.fetch_jwt_bundles()

    assert str(exc_info.value) == 'Error fetching JWT Bundle: Mocked error.'


def test_validate_jwt_svid(mocker, client):
    audience = 'spire'
    spiffe_id = 'spiffe://test.com/my_service'
    jwt_svid = generate_test_jwt_token(audience=[audience], spiffe_id=spiffe_id)

    client._spiffe_workload_api_stub.ValidateJWTSVID = mocker.Mock(
        return_value=workload_pb2.ValidateJWTSVIDResponse(
            spiffe_id=spiffe_id,
        )
    )

    svid = client.validate_jwt_svid(token=jwt_svid, audience=audience)

    assert svid.spiffe_id == SpiffeId(spiffe_id)
    assert svid.token == jwt_svid
    assert svid.audience == {audience}


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
    test_input_token, test_input_audience, expected, client
):
    with pytest.raises(ArgumentError) as exception:
        client.validate_jwt_svid(
            token=test_input_token,
            audience=test_input_audience,
        )

    assert str(exception.value) == expected


def test_validate_jwt_svid_raise_error(mocker, client):
    jwt_svid = generate_test_jwt_token()

    client._spiffe_workload_api_stub.ValidateJWTSVID = mocker.Mock(
        side_effect=Exception('Mocked error')
    )

    with pytest.raises(ValidateJwtSvidError) as exception:
        client.validate_jwt_svid(token=jwt_svid, audience='audience')

    assert str(exception.value) == 'JWT SVID is not valid: Mocked error.'


def test_watch_jwt_bundle_success(mocker, client):
    jwt_bundles = {'example.org': JWKS_1_EC_KEY, 'domain.prod': JWKS_2_EC_1_RSA_KEYS}
    jwt_bundles_2 = {'domain.dev': JWKS_1_EC_KEY}

    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        return_value=delayed_responses(
            [
                workload_pb2.JWTBundlesResponse(bundles=jwt_bundles),
                workload_pb2.JWTBundlesResponse(bundles=jwt_bundles_2),
            ]
        )
    )

    event = threading.Event()
    response_holder = ResponseHolder()

    client.watch_jwt_bundles(
        on_success=lambda r: handle_success(r, response_holder, event),
        on_error=lambda e: handle_error(e, response_holder, event),
    )

    event.wait(3)  # add timeout to prevent test from hanging

    assert not response_holder.error
    jwt_bundle_set = response_holder.success
    assert jwt_bundle_set
    jwt_bundle_1 = jwt_bundle_set.get_bundle_for_trust_domain(
        TrustDomain('example.org')
    )
    assert jwt_bundle_1
    assert len(jwt_bundle_1.jwt_authorities) == 1

    jwt_bundle_2 = jwt_bundle_set.get_bundle_for_trust_domain(
        TrustDomain('domain.prod')
    )
    assert jwt_bundle_2
    assert len(jwt_bundle_2.jwt_authorities) == 3

    # Wait to receive the second response from delayed_responses()
    time.sleep(1)

    assert not response_holder.error
    jwt_bundle_set = response_holder.success
    jwt_bundle = jwt_bundle_set.get_bundle_for_trust_domain(TrustDomain('domain.dev'))
    assert jwt_bundle
    assert len(jwt_bundle.jwt_authorities) == 1


def delayed_responses(responses: List[Any]) -> Iterable:
    for res in responses:
        yield res
        time.sleep(0.5)


def test_watch_jwt_bundle_retry_on_grpc_error(mocker, client):
    grpc_error = FakeCall()
    jwt_bundles = {'example.org': JWKS_1_EC_KEY, 'domain.prod': JWKS_2_EC_1_RSA_KEYS}

    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=[
            grpc_error,
            delayed_responses([workload_pb2.JWTBundlesResponse(bundles=jwt_bundles)]),
        ]
    )

    expected_error = FetchJwtBundleError(grpc_error.details())
    event = threading.Event()
    response_holder = ResponseHolder()

    client.watch_jwt_bundles(
        on_success=lambda r: handle_success(r, response_holder, event),
        on_error=lambda e: assert_error(e, expected_error),
    )

    event.wait(3)  # add timeout to prevent test from hanging
    # Wait to receive the response from delayed_responses()
    time.sleep(1)

    jwt_bundle_set = response_holder.success
    assert jwt_bundle_set
    jwt_bundle_1 = jwt_bundle_set.get_bundle_for_trust_domain(
        TrustDomain('example.org')
    )
    assert jwt_bundle_1
    assert len(jwt_bundle_1.jwt_authorities) == 1

    jwt_bundle_2 = jwt_bundle_set.get_bundle_for_trust_domain(
        TrustDomain('domain.prod')
    )
    assert jwt_bundle_2
    assert len(jwt_bundle_2.jwt_authorities) == 3


def test_watch_jwt_bundle_no_retry_on_grpc_error(mocker, client):
    grpc_error = FakeCall()
    grpc_error._code = grpc.StatusCode.INVALID_ARGUMENT

    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=[
            grpc_error,
        ]
    )

    expected_error = FetchJwtBundleError(grpc_error.details())
    event = threading.Event()
    response_holder = ResponseHolder()

    client.watch_jwt_bundles(
        on_success=lambda r: handle_success(r, response_holder, event),
        on_error=lambda e: handle_error(e, response_holder, event),
    )

    event.wait(3)  # add timeout to prevent test from hanging

    assert not response_holder.success
    assert response_holder.error
    assert_error(response_holder.error, expected_error)


def test_watch_jwt_bundle_no_retry_on_grpc_error_no_call(mocker, client):
    grpc_error = grpc.RpcError
    jwt_bundles = {'example.org': JWKS_1_EC_KEY, 'domain.prod': JWKS_2_EC_1_RSA_KEYS}

    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=[
            grpc_error,
            delayed_responses([workload_pb2.JWTBundlesResponse(bundles=jwt_bundles)]),
        ]
    )

    expected_error = FetchJwtBundleError('Cannot process response from Workload API.')
    event = threading.Event()
    response_holder = ResponseHolder()

    client.watch_jwt_bundles(
        on_success=lambda r: handle_success(r, response_holder, event),
        on_error=lambda e: handle_error(e, response_holder, event),
    )

    event.wait(3)  # add timeout to prevent test from hanging

    assert not response_holder.success
    assert response_holder.error
    assert_error(response_holder.error, expected_error)


def test_watch_jwt_bundle_no_retry_on_error(mocker, client):
    some_error = Exception('Some Error')

    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=some_error,
    )

    expected_error = FetchJwtBundleError(str(some_error))
    event = threading.Event()
    response_holder = ResponseHolder()

    client.watch_jwt_bundles(
        on_success=lambda r: handle_success(r, response_holder, event),
        on_error=lambda e: handle_error(e, response_holder, event),
    )

    event.wait(3)  # add timeout to prevent test from hanging

    assert not response_holder.success
    assert response_holder.error
    assert_error(response_holder.error, expected_error)
