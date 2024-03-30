"""
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

from collections import deque
from typing import Any, Iterable, List
from unittest.mock import patch

import pytest
import datetime
import grpc
import threading

from spiffe.proto import workload_pb2
from spiffe.workloadapi.workload_api_client import WorkloadApiClient
from spiffe.spiffe_id.spiffe_id import TrustDomain
from spiffe.spiffe_id.spiffe_id import SpiffeId
from spiffe.errors import ArgumentError
from spiffe.workloadapi.errors import (
    FetchJwtSvidError,
    ValidateJwtSvidError,
    FetchJwtBundleError,
    WorkloadApiError,
)
from testutils.jwt import (
    generate_test_jwt_token,
    TEST_AUDIENCE,
    JWKS_1_EC_KEY,
    JWKS_2_EC_1_RSA_KEYS,
    JWKS_MISSING_KEY_ID,
)
from testutils.utils import (
    FakeCall,
    ResponseHolder,
    handle_success,
    handle_error,
    assert_error,
)


@pytest.fixture
def client():
    with patch.object(WorkloadApiClient, '_check_spiffe_socket_exists') as mock_check:
        mock_check.return_value = None
        client_instance = WorkloadApiClient('unix:///dummy.path')
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

    svid = client.fetch_jwt_svid(audience=TEST_AUDIENCE, subject=spiffe_id)
    utc_time = datetime.datetime.now(datetime.timezone.utc).timestamp()
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

    svid = client.fetch_jwt_svid(audience=TEST_AUDIENCE)
    utc_time = datetime.datetime.now(datetime.timezone.utc).timestamp()
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

    svids = client.fetch_jwt_svids(audience=TEST_AUDIENCE)
    utc_time = datetime.datetime.now(datetime.timezone.utc).timestamp()

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
        (None, 'Parameter audiences cannot be empty'),
        ([], 'Parameter audiences cannot be empty'),
    ],
)
def test_fetch_jwt_svid_no_audience(test_input_audience, expected, client):
    with pytest.raises(ArgumentError) as exception:
        client.fetch_jwt_svid(audience=test_input_audience)

    assert str(exception.value) == expected


def test_fetch_jwt_svid_fetch_error(mocker, client):
    client._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        side_effect=Exception('Mocked Error')
    )

    with pytest.raises(FetchJwtSvidError) as exception:
        client.fetch_jwt_svid(audience=TEST_AUDIENCE)

    assert str(exception.value) == 'Error fetching JWT SVID: Mocked Error'


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
        client.fetch_jwt_svid(audience=TEST_AUDIENCE)

    assert str(exception.value) == 'Error fetching JWT SVID: Missing required claim: sub'


def test_fetch_jwt_svid_no_token_returned(mocker, client):
    client._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(svids=[])
    )
    with pytest.raises(FetchJwtSvidError) as exception:
        client.fetch_jwt_svid(audience=TEST_AUDIENCE)

    assert str(exception.value) == 'Error fetching JWT SVID: JWT SVID response is empty'


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

    assert str(exc_info.value) == 'Error fetching JWT Bundle: JWT Bundles response is empty'


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
        == 'Error fetching JWT Bundle: Error parsing JWT bundle: Error adding authority '
        'from JWKS: "keyID" cannot be empty'
    )


def test_fetch_jwt_bundles_raise_grpc_call(mocker, client):
    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(side_effect=FakeCall())

    with pytest.raises(FetchJwtBundleError) as exc_info:
        client.fetch_jwt_bundles()

    assert str(exc_info.value) == 'Error fetching JWT Bundle: Error details from Workload API'


def test_fetch_jwt_bundles_raise_grpc_error(mocker, client):
    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=grpc.RpcError('Mocked gRPC error')
    )

    with pytest.raises(FetchJwtBundleError) as exc_info:
        client.fetch_jwt_bundles()

    assert (
        str(exc_info.value)
        == 'Error fetching JWT Bundle: Could not process response from the Workload API'
    )


def test_fetch_jwt_bundles_raise_error(mocker, client):
    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=Exception('Mocked error')
    )

    with pytest.raises(FetchJwtBundleError) as exc_info:
        client.fetch_jwt_bundles()

    assert str(exc_info.value) == 'Error fetching JWT Bundle: Mocked error'


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
        (None, 'audience', 'Token cannot be empty'),
        ('', 'audience', 'Token cannot be empty'),
        ('token', None, 'Audience cannot be empty'),
        ('token', '', 'Audience cannot be empty'),
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

    assert str(exception.value) == 'JWT SVID is not valid: Mocked error'


def test_stream_jwt_bundles_success(mocker, client):
    # Setup the mock responses
    jwt_bundles = {'example.org': JWKS_1_EC_KEY, 'domain.prod': JWKS_2_EC_1_RSA_KEYS}
    jwt_bundles_2 = {'domain.dev': JWKS_1_EC_KEY}

    # Configure the mock for FetchJWTBundles
    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        return_value=delayed_responses(
            [
                workload_pb2.JWTBundlesResponse(bundles=jwt_bundles),
                workload_pb2.JWTBundlesResponse(bundles=jwt_bundles_2),
            ]
        )
    )

    update_event = threading.Event()
    responses = deque()

    def on_success_handler(response):
        responses.append(response)
        update_event.set()  # Signal that a new response is available

    def on_error_handler(error):
        print(f"Error: {error}")
        update_event.set()

    # Start streaming
    client.stream_jwt_bundles(
        on_success=on_success_handler,
        on_error=on_error_handler,
    )

    # Wait for the first update
    update_event.wait(timeout=5)
    update_event.clear()  # Reset the event for the next update
    assert responses, "No response received for the first update"
    # Process and assert the first response
    first_response = responses.popleft()
    jwt_bundle_1 = first_response.get_bundle_for_trust_domain(TrustDomain('example.org'))
    assert jwt_bundle_1
    assert len(jwt_bundle_1.jwt_authorities) == 1

    jwt_bundle_2 = first_response.get_bundle_for_trust_domain(TrustDomain('domain.prod'))
    assert jwt_bundle_2
    assert len(jwt_bundle_2.jwt_authorities) == 3

    # Wait for the second update
    update_event.wait(timeout=1)
    assert len(responses) == 1, "Expected one more response"
    second_response = responses.popleft()
    jwt_bundle = second_response.get_bundle_for_trust_domain(TrustDomain('domain.dev'))
    assert jwt_bundle
    assert len(jwt_bundle.jwt_authorities) == 1


def delayed_responses(responses: List[Any]) -> Iterable:
    """Yields responses with an artificial delay, but without using sleep to avoid slowing down tests."""
    for res in responses:
        yield res  # Assuming this delay simulates asynchronous behavior well enough for the test.


def test_stream_jwt_bundles_retry_on_grpc_error(mocker, client):
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

    client.stream_jwt_bundles(
        on_success=lambda r: handle_success(r, response_holder, event),
        on_error=lambda e: assert_error(e, expected_error),
    )

    event.wait(timeout=5)

    jwt_bundle_set = response_holder.success
    assert jwt_bundle_set
    jwt_bundle_1 = jwt_bundle_set.get_bundle_for_trust_domain(TrustDomain('example.org'))
    assert jwt_bundle_1
    assert len(jwt_bundle_1.jwt_authorities) == 1

    jwt_bundle_2 = jwt_bundle_set.get_bundle_for_trust_domain(TrustDomain('domain.prod'))
    assert jwt_bundle_2
    assert len(jwt_bundle_2.jwt_authorities) == 3


def test_stream_jwt_bundles_no_retry_on_grpc_error(mocker, client):
    grpc_error = FakeCall()
    grpc_error._code = grpc.StatusCode.INVALID_ARGUMENT

    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=[
            grpc_error,
        ]
    )

    expected_error = WorkloadApiError(f"gRPC error: {grpc_error._code}")
    event = threading.Event()
    response_holder = ResponseHolder()

    client.stream_jwt_bundles(
        on_success=lambda r: handle_success(r, response_holder, event),
        on_error=lambda e: handle_error(e, response_holder, event),
    )

    event.wait(5)

    assert not response_holder.success
    assert response_holder.error
    assert_error(response_holder.error, expected_error)


def test_stream_jwt_bundles_no_retry_on_grpc_error_no_call(mocker, client):
    grpc_error = grpc.RpcError()
    grpc_error.code = lambda: grpc.StatusCode.INVALID_ARGUMENT

    mock_error_iter = mocker.MagicMock()
    mock_error_iter.__iter__.side_effect = grpc_error

    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        return_value=mock_error_iter
    )

    done = threading.Event()
    expected_error = WorkloadApiError(f"gRPC error: {grpc.StatusCode.INVALID_ARGUMENT}")

    response_holder = ResponseHolder()

    client.stream_jwt_bundles(
        lambda r: handle_success(r, response_holder, done),
        lambda e: handle_error(e, response_holder, done),
        True,
    )

    done.wait(5)  # add timeout to prevent test from hanging

    assert not response_holder.success
    assert str(response_holder.error) == str(expected_error)


def test_stream_jwt_bundles_no_retry_on_error(mocker, client):
    thrown_error = Exception('Some Error')

    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=thrown_error,
    )

    event = threading.Event()
    response_holder = ResponseHolder()

    client.stream_jwt_bundles(
        on_success=lambda r: handle_success(r, response_holder, event),
        on_error=lambda e: handle_error(e, response_holder, event),
    )

    event.wait(3)  # add timeout to prevent test from hanging

    assert not response_holder.success
    assert response_holder.error
    assert_error(response_holder.error, thrown_error)
