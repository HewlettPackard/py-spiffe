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

from unittest.mock import patch

import pytest

from spiffe import JwtBundle, JwtBundleSet
from spiffe.proto import workload_pb2
from spiffe.workloadapi.jwt_source import JwtSource
from spiffe.workloadapi.workload_api_client import WorkloadApiClient
from spiffe.spiffe_id.spiffe_id import TrustDomain
from spiffe.spiffe_id.spiffe_id import SpiffeId
from spiffe.workloadapi.errors import JwtSourceError, FetchJwtSvidError, WorkloadApiError
from spiffe.errors import ArgumentError
from testutils.jwt import (
    generate_test_jwt_token,
    JWKS_1_EC_KEY,
    JWKS_2_EC_1_RSA_KEYS,
    TEST_AUDIENCE,
)

SPIFFE_ID = SpiffeId('spiffe://domain.test/my_service')


@pytest.fixture
def client():
    with patch.object(WorkloadApiClient, '_check_spiffe_socket_exists') as mock_check:
        mock_check.return_value = None
        client_instance = WorkloadApiClient('unix:///dummy.path')
    return client_instance


def mock_client_get_jwt_svid(mocker, client):
    jwt_svid = generate_test_jwt_token(spiffe_id=str(SPIFFE_ID))

    client._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        return_value=workload_pb2.JWTSVIDResponse(
            svids=[
                workload_pb2.JWTSVID(
                    spiffe_id=str(SPIFFE_ID),
                    svid=jwt_svid,
                )
            ]
        )
    )


def mock_client_fetch_jwt_bundles(mocker, client):
    jwt_bundles = {'domain.test': JWKS_1_EC_KEY, 'domain.prod': JWKS_2_EC_1_RSA_KEYS}

    def response_generator():
        yield workload_pb2.JWTBundlesResponse(bundles=jwt_bundles)
        yield workload_pb2.JWTBundlesResponse(bundles=jwt_bundles)

    # Use side_effect to return a new generator each time FetchJWTBundles is called.
    # This ensures the generator is fresh and not exhausted, without extra state management.
    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=lambda *args, **kwargs: response_generator()
    )


def test_jwt_source_subscription_and_unsubscription_behavior(mocker, client):
    # Prepare mock callback
    mock_callback = mocker.MagicMock()

    # Prepare the JwtSource
    mock_client_fetch_jwt_bundles(mocker, client)
    jwt_source = JwtSource(client)

    # Subscribe the mock callback to JwtSource updates
    jwt_source.subscribe_for_updates(mock_callback)

    # Prepare mock JwtBundle data
    bundle = JwtBundle.parse(TrustDomain('domain.test'), JWKS_1_EC_KEY)
    bundle_set = JwtBundleSet.of([bundle])

    # Trigger notification updating the source
    jwt_source._set_jwt_bundle_set(bundle_set)

    # Verify that the mock callback was called
    mock_callback.assert_called_once_with()

    # Unsubscribe the mock callback
    jwt_source.unsubscribe_for_updates(mock_callback)

    # Reset mock to clear the call history
    mock_callback.reset_mock()

    # Trigger notification again
    jwt_source._set_jwt_bundle_set(bundle_set)

    # Verify that the mock callback wasn't called this time
    mock_callback.assert_not_called()


def test_get_jwt_svid(mocker, client):
    mock_client_get_jwt_svid(mocker, client)
    mock_client_fetch_jwt_bundles(mocker, client)

    jwt_source = JwtSource(client)
    jwt_svid = jwt_source.fetch_svid(TEST_AUDIENCE, subject=SPIFFE_ID)

    assert jwt_svid._spiffe_id == SPIFFE_ID
    assert jwt_svid._audience == TEST_AUDIENCE


def test_get_jwt_svid_no_subject(mocker, client):
    mock_client_get_jwt_svid(mocker, client)
    mock_client_fetch_jwt_bundles(mocker, client)

    jwt_source = JwtSource(client)
    jwt_svid = jwt_source.fetch_svid(TEST_AUDIENCE)

    assert jwt_svid._spiffe_id == SPIFFE_ID
    assert jwt_svid._audience == TEST_AUDIENCE


def test_get_jwt_svid_exception(mocker, client):
    mock_client_get_jwt_svid(mocker, client)
    mock_client_fetch_jwt_bundles(mocker, client)

    jwt_source = JwtSource(client)
    with pytest.raises(ArgumentError) as err:
        _ = jwt_source.fetch_svid("")

    assert str(err.value) == 'Audience cannot be empty'


def test_error_new(mocker, client):
    client._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        side_effect=Exception('Mocked Error')
    )
    mock_client_fetch_jwt_bundles(mocker, client)
    jwt_source = JwtSource(client)
    with pytest.raises(FetchJwtSvidError) as err:
        _ = jwt_source.fetch_svid(TEST_AUDIENCE)

    assert str(err.value) == 'Error fetching JWT SVID: Mocked Error'


def test_close(mocker, client):
    mock_client_get_jwt_svid(mocker, client)
    mock_client_fetch_jwt_bundles(mocker, client)

    jwt_source = JwtSource(client)
    jwt_source.close()

    assert jwt_source.is_closed()


def test_close_twice(mocker, client):
    mock_client_get_jwt_svid(mocker, client)
    mock_client_fetch_jwt_bundles(mocker, client)

    jwt_source = JwtSource(client)
    jwt_source.close()
    jwt_source.close()

    assert jwt_source.is_closed()


def test_is_closed(mocker, client):
    mock_client_get_jwt_svid(mocker, client)
    mock_client_fetch_jwt_bundles(mocker, client)

    jwt_source = JwtSource(client)
    assert not jwt_source.is_closed()
    jwt_source.close()
    assert jwt_source.is_closed()


def get_jwt_bundle(mocker, client):
    mock_client_get_jwt_svid(mocker, client)
    mock_client_fetch_jwt_bundles(mocker, client)

    jwt_source = JwtSource(client)

    jwt_bundle = jwt_source.get_bundle_for_trust_domain(TrustDomain('domain.test'))
    assert jwt_bundle
    assert len(jwt_bundle.jwt_authorities) == 1


def test_get_jwt_bundle_exception(mocker, client):
    # Mock to raise exception when FetchJWTBundles is called
    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        side_effect=Exception('Mocked Error'),
    )

    with pytest.raises(JwtSourceError) as err:
        JwtSource(client)

    assert str(err.value) == 'JWT Source error: Failed to create JwtSource: Mocked Error'


def test_jwt_source_closes_on_error_after_init(mocker, client):
    """Test that source closes on error after first update."""
    mock_client_fetch_jwt_bundles(mocker, client)

    jwt_source = JwtSource(client)

    # Simulate an error after initialization
    jwt_source._on_error(WorkloadApiError("Test error"))

    # Source should be closed and accessing bundles should raise error
    with pytest.raises(JwtSourceError) as err:
        _ = jwt_source.bundles
    assert 'source has error' in str(err.value)

    with pytest.raises(JwtSourceError) as err:
        _ = jwt_source.get_bundle_for_trust_domain(TrustDomain('domain.test'))
    assert 'source has error' in str(err.value)


def test_jwt_source_bundles_returns_frozenset(mocker, client):
    """Test that bundles property returns frozenset."""
    mock_client_fetch_jwt_bundles(mocker, client)

    jwt_source = JwtSource(client)
    bundles = jwt_source.bundles

    # Should return frozenset
    assert isinstance(bundles, frozenset)

    # Should not be able to mutate
    with pytest.raises(AttributeError):
        bundles.add(JwtBundle.parse(TrustDomain("test"), JWKS_1_EC_KEY))


def test_jwt_source_unsubscribe_missing_callback(mocker, client):
    """Test that unsubscribe handles missing callback gracefully."""
    mock_client_fetch_jwt_bundles(mocker, client)

    jwt_source = JwtSource(client)

    # Unsubscribe a callback that was never subscribed - should not raise
    callback = mocker.MagicMock()
    jwt_source.unsubscribe_for_updates(callback)  # Should not raise ValueError
