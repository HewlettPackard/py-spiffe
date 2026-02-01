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

from spiffe import X509Svid, X509Bundle, X509BundleSet
from spiffe.proto import workload_pb2
from spiffe.spiffe_id.spiffe_id import SpiffeId
from spiffe.spiffe_id.spiffe_id import TrustDomain
from spiffe.workloadapi.errors import X509SourceError, WorkloadApiError
from spiffe.workloadapi.x509_context import X509Context
from spiffe.workloadapi.x509_source import X509Source

from spiffe.workloadapi.workload_api_client import (
    WorkloadApiClient,
)
from testutils.certs import FEDERATED_BUNDLE, CHAIN1, KEY1, BUNDLE, CHAIN2, KEY2


@pytest.fixture
def client():
    with patch.object(WorkloadApiClient, '_check_spiffe_socket_exists') as mock_check:
        mock_check.return_value = None
        client_instance = WorkloadApiClient('unix:///dummy.path')
    return client_instance


def mock_client_return_multiple_svids(mocker, client):
    federated_bundles = {'domain.test': FEDERATED_BUNDLE}

    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509SVIDResponse(
                    svids=[
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service',
                            x509_svid=CHAIN1,
                            x509_svid_key=KEY1,
                            bundle=BUNDLE,
                        ),
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service2',
                            x509_svid=CHAIN2,
                            x509_svid_key=KEY2,
                            bundle=BUNDLE,
                        ),
                    ],
                    federated_bundles=federated_bundles,
                )
            ]
        )
    )


def test_x509_source_get_default_x509_svid(mocker, client):
    mock_client_return_multiple_svids(mocker, client)

    x509_source = X509Source(client)

    x509_svid = x509_source.svid
    assert x509_svid.spiffe_id == SpiffeId('spiffe://example.org/service')


def test_x509_source_get_x509_svid_with_picker(mocker, client):
    mock_client_return_multiple_svids(mocker, client)

    x509_source = X509Source(client, svid_picker=lambda svids: svids[1])

    x509_svid = x509_source.svid
    assert x509_svid.spiffe_id == SpiffeId('spiffe://example.org/service2')


def test_x509_source_get_x509_svid_with_invalid_picker(mocker, client):
    mock_client_return_multiple_svids(mocker, client)

    with pytest.raises(X509SourceError) as err:
        # the picker selects an element from the list that doesn't exist
        X509Source(client, svid_picker=lambda svids: svids[2])

    assert (
        str(err.value)
        == 'X.509 Source error: Failed to create X509Source: Failed to pick X509 SVID: list index out of range'
    )


def test_x509_source_get_bundle_for_trust_domain(mocker, client):
    mock_client_return_multiple_svids(mocker, client)

    x509_source = X509Source(client)

    bundle = x509_source.get_bundle_for_trust_domain(TrustDomain('example.org'))
    assert bundle.trust_domain == TrustDomain('example.org')
    assert len(bundle.x509_authorities) == 1

    bundle = x509_source.get_bundle_for_trust_domain(TrustDomain('domain.test'))
    assert bundle.trust_domain == TrustDomain('domain.test')
    assert len(bundle.x509_authorities) == 1


def test_x509_source_is_closed_get_svid(mocker, client):
    mock_client_return_multiple_svids(mocker, client)

    x509_source = X509Source(client)

    x509_source.close()

    with pytest.raises(X509SourceError) as err:
        x509_source.svid

    assert str(err.value) == 'X.509 Source error: Cannot get X.509 SVID: source is closed'


def test_x509_source_subscription_and_unsubscription_behavior(mocker, client):
    # Prepare mock callback
    mock_callback = mocker.MagicMock()

    # Prepare the X509Source
    mock_client_return_multiple_svids(mocker, client)
    x509_source = X509Source(client)

    # Subscribe the mock callback to X509Source updates
    x509_source.subscribe_for_updates(mock_callback)

    # Prepare mock X509Context data
    svid = X509Svid.parse_raw(CHAIN1, KEY1)
    bundle = X509Bundle.parse_raw(TrustDomain("example.org"), BUNDLE)
    bundle_set = X509BundleSet.of([bundle])
    x509_context = X509Context([svid], bundle_set)

    # Trigger notification updating the source
    x509_source._set_context(x509_context)

    # Verify that the mock callback was called
    mock_callback.assert_called_once_with()

    # Unsubscribe the mock callback
    x509_source.unsubscribe_for_updates(mock_callback)

    # Reset mock to clear the call history
    mock_callback.reset_mock()

    # Trigger notification again
    x509_source._set_context(x509_context)

    # Verify that the mock callback wasn't called this time
    mock_callback.assert_not_called()


def test_x509_source_is_closed_get_bundle(mocker, client):
    mock_client_return_multiple_svids(mocker, client)

    x509_source = X509Source(client)

    x509_source.close()

    with pytest.raises(X509SourceError) as err:
        x509_source.get_bundle_for_trust_domain(TrustDomain('example.org'))

    assert str(err.value) == 'X.509 Source error: Cannot get X.509 Bundle: source is closed'


def test_x509_source_closes_on_error_after_init(mocker, client):
    """Test that source closes on error after first update."""
    mock_client_return_multiple_svids(mocker, client)

    x509_source = X509Source(client)

    # Simulate an error after initialization
    x509_source._on_error(WorkloadApiError("Test error"))

    # Source should be closed and accessing svid/bundles should raise error
    with pytest.raises(X509SourceError) as err:
        _ = x509_source.svid
    assert 'source has error' in str(err.value)

    with pytest.raises(X509SourceError) as err:
        _ = x509_source.bundles
    assert 'source has error' in str(err.value)


def test_x509_source_bundles_returns_frozenset(mocker, client):
    """Test that bundles property returns frozenset."""
    mock_client_return_multiple_svids(mocker, client)

    x509_source = X509Source(client)
    bundles = x509_source.bundles

    # Should return frozenset
    assert isinstance(bundles, frozenset)

    # Should not be able to mutate
    with pytest.raises(AttributeError):
        bundles.add(X509Bundle.parse_raw(TrustDomain("test"), BUNDLE))


def test_x509_source_unsubscribe_missing_callback(mocker, client):
    """Test that unsubscribe handles missing callback gracefully."""
    mock_client_return_multiple_svids(mocker, client)

    x509_source = X509Source(client)

    # Unsubscribe a callback that was never subscribed - should not raise
    callback = mocker.MagicMock()
    x509_source.unsubscribe_for_updates(callback)  # Should not raise ValueError
