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

from pyspiffe.proto.spiffe import workload_pb2
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.spiffe_id.spiffe_id import TrustDomain
from pyspiffe.workloadapi.exceptions import X509SourceError
from pyspiffe.workloadapi.x509_source import X509Source

from src.pyspiffe.workloadapi.workload_api_client import (
    WorkloadApiClient,
)
from test.workloadapi.test_constants import (
    FEDERATED_BUNDLE,
    CHAIN1,
    KEY1,
    BUNDLE,
    CHAIN2,
    KEY2,
)


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

    x509_source = X509Source(client, picker=lambda svids: svids[1])

    x509_svid = x509_source.svid
    assert x509_svid.spiffe_id == SpiffeId('spiffe://example.org/service2')


def test_x509_source_get_x509_svid_with_invalid_picker(mocker, client):
    mock_client_return_multiple_svids(mocker, client)

    # the picker selects an element from the list that doesn't exist
    x509_source = X509Source(client, picker=lambda svids: svids[2])

    # the source should be closed, as it couldn't get the X.509 context set
    with pytest.raises(X509SourceError) as exception:
        x509_source.svid

    assert (
        str(exception.value)
        == 'X.509 Source error: Cannot get X.509 SVID: source is closed.'
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

    with pytest.raises(X509SourceError) as exception:
        x509_source.svid

    assert (
        str(exception.value)
        == 'X.509 Source error: Cannot get X.509 SVID: source is closed.'
    )


def test_x509_source_is_closed_get_bundle(mocker, client):
    mock_client_return_multiple_svids(mocker, client)

    x509_source = X509Source(client)

    x509_source.close()

    with pytest.raises(X509SourceError) as exception:
        x509_source.get_bundle_for_trust_domain(TrustDomain('example.org'))

    assert (
        str(exception.value)
        == 'X.509 Source error: Cannot get X.509 Bundle: source is closed.'
    )
