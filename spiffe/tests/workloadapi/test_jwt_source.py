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

from bundle.jwt_bundle.test_jwt_bundle import JWKS_1_EC_KEY, JWKS_2_EC_1_RSA_KEYS
from spiffe.proto import workload_pb2
from spiffe.workloadapi.jwt_source import JwtSource
from spiffe.workloadapi.workload_api_client import WorkloadApiClient
from spiffe.spiffe_id.spiffe_id import TrustDomain
from spiffe.spiffe_id.spiffe_id import SpiffeId
from spiffe.workloadapi.errors import JwtSourceError, FetchJwtSvidError
from spiffe.errors import ArgumentError
from utils.jwt import generate_test_jwt_token, TEST_AUDIENCE

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

    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        return_value=[
            workload_pb2.JWTBundlesResponse(bundles=jwt_bundles),
            workload_pb2.JWTBundlesResponse(bundles=jwt_bundles),
        ]
    )


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
    with pytest.raises(ArgumentError) as exception:
        _ = jwt_source.fetch_svid("")

    assert str(exception.value) == 'Audience cannot be empty'


def test_error_new(mocker, client):
    client._spiffe_workload_api_stub.FetchJWTSVID = mocker.Mock(
        side_effect=Exception('Mocked Error')
    )
    mock_client_fetch_jwt_bundles(mocker, client)
    jwt_source = JwtSource(client)
    with pytest.raises(FetchJwtSvidError) as exception:
        _ = jwt_source.fetch_svid(TEST_AUDIENCE)

    assert str(exception.value) == 'Error fetching JWT SVID: Mocked Error'


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
    jwt_bundles = {'domain.test': JWKS_1_EC_KEY, 'domain.other': JWKS_2_EC_1_RSA_KEYS}

    client._spiffe_workload_api_stub.FetchJWTBundles = mocker.Mock(
        return_value=[
            workload_pb2.JWTBundlesResponse(bundles=jwt_bundles),
        ],
        side_effect=Exception('Mocked Error'),
    )

    jwt_source = JwtSource(client)

    with pytest.raises(JwtSourceError) as exception:
        _ = jwt_source.get_bundle_for_trust_domain(TrustDomain('domain.test'))

    assert (
        str(exception.value)
        == 'JWT Source error: Cannot get JWT Bundle: source is closed'
    )
