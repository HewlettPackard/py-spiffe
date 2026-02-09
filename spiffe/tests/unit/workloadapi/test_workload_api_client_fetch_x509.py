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

from collections.abc import Iterator
import threading
from unittest.mock import patch

import grpc
import pytest
from pytest_mock import MockerFixture
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import Certificate

from spiffe._proto import workload_pb2
from spiffe.spiffe_id.spiffe_id import SpiffeId
from spiffe.spiffe_id.spiffe_id import TrustDomain
from spiffe.workloadapi.errors import (
    FetchX509SvidError,
    FetchX509BundleError,
    WorkloadApiError,
)
from spiffe.workloadapi.workload_api_client import WorkloadApiClient
from spiffe.workloadapi.x509_context import X509Context
from testutils.certs import (
    CHAIN1,
    KEY1,
    CHAIN2,
    KEY2,
    CORRUPTED,
    FEDERATED_BUNDLE,
    BUNDLE,
)
from testutils.utils import (
    FakeCall,
    ResponseHolder,
    handle_success,
    handle_error,
    assert_error,
)


@pytest.fixture
def client() -> WorkloadApiClient:
    with patch.object(WorkloadApiClient, '_check_spiffe_socket_exists') as mock_check:
        mock_check.return_value = None
        client_instance = WorkloadApiClient('unix:///dummy.path')
    return client_instance


def test_fetch_x509_svid_success(mocker: MockerFixture, client: WorkloadApiClient) -> None:
    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509SVIDResponse(
                    svids=[
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service',
                            x509_svid=CHAIN1,
                            x509_svid_key=KEY1,
                        ),
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service2',
                            x509_svid=CHAIN2,
                            x509_svid_key=KEY2,
                        ),
                    ]
                )
            ]
        )
    )

    svid = client.fetch_x509_svid()

    assert svid.spiffe_id == SpiffeId('spiffe://example.org/service')
    assert len(svid.cert_chain) == 2
    assert isinstance(svid.leaf, Certificate)
    assert isinstance(svid.private_key, ec.EllipticCurvePrivateKey)


def test_fetch_x509_svid_empty_response(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter([workload_pb2.X509SVIDResponse(svids=[])])
    )

    with pytest.raises(FetchX509SvidError) as err:
        client.fetch_x509_svid()

    assert str(err.value) == 'Error fetching X.509 SVID: X.509 SVID response is empty'


def test_fetch_x509_svid_invalid_response(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(return_value=iter([]))

    with pytest.raises(FetchX509SvidError) as err:
        client.fetch_x509_svid()

    assert str(err.value) == 'Error fetching X.509 SVID: X.509 SVID response is invalid'


def test_fetch_x509_svid_raise_grpc_error_call(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(side_effect=FakeCall())

    with pytest.raises(FetchX509SvidError) as err:
        client.fetch_x509_svid()

    msg = str(err.value)
    assert 'Error fetching X.509 SVID' in msg
    assert 'Could not process response from the Workload API' in msg
    assert 'Error details from Workload API' in msg
    assert 'StatusCode.UNKNOWN' in msg


def test_fetch_x509_svid_raise_err(mocker: MockerFixture, client: WorkloadApiClient) -> None:
    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        side_effect=Exception('mocked error')
    )

    with pytest.raises(FetchX509SvidError) as err:
        client.fetch_x509_svid()

    assert str(err.value) == 'Error fetching X.509 SVID: mocked error'


def test_fetch_x509_svid_corrupted_response(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509SVIDResponse(
                    svids=[
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service',
                            x509_svid=CORRUPTED,
                            x509_svid_key=KEY1,
                        ),
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service2',
                            x509_svid=CHAIN2,
                            x509_svid_key=KEY2,
                        ),
                    ]
                )
            ]
        )
    )

    with pytest.raises(FetchX509SvidError) as err:
        client.fetch_x509_svid()

    assert (
        str(err.value)
        == 'Error fetching X.509 SVID: Error parsing certificate: Unable to parse DER X.509 certificate'
    )


def test_fetch_x509_svids_success(mocker: MockerFixture, client: WorkloadApiClient) -> None:
    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509SVIDResponse(
                    svids=[
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service',
                            x509_svid=CHAIN1,
                            x509_svid_key=KEY1,
                        ),
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service2',
                            x509_svid=CHAIN2,
                            x509_svid_key=KEY2,
                        ),
                    ]
                )
            ]
        )
    )

    svids = client.fetch_x509_svids()

    assert len(svids) == 2

    svid1 = svids[0]
    assert svid1.spiffe_id == SpiffeId('spiffe://example.org/service')
    assert len(svid1.cert_chain) == 2
    assert isinstance(svid1.leaf, Certificate)
    assert isinstance(svid1.private_key, ec.EllipticCurvePrivateKey)

    svid2 = svids[1]
    assert svid2.spiffe_id == SpiffeId('spiffe://example.org/service2')
    assert len(svid2.cert_chain) == 1
    assert isinstance(svid2.leaf, Certificate)
    assert isinstance(svid2.private_key, ec.EllipticCurvePrivateKey)


def test_fetch_x509_svids_empty_response(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter([workload_pb2.X509SVIDResponse(svids=[])])
    )

    with pytest.raises(FetchX509SvidError) as err:
        client.fetch_x509_svids()

    assert str(err.value) == 'Error fetching X.509 SVID: X.509 SVID response is empty'


def test_fetch_x509_svids_invalid_response(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(return_value=iter([]))

    with pytest.raises(FetchX509SvidError) as err:
        client.fetch_x509_svids()

    assert str(err.value) == 'Error fetching X.509 SVID: X.509 SVID response is invalid'


def test_fetch_x509_svids_raise_grpc_error_call(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(side_effect=FakeCall())

    with pytest.raises(FetchX509SvidError) as err:
        client.fetch_x509_svids()

    msg = str(err.value)
    assert 'Error fetching X.509 SVID' in msg
    assert 'Could not process response from the Workload API' in msg
    assert 'Error details from Workload API' in msg
    assert 'StatusCode.UNKNOWN' in msg


def test_fetch_x509_svids_raise_err(mocker: MockerFixture, client: WorkloadApiClient) -> None:
    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        side_effect=Exception('mocked error')
    )

    with pytest.raises(FetchX509SvidError) as err:
        client.fetch_x509_svids()

    assert str(err.value) == 'Error fetching X.509 SVID: mocked error'


def test_fetch_x509_svids_corrupted_response(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509SVIDResponse(
                    svids=[
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service',
                            x509_svid=CHAIN1,
                            x509_svid_key=KEY1,
                        ),
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service2',
                            x509_svid=CORRUPTED,
                            x509_svid_key=KEY2,
                        ),
                    ]
                )
            ]
        )
    )

    with pytest.raises(FetchX509SvidError) as err:
        client.fetch_x509_svids()

    assert (
        str(err.value)
        == 'Error fetching X.509 SVID: Error parsing certificate: Unable to parse DER X.509 certificate'
    )


def test_fetch_x509_context_success(mocker: MockerFixture, client: WorkloadApiClient) -> None:
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

    x509_context = client.fetch_x509_context()

    svids = x509_context.x509_svids
    bundle_set = x509_context.x509_bundle_set

    assert len(svids) == 2

    svid1 = x509_context.default_svid
    assert svid1.spiffe_id == SpiffeId('spiffe://example.org/service')
    assert len(svid1.cert_chain) == 2
    assert isinstance(svid1.leaf, Certificate)
    assert isinstance(svid1.private_key, ec.EllipticCurvePrivateKey)

    svid2 = x509_context.x509_svids[1]
    assert svid2.spiffe_id == SpiffeId('spiffe://example.org/service2')
    assert len(svid2.cert_chain) == 1
    assert isinstance(svid2.leaf, Certificate)
    assert isinstance(svid2.private_key, ec.EllipticCurvePrivateKey)

    bundle = bundle_set.get_bundle_for_trust_domain(TrustDomain('example.org'))
    assert bundle
    assert len(bundle.x509_authorities) == 1

    federated_bundle = bundle_set.get_bundle_for_trust_domain(TrustDomain('domain.test'))
    assert federated_bundle
    assert len(federated_bundle.x509_authorities) == 1


def test_fetch_x509_context_empty_response(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter([workload_pb2.X509SVIDResponse(svids=[])])
    )

    with pytest.raises(FetchX509SvidError) as err:
        client.fetch_x509_context()

    assert str(err.value) == 'Error fetching X.509 SVID: X.509 SVID response is empty'


def test_fetch_x509_context_invalid_response(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(return_value=iter([]))

    with pytest.raises(FetchX509SvidError) as err:
        client.fetch_x509_context()

    assert str(err.value) == 'Error fetching X.509 SVID: X.509 SVID response is invalid'


def test_fetch_x509_context_raise_grpc_error(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(side_effect=FakeCall())

    with pytest.raises(FetchX509SvidError) as err:
        client.fetch_x509_context()

    msg = str(err.value)
    assert 'Error fetching X.509 SVID' in msg
    assert 'Could not process response from the Workload API' in msg
    assert 'Error details from Workload API' in msg
    assert 'StatusCode.UNKNOWN' in msg


def test_fetch_x509_context_raise_err(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        side_effect=Exception('mocked error')
    )

    with pytest.raises(FetchX509SvidError) as err:
        client.fetch_x509_context()

    assert str(err.value) == 'Error fetching X.509 SVID: mocked error'


def test_fetch_x509_context_corrupted_svid(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    federated_bundles = {'domain.test': FEDERATED_BUNDLE}

    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509SVIDResponse(
                    svids=[
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service',
                            x509_svid=CHAIN1,
                            x509_svid_key=CORRUPTED,
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

    with pytest.raises(FetchX509SvidError) as err:
        client.fetch_x509_context()

    assert 'Error fetching X.509 SVID: Error parsing private key' in str(err.value)


def test_fetch_x509_context_corrupted_bundle(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
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
                            bundle=CORRUPTED,
                        ),
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service2',
                            x509_svid=CHAIN2,
                            x509_svid_key=KEY2,
                            bundle=CORRUPTED,
                        ),
                    ],
                    federated_bundles=federated_bundles,
                )
            ]
        )
    )

    with pytest.raises(FetchX509SvidError) as err:
        client.fetch_x509_context()

    assert (
        str(err.value)
        == 'Error fetching X.509 SVID: Error parsing X.509 bundle: Error parsing certificate: Unable to parse DER X.509 certificate'
    )


def test_fetch_x509_context_corrupted_federated_bundle(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    federated_bundles = {'domain.test': CORRUPTED}

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

    with pytest.raises(FetchX509SvidError) as err:
        client.fetch_x509_context()

    assert (
        str(err.value)
        == 'Error fetching X.509 SVID: Error parsing X.509 bundle: Error parsing certificate: Unable to parse DER X.509 certificate'
    )


def test_fetch_x509_bundles_success(mocker: MockerFixture, client: WorkloadApiClient) -> None:
    bundles = {'example.org': BUNDLE, 'domain.test': FEDERATED_BUNDLE}

    client._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509BundlesResponse(
                    bundles=bundles,
                )
            ]
        )
    )

    bundle_set = client.fetch_x509_bundles()

    bundle = bundle_set.get_bundle_for_trust_domain(TrustDomain('example.org'))
    assert bundle
    assert len(bundle.x509_authorities) == 1

    federated_bundle = bundle_set.get_bundle_for_trust_domain(TrustDomain('domain.test'))
    assert federated_bundle
    assert len(federated_bundle.x509_authorities) == 1


def test_fetch_x509_bundles_empty_response(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    client._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(
        return_value=iter([workload_pb2.X509BundlesResponse(bundles={})])
    )

    with pytest.raises(FetchX509BundleError) as err:
        client.fetch_x509_bundles()

    assert str(err.value) == 'Error fetching X.509 Bundle: X.509 Bundles response is empty'


def test_fetch_x509_bundles_invalid_response(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    client._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(return_value=iter([]))

    with pytest.raises(FetchX509BundleError) as err:
        client.fetch_x509_bundles()

    assert str(err.value) == 'Error fetching X.509 Bundle: X.509 Bundles response is invalid'


def test_fetch_x509_bundles_raise_grpc_error(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    client._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(side_effect=FakeCall())

    with pytest.raises(FetchX509BundleError) as err:
        client.fetch_x509_bundles()

    msg = str(err.value)
    assert 'Error fetching X.509 Bundle' in msg
    assert 'Could not process response from the Workload API' in msg
    assert 'Error details from Workload API' in msg
    assert 'StatusCode.UNKNOWN' in msg


def test_fetch_x509_bundles_raise_err(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    client._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(
        side_effect=Exception('mocked error')
    )

    with pytest.raises(FetchX509BundleError) as err:
        client.fetch_x509_bundles()

    assert str(err.value) == 'Error fetching X.509 Bundle: mocked error'


def test_fetch_x509_bundles_corrupted_bundle(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    bundles = {'example.org': CORRUPTED, 'domain.test': FEDERATED_BUNDLE}

    client._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509BundlesResponse(
                    bundles=bundles,
                )
            ]
        )
    )

    with pytest.raises(FetchX509BundleError) as err:
        client.fetch_x509_bundles()

    assert (
        str(err.value)
        == 'Error fetching X.509 Bundle: Error parsing X.509 bundle: Error parsing '
        'certificate: Unable to parse DER X.509 certificate'
    )


def test_fetch_x509_bundles_corrupted_federated_bundle(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    bundles = {'example.org': BUNDLE, 'domain.test': CORRUPTED}

    client._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509BundlesResponse(
                    bundles=bundles,
                )
            ]
        )
    )

    with pytest.raises(FetchX509BundleError) as err:
        client.fetch_x509_bundles()

    assert (
        str(err.value)
        == 'Error fetching X.509 Bundle: Error parsing X.509 bundle: Error parsing '
        'certificate: Unable to parse DER X.509 certificate'
    )


def test_stream_x509_contexts_success(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
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

    done = threading.Event()
    response_holder = ResponseHolder[X509Context]()

    client.stream_x509_contexts(
        lambda r: handle_success(r, response_holder, done),
        lambda e: handle_error(e, response_holder, done),
        retry_connect=True,
    )

    done.wait(timeout=5)

    assert response_holder.error is None
    assert response_holder.success is not None
    x509_context = response_holder.success
    svid1 = x509_context.default_svid
    assert svid1._spiffe_id == SpiffeId('spiffe://example.org/service')
    assert len(svid1.cert_chain) == 2
    assert isinstance(svid1.leaf, Certificate)
    assert isinstance(svid1.private_key, ec.EllipticCurvePrivateKey)

    svid2 = x509_context.x509_svids[1]
    assert svid2._spiffe_id == SpiffeId('spiffe://example.org/service2')
    assert len(svid2.cert_chain) == 1
    assert isinstance(svid2.leaf, Certificate)
    assert isinstance(svid2.private_key, ec.EllipticCurvePrivateKey)

    bundle_set = x509_context.x509_bundle_set
    bundle = bundle_set.get_bundle_for_trust_domain(TrustDomain('example.org'))
    assert bundle
    assert len(bundle.x509_authorities) == 1


def test_stream_x509_contexts_raise_retryable_grpc_error_and_then_ok_response(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    mock_error_iter = mocker.MagicMock()
    mock_error_iter.__iter__.side_effect = (
        yield_grpc_error_and_then_correct_x509_svid_response()
    )

    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(return_value=mock_error_iter)

    expected_error = FetchX509SvidError('StatusCode.DEADLINE_EXCEEDED')
    done = threading.Event()

    response_holder = ResponseHolder[X509Context]()

    client.stream_x509_contexts(
        lambda r: handle_success(r, response_holder, done),
        lambda e: assert_error(e, expected_error),
        True,
    )

    done.wait(timeout=90)

    assert response_holder.error is None
    assert response_holder.success is not None
    x509_context = response_holder.success
    svid1 = x509_context.default_svid
    assert svid1._spiffe_id == SpiffeId('spiffe://example.org/service')
    assert len(svid1.cert_chain) == 2
    assert isinstance(svid1.leaf, Certificate)
    assert isinstance(svid1.private_key, ec.EllipticCurvePrivateKey)

    svid2 = x509_context.x509_svids[1]
    assert svid2._spiffe_id == SpiffeId('spiffe://example.org/service2')
    assert len(svid2.cert_chain) == 1
    assert isinstance(svid2.leaf, Certificate)
    assert isinstance(svid2.private_key, ec.EllipticCurvePrivateKey)

    bundle_set = x509_context.x509_bundle_set
    bundle = bundle_set.get_bundle_for_trust_domain(TrustDomain('example.org'))
    assert bundle
    assert len(bundle.x509_authorities) == 1


def test_stream_x509_contexts_raise_unretryable_grpc_error(
    mocker: MockerFixture, client: WorkloadApiClient
) -> None:
    grpc_error = FakeCall()
    grpc_error._code = grpc.StatusCode.INVALID_ARGUMENT

    mock_error_iter = mocker.MagicMock()
    mock_error_iter.__iter__.side_effect = grpc_error

    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(return_value=mock_error_iter)

    done = threading.Event()
    expected_error = WorkloadApiError('gRPC error: StatusCode.INVALID_ARGUMENT')

    response_holder = ResponseHolder[X509Context]()

    client.stream_x509_contexts(
        lambda r: handle_success(r, response_holder, done),
        lambda e: handle_error(e, response_holder, done),
        True,
    )

    done.wait(timeout=5)

    assert not response_holder.success
    assert str(response_holder.error) == str(expected_error)


def yield_grpc_error_and_then_correct_x509_svid_response() -> Iterator[object]:
    grpc_error = FakeCall()
    grpc_error._code = grpc.StatusCode.DEADLINE_EXCEEDED
    yield grpc_error

    federated_bundles = {'domain.test': FEDERATED_BUNDLE}
    response = iter(
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
    yield response
