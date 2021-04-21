import threading
from unittest.mock import MagicMock

import grpc
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import Certificate

from pyspiffe.proto.spiffe import workload_pb2
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.spiffe_id.trust_domain import TrustDomain
from pyspiffe.workloadapi.exceptions import FetchX509SvidError, FetchX509BundleError
from pyspiffe.workloadapi.x509_context import X509Context
from test.utils.utils import read_file_bytes
from test.workloadapi.test_default_workload_api_client import WORKLOAD_API_CLIENT

_TEST_CERTS_PATH = 'test/svid/x509svid/certs/{}'
_TEST_BUNDLE_PATH = 'test/bundle/x509bundle/certs/{}'
_CHAIN1 = read_file_bytes(_TEST_CERTS_PATH.format('1-chain.der'))
_KEY1 = read_file_bytes(_TEST_CERTS_PATH.format('1-key.der'))
_CHAIN2 = read_file_bytes(_TEST_CERTS_PATH.format('4-cert.der'))
_KEY2 = read_file_bytes(_TEST_CERTS_PATH.format('4-key.der'))
_BUNDLE = read_file_bytes(_TEST_BUNDLE_PATH.format('cert.der'))
_FEDERATED_BUNDLE = read_file_bytes(_TEST_BUNDLE_PATH.format('federated_bundle.der'))
_CORRUPTED = read_file_bytes(_TEST_CERTS_PATH.format('corrupted'))


def test_fetch_x509_svid_success(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509SVIDResponse(
                    svids=[
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service',
                            x509_svid=_CHAIN1,
                            x509_svid_key=_KEY1,
                        ),
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service2',
                            x509_svid=_CHAIN2,
                            x509_svid_key=_KEY2,
                        ),
                    ]
                )
            ]
        )
    )

    svid = WORKLOAD_API_CLIENT.fetch_x509_svid()

    assert svid.spiffe_id() == SpiffeId.parse('spiffe://example.org/service')
    assert len(svid.cert_chain()) == 2
    assert isinstance(svid.leaf(), Certificate)
    assert isinstance(svid.private_key(), ec.EllipticCurvePrivateKey)


def test_fetch_x509_svid_empty_response(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter([workload_pb2.X509SVIDResponse(svids=[])])
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_svid()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: X.509 SVID response is empty.'
    )


def test_fetch_x509_svid_invalid_response(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter([])
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_svid()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: X.509 SVID response is invalid.'
    )


def test_fetch_x509_svid_raise_exception(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        side_effect=Exception('mocked error')
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_svid()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: X.509 SVID response is invalid.'
    )


def test_fetch_x509_svid_corrupted_response(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509SVIDResponse(
                    svids=[
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service',
                            x509_svid=_CORRUPTED,
                            x509_svid_key=_KEY1,
                        ),
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service2',
                            x509_svid=_CHAIN2,
                            x509_svid_key=_KEY2,
                        ),
                    ]
                )
            ]
        )
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_svid()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: Unable to parse DER X.509 certificate.'
    )


def test_fetch_x509_svids_success(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509SVIDResponse(
                    svids=[
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service',
                            x509_svid=_CHAIN1,
                            x509_svid_key=_KEY1,
                        ),
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service2',
                            x509_svid=_CHAIN2,
                            x509_svid_key=_KEY2,
                        ),
                    ]
                )
            ]
        )
    )

    svids = WORKLOAD_API_CLIENT.fetch_x509_svids()

    assert len(svids) == 2

    svid1 = svids[0]
    assert svid1.spiffe_id() == SpiffeId.parse('spiffe://example.org/service')
    assert len(svid1.cert_chain()) == 2
    assert isinstance(svid1.leaf(), Certificate)
    assert isinstance(svid1.private_key(), ec.EllipticCurvePrivateKey)

    svid2 = svids[1]
    assert svid2.spiffe_id() == SpiffeId.parse('spiffe://example.org/service2')
    assert len(svid2.cert_chain()) == 1
    assert isinstance(svid2.leaf(), Certificate)
    assert isinstance(svid2.private_key(), ec.EllipticCurvePrivateKey)


def test_fetch_x509_svids_empty_response(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter([workload_pb2.X509SVIDResponse(svids=[])])
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_svids()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: X.509 SVID response is empty.'
    )


def test_fetch_x509_svids_invalid_response(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter([])
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_svids()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: X.509 SVID response is invalid.'
    )


def test_fetch_x509_svids_raise_exception(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        side_effect=Exception('mocked error')
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_svids()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: X.509 SVID response is invalid.'
    )


def test_fetch_x509_svids_corrupted_response(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509SVIDResponse(
                    svids=[
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service',
                            x509_svid=_CHAIN1,
                            x509_svid_key=_KEY1,
                        ),
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service2',
                            x509_svid=_CORRUPTED,
                            x509_svid_key=_KEY2,
                        ),
                    ]
                )
            ]
        )
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_svids()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: Unable to parse DER X.509 certificate.'
    )


def test_fetch_x509_context_success(mocker):
    federated_bundles = dict()
    federated_bundles['domain.test'] = _FEDERATED_BUNDLE

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509SVIDResponse(
                    svids=[
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service',
                            x509_svid=_CHAIN1,
                            x509_svid_key=_KEY1,
                            bundle=_BUNDLE,
                        ),
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service2',
                            x509_svid=_CHAIN2,
                            x509_svid_key=_KEY2,
                            bundle=_BUNDLE,
                        ),
                    ],
                    federated_bundles=federated_bundles,
                )
            ]
        )
    )

    x509_context = WORKLOAD_API_CLIENT.fetch_x509_context()

    svids = x509_context.x509_svids()
    bundle_set = x509_context.x509_bundle_set()

    assert len(svids) == 2

    svid1 = x509_context.default_svid()
    assert svid1.spiffe_id() == SpiffeId.parse('spiffe://example.org/service')
    assert len(svid1.cert_chain()) == 2
    assert isinstance(svid1.leaf(), Certificate)
    assert isinstance(svid1.private_key(), ec.EllipticCurvePrivateKey)

    svid2 = x509_context.x509_svids()[1]
    assert svid2.spiffe_id() == SpiffeId.parse('spiffe://example.org/service2')
    assert len(svid2.cert_chain()) == 1
    assert isinstance(svid2.leaf(), Certificate)
    assert isinstance(svid2.private_key(), ec.EllipticCurvePrivateKey)

    bundle = bundle_set.get_x509_bundle_for_trust_domain(TrustDomain('example.org'))
    assert bundle
    assert len(bundle.x509_authorities()) == 1

    federated_bundle = bundle_set.get_x509_bundle_for_trust_domain(
        TrustDomain('domain.test')
    )
    assert federated_bundle
    assert len(federated_bundle.x509_authorities()) == 1


def test_fetch_x509_context_empty_response(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter([workload_pb2.X509SVIDResponse(svids=[])])
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_context()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: X.509 SVID response is empty.'
    )


def test_fetch_x509_context_invalid_response(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter([])
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_context()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: X.509 SVID response is invalid.'
    )


def test_fetch_x509_context_raise_exception(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        side_effect=Exception('mocked error')
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_context()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: X.509 SVID response is invalid.'
    )


def test_fetch_x509_context_corrupted_svid(mocker):
    federated_bundles = dict()
    federated_bundles['domain.test'] = _FEDERATED_BUNDLE

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509SVIDResponse(
                    svids=[
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service',
                            x509_svid=_CHAIN1,
                            x509_svid_key=_CORRUPTED,
                            bundle=_BUNDLE,
                        ),
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service2',
                            x509_svid=_CHAIN2,
                            x509_svid_key=_KEY2,
                            bundle=_BUNDLE,
                        ),
                    ],
                    federated_bundles=federated_bundles,
                )
            ]
        )
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_context()

    assert 'Error fetching X.509 SVID: Error parsing private key' in str(
        exception.value
    )


def test_fetch_x509_context_corrupted_bundle(mocker):
    federated_bundles = dict()
    federated_bundles['domain.test'] = _FEDERATED_BUNDLE

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509SVIDResponse(
                    svids=[
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service',
                            x509_svid=_CHAIN1,
                            x509_svid_key=_KEY1,
                            bundle=_CORRUPTED,
                        ),
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service2',
                            x509_svid=_CHAIN2,
                            x509_svid_key=_KEY2,
                            bundle=_CORRUPTED,
                        ),
                    ],
                    federated_bundles=federated_bundles,
                )
            ]
        )
    )

    with (pytest.raises(FetchX509BundleError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_context()

    assert (
        str(exception.value)
        == 'Error fetching X.509 Bundles: Error parsing X.509 bundle: Unable to parse DER X.509 certificate.'
    )


def test_fetch_x509_context_corrupted_federated_bundle(mocker):
    federated_bundles = dict()
    federated_bundles['domain.test'] = _CORRUPTED

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509SVIDResponse(
                    svids=[
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service',
                            x509_svid=_CHAIN1,
                            x509_svid_key=_KEY1,
                            bundle=_BUNDLE,
                        ),
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service2',
                            x509_svid=_CHAIN2,
                            x509_svid_key=_KEY2,
                            bundle=_BUNDLE,
                        ),
                    ],
                    federated_bundles=federated_bundles,
                )
            ]
        )
    )

    with (pytest.raises(FetchX509BundleError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_context()

    assert (
        str(exception.value)
        == 'Error fetching X.509 Bundles: Error parsing X.509 bundle: Unable to parse DER X.509 certificate.'
    )


def test_fetch_x509_bundles_success(mocker):
    bundles = dict()
    bundles['example.org'] = _BUNDLE
    bundles['domain.test'] = _FEDERATED_BUNDLE

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509BundlesResponse(
                    bundles=bundles,
                )
            ]
        )
    )

    bundle_set = WORKLOAD_API_CLIENT.fetch_x509_bundles()

    bundle = bundle_set.get_x509_bundle_for_trust_domain(TrustDomain('example.org'))
    assert bundle
    assert len(bundle.x509_authorities()) == 1

    federated_bundle = bundle_set.get_x509_bundle_for_trust_domain(
        TrustDomain('domain.test')
    )
    assert federated_bundle
    assert len(federated_bundle.x509_authorities()) == 1


def test_fetch_x509_bundles_empty_response(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(
        return_value=iter([workload_pb2.X509BundlesResponse(bundles=[])])
    )

    with (pytest.raises(FetchX509BundleError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_bundles()

    assert (
        str(exception.value)
        == 'Error fetching X.509 Bundles: X.509 Bundles response is empty.'
    )


def test_fetch_x509_bundles_invalid_response(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(
        return_value=iter([])
    )

    with (pytest.raises(FetchX509BundleError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_bundles()

    assert (
        str(exception.value)
        == 'Error fetching X.509 Bundles: X.509 Bundles response is invalid.'
    )


def test_fetch_x509_bundles_raise_exception(mocker):
    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(
        side_effect=Exception('mocked error')
    )

    with (pytest.raises(FetchX509BundleError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_bundles()

    assert (
        str(exception.value)
        == 'Error fetching X.509 Bundles: X.509 Bundles response is invalid.'
    )


def test_fetch_x509_bundles_corrupted_bundle(mocker):
    bundles = dict()
    bundles['example.org'] = _CORRUPTED
    bundles['domain.test'] = _FEDERATED_BUNDLE

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509BundlesResponse(
                    bundles=bundles,
                )
            ]
        )
    )

    with (pytest.raises(FetchX509BundleError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_bundles()

    assert (
        str(exception.value)
        == 'Error fetching X.509 Bundles: Error parsing X.509 bundle: Unable to parse DER X.509 certificate.'
    )


def test_fetch_x509_bundles_corrupted_federated_bundle(mocker):
    bundles = dict()
    bundles['example.org'] = _BUNDLE
    bundles['domain.test'] = _CORRUPTED

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509BundlesResponse(
                    bundles=bundles,
                )
            ]
        )
    )

    with (pytest.raises(FetchX509BundleError)) as exception:
        WORKLOAD_API_CLIENT.fetch_x509_bundles()

    assert (
        str(exception.value)
        == 'Error fetching X.509 Bundles: Error parsing X.509 bundle: Unable to parse DER X.509 certificate.'
    )


class ResponseHolder:
    # Used in tests to store responses from the watch methods.

    def __init__(self):
        self.error = None
        self.success = None


def test_watch_x509_context_success(mocker):
    federated_bundles = dict()
    federated_bundles['domain.test'] = _FEDERATED_BUNDLE

    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509SVIDResponse(
                    svids=[
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service',
                            x509_svid=_CHAIN1,
                            x509_svid_key=_KEY1,
                            bundle=_BUNDLE,
                        ),
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service2',
                            x509_svid=_CHAIN2,
                            x509_svid_key=_KEY2,
                            bundle=_BUNDLE,
                        ),
                    ],
                    federated_bundles=federated_bundles,
                )
            ]
        )
    )

    done = threading.Event()
    response_holder = ResponseHolder()

    _WORKLOAD_API_CLIENT.watch_x509_context(
        lambda r: handle_x509_context_success(r, response_holder, done),
        lambda e: handle_error(e, response_holder, done),
        True,
    )

    done.wait(5)  # add timeout to prevent test from hanging

    assert not response_holder.error
    x509_context = response_holder.success
    svid1 = x509_context.default_svid()
    assert svid1.spiffe_id() == SpiffeId.parse('spiffe://example.org/service')
    assert len(svid1.cert_chain()) == 2
    assert isinstance(svid1.leaf(), Certificate)
    assert isinstance(svid1.private_key(), ec.EllipticCurvePrivateKey)

    svid2 = x509_context.x509_svids()[1]
    assert svid2.spiffe_id() == SpiffeId.parse('spiffe://example.org/service2')
    assert len(svid2.cert_chain()) == 1
    assert isinstance(svid2.leaf(), Certificate)
    assert isinstance(svid2.private_key(), ec.EllipticCurvePrivateKey)

    bundle_set = x509_context.x509_bundle_set()
    bundle = bundle_set.get_x509_bundle_for_trust_domain(TrustDomain('example.org'))
    assert bundle
    assert len(bundle.x509_authorities()) == 1


def test_watch_x509_context_raise_retryable_grpc_error_and_then_ok_response(mocker):
    mock_error_iter = MagicMock()
    mock_error_iter.__iter__.side_effect = (
        yield_grpc_error_and_then_correct_x509_svid_response()
    )

    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=mock_error_iter
    )

    expected_error = FetchX509SvidError('StatusCode.DEADLINE_EXCEEDED')
    done = threading.Event()

    response_holder = ResponseHolder()

    _WORKLOAD_API_CLIENT.watch_x509_context(
        lambda r: handle_x509_context_success(r, response_holder, done),
        lambda e: assert_error(e, expected_error),
        True,
    )

    done.wait(5)  # add timeout to prevent test from hanging

    x509_context = response_holder.success
    svid1 = x509_context.default_svid()
    assert svid1.spiffe_id() == SpiffeId.parse('spiffe://example.org/service')
    assert len(svid1.cert_chain()) == 2
    assert isinstance(svid1.leaf(), Certificate)
    assert isinstance(svid1.private_key(), ec.EllipticCurvePrivateKey)

    svid2 = x509_context.x509_svids()[1]
    assert svid2.spiffe_id() == SpiffeId.parse('spiffe://example.org/service2')
    assert len(svid2.cert_chain()) == 1
    assert isinstance(svid2.leaf(), Certificate)
    assert isinstance(svid2.private_key(), ec.EllipticCurvePrivateKey)

    bundle_set = x509_context.x509_bundle_set()
    bundle = bundle_set.get_x509_bundle_for_trust_domain(TrustDomain('example.org'))
    assert bundle
    assert len(bundle.x509_authorities()) == 1


def test_watch_x509_context_raise_unretryable_grpc_error(mocker):
    grpc_error = grpc.RpcError()
    grpc_error.code = lambda: grpc.StatusCode.INVALID_ARGUMENT

    mock_error_iter = MagicMock()
    mock_error_iter.__iter__.side_effect = grpc_error

    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=mock_error_iter
    )

    done = threading.Event()
    expected_error = FetchX509SvidError('StatusCode.INVALID_ARGUMENT')

    response_holder = ResponseHolder()

    _WORKLOAD_API_CLIENT.watch_x509_context(
        lambda r: handle_x509_context_success(r, response_holder, done),
        lambda e: handle_error(e, response_holder, done),
        True,
    )

    done.wait(5)  # add timeout to prevent test from hanging

    assert not response_holder.success
    assert str(response_holder.error) == str(expected_error)


def assert_error(error: Exception, expected: Exception):
    assert str(error) == str(expected)


def handle_error(
    error: Exception, response_holder: ResponseHolder, event: threading.Event
):
    response_holder.error = error
    event.set()


def handle_x509_context_success(
    response: X509Context, response_holder: ResponseHolder, event: threading.Event
):
    response_holder.success = response
    event.set()


def yield_grpc_error_and_then_correct_x509_svid_response():
    grpc_error = grpc.RpcError()
    grpc_error.code = lambda: grpc.StatusCode.DEADLINE_EXCEEDED
    yield grpc_error

    federated_bundles = dict()
    federated_bundles['domain.test'] = _FEDERATED_BUNDLE
    response = iter(
        [
            workload_pb2.X509SVIDResponse(
                svids=[
                    workload_pb2.X509SVID(
                        spiffe_id='spiffe://example.org/service',
                        x509_svid=_CHAIN1,
                        x509_svid_key=_KEY1,
                        bundle=_BUNDLE,
                    ),
                    workload_pb2.X509SVID(
                        spiffe_id='spiffe://example.org/service2',
                        x509_svid=_CHAIN2,
                        x509_svid_key=_KEY2,
                        bundle=_BUNDLE,
                    ),
                ],
                federated_bundles=federated_bundles,
            )
        ]
    )
    yield response
