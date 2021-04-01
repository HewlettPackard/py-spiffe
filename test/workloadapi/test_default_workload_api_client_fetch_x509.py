import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import Certificate

from pyspiffe.proto.spiffe import workload_pb2
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.spiffe_id.trust_domain import TrustDomain
from pyspiffe.workloadapi.default_workload_api_client import DefaultWorkloadApiClient
from pyspiffe.workloadapi.exceptions import FetchX509SvidError, FetchX509BundleError
from test.utils.utils import read_file_bytes

_WORKLOAD_API_CLIENT = DefaultWorkloadApiClient('unix:///dummy.path')
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
    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
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

    svid = _WORKLOAD_API_CLIENT.fetch_x509_svid()

    assert svid.spiffe_id() == SpiffeId.parse('spiffe://example.org/service')
    assert len(svid.cert_chain()) == 2
    assert isinstance(svid.leaf(), Certificate)
    assert isinstance(svid.private_key(), ec.EllipticCurvePrivateKey)


def test_fetch_x509_svid_empty_response(mocker):
    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter([workload_pb2.X509SVIDResponse(svids=[])])
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        _WORKLOAD_API_CLIENT.fetch_x509_svid()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: X.509 SVID response is empty.'
    )


def test_fetch_x509_svid_invalid_response(mocker):
    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter([])
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        _WORKLOAD_API_CLIENT.fetch_x509_svid()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: X.509 SVID response is invalid.'
    )


def test_fetch_x509_svid_raise_exception(mocker):
    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        side_effect=Exception('mocked error')
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        _WORKLOAD_API_CLIENT.fetch_x509_svid()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: X.509 SVID response is invalid.'
    )


def test_fetch_x509_svid_corrupted_response(mocker):
    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
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
        _WORKLOAD_API_CLIENT.fetch_x509_svid()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: Error parsing certificate: Unable to parse DER X.509 certificate.'
    )


def test_fetch_x509_svids_success(mocker):
    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
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

    svids = _WORKLOAD_API_CLIENT.fetch_x509_svids()

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
    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter([workload_pb2.X509SVIDResponse(svids=[])])
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        _WORKLOAD_API_CLIENT.fetch_x509_svids()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: X.509 SVID response is empty.'
    )


def test_fetch_x509_svids_invalid_response(mocker):
    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter([])
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        _WORKLOAD_API_CLIENT.fetch_x509_svids()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: X.509 SVID response is invalid.'
    )


def test_fetch_x509_svids_raise_exception(mocker):
    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        side_effect=Exception('mocked error')
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        _WORKLOAD_API_CLIENT.fetch_x509_svids()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: X.509 SVID response is invalid.'
    )


def test_fetch_x509_svids_corrupted_response(mocker):
    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
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
        _WORKLOAD_API_CLIENT.fetch_x509_svids()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: Error parsing certificate: Unable to parse DER X.509 certificate.'
    )


def test_fetch_x509_context_success(mocker):
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

    x509_context = _WORKLOAD_API_CLIENT.fetch_x509_context()

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
    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter([workload_pb2.X509SVIDResponse(svids=[])])
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        _WORKLOAD_API_CLIENT.fetch_x509_context()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: X.509 SVID response is empty.'
    )


def test_fetch_x509_context_invalid_response(mocker):
    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter([])
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        _WORKLOAD_API_CLIENT.fetch_x509_context()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: X.509 SVID response is invalid.'
    )


def test_fetch_x509_context_raise_exception(mocker):
    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        side_effect=Exception('mocked error')
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        _WORKLOAD_API_CLIENT.fetch_x509_context()

    assert (
        str(exception.value)
        == 'Error fetching X.509 SVID: X.509 SVID response is invalid.'
    )


def test_fetch_x509_context_corrupted_svid(mocker):
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
        _WORKLOAD_API_CLIENT.fetch_x509_context()

    assert 'Error fetching X.509 SVID: Error parsing private key' in str(
        exception.value
    )


def test_fetch_x509_context_corrupted_bundle(mocker):
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
        _WORKLOAD_API_CLIENT.fetch_x509_context()

    assert (
        str(exception.value)
        == 'Error fetching X.509 Bundles: Unable to parse DER X.509 certificate.'
    )


def test_fetch_x509_context_corrupted_federated_bundle(mocker):
    federated_bundles = dict()
    federated_bundles['domain.test'] = _CORRUPTED

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

    with (pytest.raises(FetchX509BundleError)) as exception:
        _WORKLOAD_API_CLIENT.fetch_x509_context()

    assert (
        str(exception.value)
        == 'Error fetching X.509 Bundles: Unable to parse DER X.509 certificate.'
    )


def test_fetch_x509_bundles_success(mocker):
    bundles = dict()
    bundles['example.org'] = _BUNDLE
    bundles['domain.test'] = _FEDERATED_BUNDLE

    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509BundlesResponse(
                    bundles=bundles,
                )
            ]
        )
    )

    bundle_set = _WORKLOAD_API_CLIENT.fetch_x509_bundles()

    bundle = bundle_set.get_x509_bundle_for_trust_domain(TrustDomain('example.org'))
    assert bundle
    assert len(bundle.x509_authorities()) == 1

    federated_bundle = bundle_set.get_x509_bundle_for_trust_domain(
        TrustDomain('domain.test')
    )
    assert federated_bundle
    assert len(federated_bundle.x509_authorities()) == 1


def test_fetch_x509_bundles_empty_response(mocker):
    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(
        return_value=iter([workload_pb2.X509BundlesResponse(bundles=[])])
    )

    with (pytest.raises(FetchX509BundleError)) as exception:
        _WORKLOAD_API_CLIENT.fetch_x509_bundles()

    assert (
        str(exception.value)
        == 'Error fetching X.509 Bundles: X.509 Bundles response is empty.'
    )


def test_fetch_x509_bundles_invalid_response(mocker):
    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(
        return_value=iter([])
    )

    with (pytest.raises(FetchX509BundleError)) as exception:
        _WORKLOAD_API_CLIENT.fetch_x509_bundles()

    assert (
        str(exception.value)
        == 'Error fetching X.509 Bundles: X.509 Bundles response is invalid.'
    )


def test_fetch_x509_bundles_raise_exception(mocker):
    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(
        side_effect=Exception('mocked error')
    )

    with (pytest.raises(FetchX509BundleError)) as exception:
        _WORKLOAD_API_CLIENT.fetch_x509_bundles()

    assert (
        str(exception.value)
        == 'Error fetching X.509 Bundles: X.509 Bundles response is invalid.'
    )


def test_fetch_x509_bundles_corrupted_bundle(mocker):
    bundles = dict()
    bundles['example.org'] = _CORRUPTED
    bundles['domain.test'] = _FEDERATED_BUNDLE

    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509BundlesResponse(
                    bundles=bundles,
                )
            ]
        )
    )

    with (pytest.raises(FetchX509BundleError)) as exception:
        _WORKLOAD_API_CLIENT.fetch_x509_bundles()

    assert (
        str(exception.value)
        == 'Error fetching X.509 Bundles: Unable to parse DER X.509 certificate.'
    )


def test_fetch_x509_bundles_corrupted_federated_bundle(mocker):
    bundles = dict()
    bundles['example.org'] = _BUNDLE
    bundles['domain.test'] = _CORRUPTED

    _WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509Bundles = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509BundlesResponse(
                    bundles=bundles,
                )
            ]
        )
    )

    with (pytest.raises(FetchX509BundleError)) as exception:
        _WORKLOAD_API_CLIENT.fetch_x509_bundles()

    assert (
        str(exception.value)
        == 'Error fetching X.509 Bundles: Unable to parse DER X.509 certificate.'
    )
