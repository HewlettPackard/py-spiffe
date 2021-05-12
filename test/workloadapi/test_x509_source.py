import pytest

from pyspiffe.proto.spiffe import workload_pb2
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.spiffe_id.trust_domain import TrustDomain
from pyspiffe.workloadapi.default_workload_api_client import DefaultWorkloadApiClient
from pyspiffe.workloadapi.default_x509_source import DefaultX509Source
from test.utils.utils import read_file_bytes

WORKLOAD_API_CLIENT = DefaultWorkloadApiClient('unix:///dummy.path')

TEST_CERTS_PATH = 'test/svid/x509svid/certs/{}'
TEST_BUNDLE_PATH = 'test/bundle/x509bundle/certs/{}'
CHAIN1 = read_file_bytes(TEST_CERTS_PATH.format('1-chain.der'))
KEY1 = read_file_bytes(TEST_CERTS_PATH.format('1-key.der'))
CHAIN2 = read_file_bytes(TEST_CERTS_PATH.format('4-cert.der'))
KEY2 = read_file_bytes(TEST_CERTS_PATH.format('4-key.der'))
BUNDLE = read_file_bytes(TEST_BUNDLE_PATH.format('cert.der'))
FEDERATED_BUNDLE = read_file_bytes(TEST_BUNDLE_PATH.format('federated_bundle.der'))


def mock_client_return_multiple_svids(mocker):
    federated_bundles = dict()
    federated_bundles['domain.test'] = FEDERATED_BUNDLE

    WORKLOAD_API_CLIENT._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
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


def test_x509_source_get_default_x509_svid(mocker):
    mock_client_return_multiple_svids(mocker)

    x509_source = DefaultX509Source(WORKLOAD_API_CLIENT)

    x509_svid = x509_source.get_x509_svid()
    assert x509_svid.spiffe_id() == SpiffeId.parse('spiffe://example.org/service')


def test_x509_source_get_x509_svid_with_picker(mocker):
    mock_client_return_multiple_svids(mocker)

    x509_source = DefaultX509Source(WORKLOAD_API_CLIENT, picker=lambda svids: svids[1])

    x509_svid = x509_source.get_x509_svid()
    assert x509_svid.spiffe_id() == SpiffeId.parse('spiffe://example.org/service2')


def test_x509_source_get_x509_svid_with_invalid_picker(mocker):
    mock_client_return_multiple_svids(mocker)

    # the picker selects an element from the list that doesn't exist
    x509_source = DefaultX509Source(WORKLOAD_API_CLIENT, picker=lambda svids: svids[2])

    # the source should be closed, as it couldn't get the X.509 context set
    with (pytest.raises(Exception)) as exception:
        x509_source.get_x509_svid()

    assert (
        str(exception.value)
        == 'X.509 Source error: Cannot get X.509 SVID: source is closed.'
    )


def test_x509_source_get_bundle_for_trust_domain(mocker):
    mock_client_return_multiple_svids(mocker)
    x509_source = DefaultX509Source(WORKLOAD_API_CLIENT)

    bundle = x509_source.get_bundle_for_trust_domain(TrustDomain('example.org'))
    assert bundle.trust_domain() == TrustDomain('example.org')
    assert len(bundle.x509_authorities()) == 1

    bundle = x509_source.get_bundle_for_trust_domain(TrustDomain('domain.test'))
    assert bundle.trust_domain() == TrustDomain('domain.test')
    assert len(bundle.x509_authorities()) == 1


def test_x509_source_is_closed_get_svid(mocker):
    mock_client_return_multiple_svids(mocker)
    x509_source = DefaultX509Source(WORKLOAD_API_CLIENT)

    x509_source.close()

    with (pytest.raises(Exception)) as exception:
        x509_source.get_x509_svid()

    assert (
        str(exception.value)
        == 'X.509 Source error: Cannot get X.509 SVID: source is closed.'
    )


def test_x509_source_is_closed_get_bundle(mocker):
    mock_client_return_multiple_svids(mocker)
    x509_source = DefaultX509Source(WORKLOAD_API_CLIENT)

    x509_source.close()

    with (pytest.raises(Exception)) as exception:
        x509_source.get_bundle_for_trust_domain(TrustDomain('example.org'))

    assert (
        str(exception.value)
        == 'X.509 Source error: Cannot get X.509 Bundle: source is closed.'
    )
