import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import Certificate

from pyspiffe.proto.spiffe import workload_pb2
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.workloadapi.default_workload_api_client import DefaultWorkloadApiClient
from pyspiffe.workloadapi.exceptions import FetchX509SvidError
from test.utils.utils import read_file_bytes

_TEST_CERTS_PATH = 'test/svid/x509svid/certs/{}'


def test_fetch_x509_svid_success(mocker):
    client = DefaultWorkloadApiClient('unix:///dummy.path')
    chain_bytes = read_file_bytes(_TEST_CERTS_PATH.format('1-chain.der'))
    key_bytes = read_file_bytes(_TEST_CERTS_PATH.format('1-key.der'))

    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter(
            [
                workload_pb2.X509SVIDResponse(
                    svids=[
                        workload_pb2.X509SVID(
                            spiffe_id='spiffe://example.org/service',
                            x509_svid=chain_bytes,
                            x509_svid_key=key_bytes,
                        )
                    ]
                )
            ]
        )
    )

    svid = client.fetch_x509_svid()

    assert svid.spiffe_id() == SpiffeId.parse('spiffe://example.org/service')
    assert len(svid.cert_chain()) == 2
    assert isinstance(svid.leaf(), Certificate)
    assert isinstance(svid.private_key(), ec.EllipticCurvePrivateKey)


def test_fetch_x509_svid_empty_response(mocker):
    client = DefaultWorkloadApiClient('unix:///dummy.path')

    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        return_value=iter([workload_pb2.X509SVIDResponse(svids=[])])
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        client.fetch_x509_svid()

    assert str(exception.value) == 'X.509 SVID response is empty.'


def test_fetch_x509_svid_invalid_response(mocker):
    client = DefaultWorkloadApiClient('unix:///dummy.path')

    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(return_value=iter([]))

    with (pytest.raises(FetchX509SvidError)) as exception:
        client.fetch_x509_svid()

    assert str(exception.value) == 'X.509 SVID response is invalid.'


def test_fetch_x509_svid_raise_exception(mocker):
    client = DefaultWorkloadApiClient('unix:///dummy.path')

    client._spiffe_workload_api_stub.FetchX509SVID = mocker.Mock(
        side_effect=Exception('mocked error')
    )

    with (pytest.raises(FetchX509SvidError)) as exception:
        client.fetch_x509_svid()

    assert str(exception.value) == 'X.509 SVID response is invalid.'
