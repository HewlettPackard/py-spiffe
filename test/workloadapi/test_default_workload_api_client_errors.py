import pytest

from fake_workload_api_errors import (
    FakeWorkloadApiEmptyResponse,
    FakeWorkloadApiInvalidResponse,
    FakeWorkloadApiRaiseException,
)
from pyspiffe.workloadapi.default_workload_api_client import DefaultWorkloadApiClient
from pyspiffe.workloadapi.exceptions import FetchX509SvidError
from utils import workload_api


def test_fetch_x509_svid_empty_response():
    with workload_api(FakeWorkloadApiEmptyResponse) as fake_stub:
        client = DefaultWorkloadApiClient('unix:/dummy')
        client._spiffe_workload_api_stub = fake_stub

        with (pytest.raises(FetchX509SvidError)) as exception:
            client.fetch_x509_svid()

        assert str(exception.value) == 'X.509 SVID response is empty.'


def test_fetch_x509_svid_invalid_response():
    with workload_api(FakeWorkloadApiInvalidResponse) as fake_stub:
        client = DefaultWorkloadApiClient('unix:/dummy')
        client._spiffe_workload_api_stub = fake_stub

        with (pytest.raises(FetchX509SvidError)) as exception:
            client.fetch_x509_svid()

        assert str(exception.value) == 'X.509 SVID response is invalid.'


def test_fetch_x509_svid_raise_exception():
    with workload_api(FakeWorkloadApiRaiseException) as fake_stub:
        client = DefaultWorkloadApiClient('unix:/dummy')
        client._spiffe_workload_api_stub = fake_stub

        with (pytest.raises(FetchX509SvidError)) as exception:
            client.fetch_x509_svid()

        assert str(exception.value) == 'X.509 SVID response is invalid.'
