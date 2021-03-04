import os
from concurrent import futures
from contextlib import contextmanager

import grpc
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import Certificate

from fake_workload_api import FakeWorkloadApi
from pyspiffe.proto.spiffe import workload_pb2_grpc
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.workloadapi.default_workload_api_client import DefaultWorkloadApiClient

SPIFFE_SOCKET_ENV = 'SPIFFE_ENDPOINT_SOCKET'


# No SPIFFE_ENDPOINT_SOCKET, and no path passed, raises exception
def test_instantiate_default_without_var():
    os.environ[SPIFFE_SOCKET_ENV] = ""
    with pytest.raises(ValueError):
        DefaultWorkloadApiClient()


# With SPIFFE_ENDPOINT_SOCKET, and no path passed, succeeds
def test_instantiate_default_with_var():
    os.environ[SPIFFE_SOCKET_ENV] = 'unix:///tmp/agent.sock'
    wlapi = DefaultWorkloadApiClient()
    del os.environ[SPIFFE_SOCKET_ENV]
    assert wlapi.get_spiffe_endpoint_socket() == 'unix:///tmp/agent.sock'


# Pass socket path
def test_instantiate_socket_path():
    wlapi = DefaultWorkloadApiClient(spiffe_socket='unix:///tmp/agent.sock')
    assert wlapi.get_spiffe_endpoint_socket() == 'unix:///tmp/agent.sock'


# With bad SPIFFE_ENDPOINT_SOCKET, and no path passed, throws exception
def test_instantiate_default_with_bad_var():
    os.environ[SPIFFE_SOCKET_ENV] = '/invalid'
    with pytest.raises(ValueError):
        DefaultWorkloadApiClient()
    del os.environ[SPIFFE_SOCKET_ENV]


# With bad socket path passed
def test_instantiate_bad_socket_path():
    with pytest.raises(ValueError):
        DefaultWorkloadApiClient(spiffe_socket='/invalid')


def test_fetch_x509_svid():
    with workload_api(FakeWorkloadApi) as fake_stub:
        client = DefaultWorkloadApiClient('unix:/dummy')
        client._spiffe_workload_api_stub = fake_stub

        svid = client.fetch_x509_svid()

        assert svid.spiffe_id() == SpiffeId.parse('spiffe://example.org/service')
        assert len(svid.cert_chain()) == 2
        assert isinstance(svid.leaf(), Certificate)
        assert isinstance(svid.private_key(), ec.EllipticCurvePrivateKey)


# TODO: Implement using the FakeWorkloadApi
def test_fetch_jx509_context():
    wlapi = get_client()
    wlapi.fetch_x509_context()


# TODO: Implement using the FakeWorkloadApi
def test_fetch_jx509_bundles():
    wlapi = get_client()
    wlapi.fetch_x509_bundles()


# TODO: Implement using the FakeWorkloadApi
def test_fetch_jwt_svid_aud():
    wlapi = get_client()
    audiences = ['foo', 'bar']
    wlapi.fetch_jwt_svid(audiences=audiences)


# TODO: Implement using the FakeWorkloadApi
def test_fetch_jwt_svid_aud_sub():
    wlapi = get_client()
    audiences = ['foo', 'bar']
    wlapi.fetch_jwt_svid(audiences=audiences, subject='spiffe://TODO')


# TODO: Implement using the FakeWorkloadApi
def test_fetch_jwt_bundles():
    wlapi = get_client()
    wlapi.fetch_jwt_bundles()


# TODO: Implement using the FakeWorkloadApi
def test_validate_jwt_svid():
    wlapi = get_client()
    token = 'TODO'
    audiences = 'foo'
    wlapi.validate_jwt_svid(token=token, audience=audiences)


# Utility functions
def get_client():
    return DefaultWorkloadApiClient(spiffe_socket='unix:///tmp/agent.sock')


@contextmanager
def workload_api(cls):
    """Instantiate a WorkloadApi and return a stub for use in tests"""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    workload_pb2_grpc.add_SpiffeWorkloadAPIServicer_to_server(cls(), server)
    port = server.add_insecure_port('[::]:0')
    server.start()

    try:
        with grpc.insecure_channel('localhost:%d' % port) as channel:
            yield workload_pb2_grpc.SpiffeWorkloadAPIStub(channel)
    finally:
        server.stop(None)
