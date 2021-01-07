import os
import pytest

from pyspiffe.workloadapi.default_workload_api_client import DefaultWorkloadApiClient

# TODO: How to test functions that talk to workload API

# No SPIFFE_ENDPOINT_SOCKET, and no path passed, raises exception
def test_instantiate_default_without_var():
  with pytest.raises(RuntimeError):
    wlapi = DefaultWorkloadApiClient()

# With SPIFFE_ENDPOINT_SOCKET, and no path passed, succeeds
def test_instantiate_default_with_var():
  os.environ['SPIFFE_ENDPOINT_SOCKET'] = '/tmp/agent.sock'
  wlapi = DefaultWorkloadApiClient()
  del os.environ['SPIFFE_ENDPOINT_SOCKET']
  assert wlapi.spiffe_socket_path == "/tmp/agent.sock"

# Pass socket path
def test_instantiate_socket_path():
  wlapi = DefaultWorkloadApiClient(spiffe_socket_path="/tmp/agent.sock")
  assert wlapi.spiffe_socket_path == "/tmp/agent.sock"

# TODO: Implement
def test_fetch_x509_svid():
  wlapi = get_client()
  wlapi.fetch_x509_svid()

# TODO: Implement
def test_fetch_jx509_bundles():
  wlapi = get_client()
  wlapi.fetch_x509_bundles()

# TODO: Implement
def test_fetch_jwt_svid():
  wlapi = get_client()
  audiences = ["foo", "bar"]
  wlapi.fetch_jwt_svid(audiences=audiences)

# TODO: Implement
def test_fetch_jwt_svid():
  wlapi = get_client()
  audiences = ["foo", "bar"]
  wlapi.fetch_jwt_svid(audiences=audiences, subject="spiffe://TODO")

# TODO: Implement
def test_fetch_jwt_bundles():
  wlapi = get_client()
  wlapi.fetch_jwt_bundles()

# TODO: Implement
def test_validate_jwt_svid():
  wlapi = get_client()
  token = "TODO"
  audiences = "foo"
  wlapi.validate_jwt_svid(token=token, audience=audiences)


## Utility functions

def get_client():
  return DefaultWorkloadApiClient(spiffe_socket_path="/tmp/agent.sock")
