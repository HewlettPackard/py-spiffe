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

from spiffe import SpiffeId, WorkloadApiClient

"""
Integration Tests for the Workload API client.

These tests require a running SPIRE Server and Agent. Before running the tests,
ensure the SPIFFE_ENDPOINT_SOCKET environment variable is correctly set to point
to the SPIRE Agent's Workload API socket path.

These tests also require the presence of a valid registration entry for the calling workload.
"""


def test_workload_api_client_x509() -> None:
    client = None
    try:
        client = WorkloadApiClient()

        svid = client.fetch_x509_svid()
        assert svid
        assert isinstance(svid.spiffe_id, SpiffeId)
        assert svid.leaf is not None
        assert svid.cert_chain is not None

        svids = client.fetch_x509_svids()
        assert len(svids) > 0

        bundle_set = client.fetch_x509_bundles()
        bundle = bundle_set.get_bundle_for_trust_domain(svid.spiffe_id.trust_domain)
        assert bundle is not None
        assert len(bundle.x509_authorities) > 0

        x509_context = client.fetch_x509_context()
        svid = x509_context.default_svid
        assert svid is not None
        bundle = x509_context.x509_bundle_set.get_bundle_for_trust_domain(
            svid.spiffe_id.trust_domain
        )
        assert bundle is not None
        assert len(bundle.x509_authorities) > 0

    finally:
        if client is not None:
            client.close()


def test_workload_api_client_jwt() -> None:
    client = None
    try:
        client = WorkloadApiClient()

        svid = client.fetch_jwt_svid(audience={"aud1", "aud2"})
        assert svid
        assert isinstance(svid.spiffe_id, SpiffeId)
        assert "aud1" in svid.audience
        assert "aud2" in svid.audience
        assert svid.token != ""
        assert svid.expiry != 0

        svids = client.fetch_jwt_svids(audience={"other"})
        assert len(svids) > 0
        svid = svids[0]
        assert "other" in svid.audience

        bundle_set = client.fetch_jwt_bundles()
        bundles = bundle_set.bundles
        assert len(bundles) > 0
        bundle = bundle_set.get_bundle_for_trust_domain(svid.spiffe_id.trust_domain)
        assert bundle is not None
        assert len(bundle.jwt_authorities) > 0

    finally:
        if client is not None:
            client.close()
