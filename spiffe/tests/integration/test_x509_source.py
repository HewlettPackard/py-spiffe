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

from spiffe import X509Source, SpiffeId

"""
Integration Tests for the X09Source.

These tests require a running SPIRE Server and Agent. Before running the tests,
ensure the SPIFFE_ENDPOINT_SOCKET environment variable is correctly set to point
to the SPIRE Agent's Workload API socket path.

These tests also require the presence of a valid registration entry for the calling workload.
"""


def test_x509_source():
    x509_source = None
    try:
        x509_source = X509Source(timeout_in_seconds=5)
        svid = x509_source.svid
        bundle = x509_source.get_bundle_for_trust_domain(svid.spiffe_id.trust_domain)

        assert svid
        assert isinstance(svid.spiffe_id, SpiffeId)
        assert bundle
        assert len(bundle.x509_authorities) > 0

    finally:
        if x509_source is not None:
            x509_source.close()
