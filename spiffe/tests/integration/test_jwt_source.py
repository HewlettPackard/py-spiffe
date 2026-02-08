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

import spiffe
from spiffe import SpiffeId

"""
Integration Tests for the JwtSource.

These tests require a running SPIRE Server and Agent. Before running the tests,
ensure the SPIFFE_ENDPOINT_SOCKET environment variable is correctly set to point
to the SPIRE Agent's Workload API socket path.

These tests also require the presence of a valid registration entry for the calling workload.
"""


def test_jwt_source() -> None:
    jwt_source = None
    try:
        jwt_source = spiffe.JwtSource(timeout_in_seconds=30)
        svid = jwt_source.fetch_svid({"aud1", "aud2"})

        assert svid
        assert isinstance(svid.spiffe_id, SpiffeId)
        assert "aud1" in svid.audience
        assert "aud2" in svid.audience
        assert svid.token != ""
        assert svid.expiry != 0

        svid = jwt_source.fetch_svid({"other"})
        assert "other" in svid.audience

        bundle = jwt_source.get_bundle_for_trust_domain(svid.spiffe_id.trust_domain)
        assert bundle
        assert len(bundle.jwt_authorities) > 0

    finally:
        if jwt_source is not None:
            jwt_source.close()
