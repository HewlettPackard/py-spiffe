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

from unittest.mock import PropertyMock, MagicMock, patch

import pytest
from OpenSSL import SSL
from cryptography.hazmat.primitives import serialization

from spiffe import X509Source, X509Svid, TrustDomain, X509Bundle, X509BundleSet
from spiffetls import create_ssl_context
from testutils.certs import TEST_BUNDLE_CERTS_DIR
from testutils.certs import TEST_CERTS_DIR


@pytest.fixture
def source_mocks():
    der_type = serialization.Encoding.DER
    chain_path = TEST_CERTS_DIR / '1-chain.der'
    key_path = TEST_CERTS_DIR / '1-key.der'
    x509_svid = X509Svid.load(str(chain_path), str(key_path), der_type)

    bundle_1 = X509Bundle.load(
        TrustDomain('domain.test'), TEST_BUNDLE_CERTS_DIR / 'certs.der', der_type
    )
    bundle_2 = X509Bundle.load(
        TrustDomain('example.org'),
        TEST_BUNDLE_CERTS_DIR / 'federated_bundle.der',
        der_type,
    )
    x509_bundle_set = X509BundleSet.of([bundle_1, bundle_2])

    x509_source_mock = MagicMock(spec=X509Source)
    mock_svid = PropertyMock(return_value=x509_svid)
    mock_bundles = PropertyMock(return_value=x509_bundle_set.bundles)

    type(x509_source_mock).svid = mock_svid
    type(x509_source_mock).bundles = mock_bundles

    return x509_source_mock, mock_svid, mock_bundles


@pytest.mark.parametrize(
    "method,use_system_trust_store",
    [
        (SSL.TLS_SERVER_METHOD, False),
        (SSL.TLS_CLIENT_METHOD, False),
        (SSL.TLS_CLIENT_METHOD, True),
    ],
)
def test_create_ssl_context(method, use_system_trust_store, source_mocks):
    authorize_fn = MagicMock()
    x509_source, mock_svid, mock_bundle = source_mocks
    with patch('OpenSSL.SSL.Context') as MockContext:
        ssl_context_instance = MockContext.return_value

        create_ssl_context(
            method,
            x509_source,
            authorize_fn,
            use_system_trusted_cas=use_system_trust_store,
        )

        MockContext.assert_called_once_with(method)
        ssl_context_instance.use_certificate.assert_called_once()
        ssl_context_instance.use_privatekey.assert_called_once()
        ssl_context_instance.check_privatekey.assert_called_once()

        if use_system_trust_store:
            ssl_context_instance.set_default_verify_paths.assert_called_once()
        else:
            ssl_context_instance.set_default_verify_paths.assert_not_called()

        assert mock_svid.call_count > 0, "Expected x509_source.svid to be accessed"
        assert mock_bundle.call_count > 0, "Expected x509_source.bundles to be accessed"
