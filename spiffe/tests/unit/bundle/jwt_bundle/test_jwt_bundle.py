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

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from jwt.exceptions import InvalidKeyError
from spiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from spiffe.bundle.jwt_bundle.errors import JwtBundleError, ParseJWTBundleError
from spiffe.errors import ArgumentError
from spiffe.spiffe_id.spiffe_id import TrustDomain
from testutils.jwt import (
    JWKS_1_EC_KEY,
    JWKS_2_EC_1_RSA_KEYS,
    JWKS_MISSING_X,
    JWKS_MISSING_KEY_ID,
)

# Default trust domain to run test cases.
trust_domain = TrustDomain("spiffe://any.domain")

# Default authorities to run test cases.
ec_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
authorities = {
    'kid1': ec_key,
    'kid2': rsa_key,
}


def test_create_jwt_bundle():
    jwt_bundle = JwtBundle(trust_domain, authorities)

    assert jwt_bundle.trust_domain == trust_domain
    assert len(jwt_bundle.jwt_authorities.keys()) == len(authorities.keys())


def test_create_jwt_bundle_no_trust_domain():
    with pytest.raises(JwtBundleError) as exc_info:
        JwtBundle(None, authorities)

    assert str(exc_info.value) == 'Trust domain cannot be empty'


def test_create_jwt_bundle_no_authorities():
    jwt_bundle = JwtBundle(trust_domain, None)

    assert jwt_bundle.trust_domain == trust_domain
    assert isinstance(jwt_bundle.jwt_authorities, dict)
    assert len(jwt_bundle.jwt_authorities.keys()) == 0


def test_get_jwt_authority_valid_input():
    jwt_bundle = JwtBundle(trust_domain, authorities)

    authority_key = jwt_bundle.get_jwt_authority('kid2')

    assert rsa_key == authority_key


def test_get_jwt_authority_invalid_key_id_not_found():
    jwt_bundle = JwtBundle(trust_domain, authorities)

    response = jwt_bundle.get_jwt_authority('p0')

    assert response is None


def test_get_jwt_authority_invalid_input():
    jwt_bundle = JwtBundle(trust_domain, authorities)

    with pytest.raises(ArgumentError) as exception:
        jwt_bundle.get_jwt_authority('')

    assert str(exception.value) == 'key_id cannot be empty'


def test_get_jwt_authority_empty_authority_dict():
    invalid_authorities = None
    jwt_bundle = JwtBundle(trust_domain, invalid_authorities)

    response = jwt_bundle.get_jwt_authority(key_id='p1')

    assert response is None


@pytest.mark.parametrize(
    'test_bytes, expected_authorities',
    [(JWKS_1_EC_KEY, 1), (JWKS_2_EC_1_RSA_KEYS, 3)],
)
def test_parse(test_bytes, expected_authorities):
    jwt_bundle = JwtBundle.parse(trust_domain, test_bytes)

    assert jwt_bundle
    assert len(jwt_bundle.jwt_authorities) == expected_authorities


@pytest.mark.parametrize(
    'test_trust_domain',
    ['', None],
)
def test_parse_invalid_trust_domain(test_trust_domain):
    with pytest.raises(ArgumentError) as exception:
        JwtBundle.parse(test_trust_domain, JWKS_1_EC_KEY)

    assert str(exception.value) == 'Trust domain cannot be empty'


@pytest.mark.parametrize(
    'test_bundle_bytes',
    [b'', None],
)
def test_parse_missing_bundle_bytes(test_bundle_bytes):
    with pytest.raises(ArgumentError) as exception:
        JwtBundle.parse(trust_domain, test_bundle_bytes)

    assert str(exception.value) == 'Bundle bytes cannot be empty'


@pytest.mark.parametrize(
    'test_bytes',
    [b'1211', b'invalid bytes'],
)
def test_parse_invalid_bytes(test_bytes):
    with pytest.raises(ParseJWTBundleError) as exception:
        JwtBundle.parse(trust_domain, test_bytes)

    assert (
        str(exception.value)
        == 'Error parsing JWT bundle: "bundle_bytes" does not represent a valid jwks'
    )


def test_parse_bundle_bytes_invalid_key(mocker):
    mocker.patch(
        'spiffe.bundle.jwt_bundle.jwt_bundle.PyJWKSet.from_json',
        side_effect=InvalidKeyError('Invalid Key'),
        autospec=True,
    )

    with pytest.raises(ParseJWTBundleError) as err:
        JwtBundle.parse(trust_domain, JWKS_MISSING_X)

    assert str(err.value) == 'Error parsing JWT bundle: Invalid Key'


def test_parse_corrupted_key_missing_key_id():
    with pytest.raises(ParseJWTBundleError) as exception:
        JwtBundle.parse(trust_domain, JWKS_MISSING_KEY_ID)

    assert (
        str(exception.value)
        == 'Error parsing JWT bundle: Error adding authority from JWKS: "keyID" cannot be empty'
    )


def test_parse_jwks_with_empty_keys_array():
    jwks_empty_keys_bytes = '{"keys": []}'.encode('utf-8')
    bundle = JwtBundle.parse(trust_domain, jwks_empty_keys_bytes)

    assert bundle
    assert len(bundle.jwt_authorities) == 0


def test_parse_jwks_with_null_keys_field():
    jwks_null_keys_bytes = '{"keys": null}'.encode('utf-8')
    bundle = JwtBundle.parse(trust_domain, jwks_null_keys_bytes)

    assert bundle
    assert len(bundle.jwt_authorities) == 0
