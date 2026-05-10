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

import json

import pytest
from typing import Dict
from pytest_mock import MockerFixture
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from jwt.exceptions import InvalidKeyError
from spiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle, _PUBLIC_KEY_TYPES
from spiffe.bundle.jwt_bundle.errors import ParseJWTBundleError
from spiffe.errors import ArgumentError
from spiffe.spiffe_id.spiffe_id import TrustDomain, TrustDomainError
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
authorities: Dict[str, _PUBLIC_KEY_TYPES] = {
    'kid1': ec_key.public_key(),
    'kid2': rsa_key.public_key(),
}


def _jwks_bytes(keys: list[dict[str, object]]) -> bytes:
    return json.dumps({'keys': keys}).encode('utf-8')


EC_JWT_SVID_KEY: dict[str, object] = {
    "kty": "EC",
    "use": "jwt-svid",
    "kid": "C6vs25welZOx6WksNYfbMfiw9l96pMnD",
    "crv": "P-256",
    "x": "ngLYQnlfF6GsojUwqtcEE3WgTNG2RUlsGhK73RNEl5k",
    "y": "tKbiDSUSsQ3F1P7wteeHNXIcU-cx6CgSbroeQrQHTLM",
}

EC_X509_SVID_KEY: dict[str, object] = {
    **EC_JWT_SVID_KEY,
    "use": "x509-svid",
    "kid": "x509-key",
}

EC_MISSING_USE_KEY: dict[str, object] = {
    key: value for key, value in EC_JWT_SVID_KEY.items() if key != "use"
}


def test_create_jwt_bundle() -> None:
    jwt_bundle = JwtBundle(trust_domain, authorities)

    assert jwt_bundle.trust_domain == trust_domain
    assert len(jwt_bundle.jwt_authorities.keys()) == len(authorities.keys())


def test_create_jwt_bundle_no_authorities() -> None:
    jwt_bundle = JwtBundle(trust_domain, {})

    assert jwt_bundle.trust_domain == trust_domain
    assert isinstance(jwt_bundle.jwt_authorities, dict)
    assert len(jwt_bundle.jwt_authorities.keys()) == 0


def test_get_jwt_authority_valid_input() -> None:
    jwt_bundle = JwtBundle(trust_domain, authorities)

    authority_key = jwt_bundle.get_jwt_authority('kid2')

    assert rsa_key.public_key() == authority_key


def test_get_jwt_authority_invalid_key_id_not_found() -> None:
    jwt_bundle = JwtBundle(trust_domain, authorities)

    response = jwt_bundle.get_jwt_authority('p0')

    assert response is None


def test_get_jwt_authority_invalid_input() -> None:
    jwt_bundle = JwtBundle(trust_domain, authorities)

    with pytest.raises(ArgumentError) as exception:
        jwt_bundle.get_jwt_authority('')

    assert str(exception.value) == 'key_id cannot be empty'


def test_get_jwt_authority_empty_authority_dict() -> None:
    invalid_authorities: Dict[str, _PUBLIC_KEY_TYPES] = {}
    jwt_bundle = JwtBundle(trust_domain, invalid_authorities)

    response = jwt_bundle.get_jwt_authority(key_id='p1')

    assert response is None


@pytest.mark.parametrize(
    'test_bytes, expected_authorities',
    [(JWKS_1_EC_KEY, 1), (JWKS_2_EC_1_RSA_KEYS, 3)],
)
def test_parse(test_bytes: bytes, expected_authorities: int) -> None:
    jwt_bundle = JwtBundle.parse(trust_domain, test_bytes)

    assert jwt_bundle
    assert len(jwt_bundle.jwt_authorities) == expected_authorities


def test_parse_mixed_jwt_svid_and_x509_svid_keys_only_loads_jwt_svid() -> None:
    jwt_bundle = JwtBundle.parse(
        trust_domain,
        _jwks_bytes([EC_X509_SVID_KEY, EC_JWT_SVID_KEY]),
    )

    assert len(jwt_bundle.jwt_authorities) == 1
    assert jwt_bundle.get_jwt_authority(str(EC_JWT_SVID_KEY["kid"])) is not None
    assert jwt_bundle.get_jwt_authority(str(EC_X509_SVID_KEY["kid"])) is None


def test_parse_no_jwt_svid_keys_produces_empty_bundle() -> None:
    jwt_bundle = JwtBundle.parse(
        trust_domain,
        _jwks_bytes([EC_X509_SVID_KEY, EC_MISSING_USE_KEY]),
    )

    # SPIFFE bundle clients MUST ignore keys with missing or non-jwt-svid use.
    assert jwt_bundle
    assert len(jwt_bundle.jwt_authorities) == 0


def test_parse_accepted_jwt_svid_key_without_kid_raises() -> None:
    key_without_kid = {key: value for key, value in EC_JWT_SVID_KEY.items() if key != "kid"}

    with pytest.raises(ParseJWTBundleError) as exception:
        JwtBundle.parse(trust_domain, _jwks_bytes([key_without_kid]))

    assert (
        str(exception.value)
        == 'Error parsing JWT bundle: Error adding authority from JWKS: "keyID" cannot be empty'
    )


def test_parse_malformed_jwt_svid_key_raises_parse_error() -> None:
    malformed_jwt_svid_key = {
        key: value for key, value in EC_JWT_SVID_KEY.items() if key != "x"
    }

    with pytest.raises(ParseJWTBundleError) as exception:
        JwtBundle.parse(trust_domain, _jwks_bytes([malformed_jwt_svid_key]))

    assert str(exception.value).startswith('Error parsing JWT bundle: ')


def test_parse_malformed_non_jwt_svid_key_is_ignored() -> None:
    malformed_x509_svid_key = {
        key: value for key, value in EC_X509_SVID_KEY.items() if key != "x"
    }

    jwt_bundle = JwtBundle.parse(trust_domain, _jwks_bytes([malformed_x509_svid_key]))

    assert len(jwt_bundle.jwt_authorities) == 0


def test_parse_invalid_trust_domain() -> None:
    with pytest.raises(TrustDomainError) as exception:
        TrustDomain('')

    assert str(exception.value) == 'Invalid trust domain: cannot be empty'


def test_parse_missing_bundle_bytes() -> None:
    with pytest.raises(ArgumentError) as exception:
        JwtBundle.parse(trust_domain, b'')

    assert str(exception.value) == 'Bundle bytes cannot be empty'


@pytest.mark.parametrize(
    'test_bytes',
    [b'1211', b'invalid bytes'],
)
def test_parse_invalid_bytes(test_bytes: bytes) -> None:
    with pytest.raises(ParseJWTBundleError) as exception:
        JwtBundle.parse(trust_domain, test_bytes)

    assert (
        str(exception.value)
        == 'Error parsing JWT bundle: "bundle_bytes" does not represent a valid jwks'
    )


def test_parse_bundle_bytes_invalid_key(mocker: MockerFixture) -> None:
    mocker.patch(
        'spiffe.bundle.jwt_bundle.jwt_bundle.PyJWKSet.from_json',
        side_effect=InvalidKeyError('Invalid Key'),
        autospec=True,
    )

    with pytest.raises(ParseJWTBundleError) as err:
        JwtBundle.parse(trust_domain, JWKS_MISSING_X)

    assert str(err.value) == 'Error parsing JWT bundle: Invalid Key'


def test_parse_corrupted_key_missing_key_id() -> None:
    with pytest.raises(ParseJWTBundleError) as exception:
        JwtBundle.parse(trust_domain, JWKS_MISSING_KEY_ID)

    assert (
        str(exception.value)
        == 'Error parsing JWT bundle: Error adding authority from JWKS: "keyID" cannot be empty'
    )


def test_parse_jwks_with_empty_keys_array() -> None:
    jwks_empty_keys_bytes = '{"keys": []}'.encode('utf-8')
    bundle = JwtBundle.parse(trust_domain, jwks_empty_keys_bytes)

    assert bundle
    assert len(bundle.jwt_authorities) == 0


def test_parse_jwks_with_null_keys_field() -> None:
    jwks_null_keys_bytes = '{"keys": null}'.encode('utf-8')
    bundle = JwtBundle.parse(trust_domain, jwks_null_keys_bytes)

    assert bundle
    assert len(bundle.jwt_authorities) == 0


@pytest.mark.parametrize(
    'invalid_keys_json',
    ['{"keys": false}', '{"keys": ""}', '{"keys": 0}'],
)
def test_parse_jwks_with_invalid_keys_type_raises(invalid_keys_json: str) -> None:
    with pytest.raises(ParseJWTBundleError) as exception:
        JwtBundle.parse(trust_domain, invalid_keys_json.encode('utf-8'))

    assert (
        str(exception.value)
        == 'Error parsing JWT bundle: "bundle_bytes" does not represent a valid jwks'
    )
