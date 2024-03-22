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

from typing import Set

import pytest
import datetime
from calendar import timegm
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from pyspiffe.svid import INVALID_INPUT_ERROR
from pyspiffe.svid.jwt_svid import JwtSvid
from pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from pyspiffe.exceptions import ArgumentError
from pyspiffe.svid.exceptions import (
    TokenExpiredError,
    JwtSvidError,
    InvalidTokenError,
    MissingClaimError,
)
from pyspiffe.bundle.jwt_bundle.exceptions import AuthorityNotFoundError
from test.utils.jwt_utils import (
    extract_key_pair_pems,
    generate_test_jwt_token,
    TEST_SPIFFE_ID,
    TEST_AUDIENCE,
    TEST_KEY,
    TEST_TRUST_DOMAIN,
    TEST_EXPIRY,
)

JWT_BUNDLE = JwtBundle(TEST_TRUST_DOMAIN, {'kid1': TEST_KEY.public_key()})

rsa_private_key = rsa.generate_private_key(
    backend=default_backend(), public_exponent=65537, key_size=2048
).private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)

ec_private_key = ec.generate_private_key(
    ec.SECP256R1(), default_backend()
).private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)

"""
    parse_insecure tests
"""


@pytest.mark.parametrize(
    'test_input_token,test_input_audience, expected',
    [
        ('', {}, INVALID_INPUT_ERROR.format('token cannot be empty.')),
        ('', None, INVALID_INPUT_ERROR.format('token cannot be empty.')),
        (None, {}, INVALID_INPUT_ERROR.format('token cannot be empty.')),
        (None, None, INVALID_INPUT_ERROR.format('token cannot be empty.')),
    ],
)
def test_parse_insecure_invalid_input(
    test_input_token, test_input_audience: Set[str], expected
):
    with pytest.raises(ArgumentError) as exception:
        JwtSvid.parse_insecure(test_input_token, test_input_audience)

    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_token,test_input_audience, expected',
    [
        (
            jwt.encode(
                {
                    'sub': 'spiffeid://somewhere.over.the',
                    'exp': timegm(
                        (
                            datetime.datetime.utcnow() + datetime.timedelta(hours=72)
                        ).utctimetuple()
                    ),
                },
                rsa_private_key,
                headers={'alg': 'RS256', 'typ': 'JOSE'},
            ),
            {'spire'},
            str(MissingClaimError('aud')),
        ),  # no aud
        (
            jwt.encode(
                {
                    'aud': ['test-audience', 'other'],
                    'sub': 'spiffeid://somewhere.over.the',
                },
                ec_private_key,
                headers={'alg': 'ES384', 'typ': 'JWT'},
            ),
            {"test-audience", "other"},
            str(MissingClaimError('exp')),
        ),  # no exp
        (
            jwt.encode(
                {
                    'aud': ['test-audience', 'other'],
                    'exp': timegm(
                        (
                            datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                        ).utctimetuple()
                    ),
                },
                rsa_private_key,
                headers={'alg': 'RS512', 'typ': 'JWT'},
            ),
            {'test-audience', 'other'},
            str(MissingClaimError('sub')),
        ),  # no sub
        (
            jwt.encode(
                {
                    'aud': ['test-audience', 'other'],
                    'sub': 'spiffeid://somewhere.over.the',
                    'exp': timegm(
                        (
                            datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                        ).utctimetuple()
                    ),
                },
                rsa_private_key,
                headers={'alg': 'PS512', 'typ': 'JOSE'},
            ),
            {'test-audience', 'other'},
            str(TokenExpiredError()),
        ),  # expired token
    ],
)
def test_parse_insecure_invalid_claims(test_input_token, test_input_audience, expected):
    with pytest.raises(JwtSvidError) as exception:
        JwtSvid.parse_insecure(test_input_token, test_input_audience)

    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_token,test_input_audience',
    [
        (
            'eyJhbGciOiJFUzI1NiIsImtpZCI6Imd1eTdsOWZSQzhkQW1IUmFtaFpQbktRa3lId2FHQzR0IiwidHlwIjoiSldUIn0.eyJhdWQiOlsib3RoZXItc2VydmljZSJdLCJleHAiOjE2MTIyOTAxODMsImlhdCI6MTYxMjI4OTg4Mywic3ViIjoic3hthrtmZlOi8vZXhhbXBsZS5vcmcvc2VydmljZSJ9.W7CLQvYVBQ8Zg3ELcuB1K9hE4I9wyCMB_8PJTZXbjnlMBcgd0VDbSm5OjoqcGQF975eaVl_AdkryJ_lzxsEQ4A',
            {'spire'},
        ),  # middle
        (
            'errJhbGciOiJFUzI1NiIsImtpZCI6Imd1eTdsOWZSQzhkQW1IUmFtaFpQbktRa3lId2FHQzR0IiwidHlwIjoiSldUIn0.eyJhdWQiOlsib3RoZXItc2VydmljZSJdLCJleHAiOjE2MTIyOTAxODMsImlhdCI6MTYxMjI4OTg4Mywic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvc2VydmljZSJ9.W7CLQvYVBQ8Zg3ELcuB1K9hE4I9wyCMB_8PJTZXbjnlMBcgd0VDbSm5OjoqcGQF975eaVl_AdkryJ_lzxsEQ4A',
            {'spire'},
        ),  # first
    ],
)
def test_parse_insecure_invalid_token(test_input_token, test_input_audience):
    with pytest.raises(InvalidTokenError):
        JwtSvid.parse_insecure(test_input_token, test_input_audience)


@pytest.mark.parametrize(
    'test_input_token,test_input_audience, expected',
    [
        (
            jwt.encode(
                {
                    'aud': ['joe'],
                    'sub': 'spiffe://test.org',
                    'exp': timegm(
                        (
                            datetime.datetime.utcnow() + datetime.timedelta(hours=100)
                        ).utctimetuple()
                    ),
                },
                rsa_private_key,
                headers={'alg': 'RS256', 'typ': 'JWT'},
            ),
            {'joe'},
            'spiffe://test.org',
        ),
        (
            jwt.encode(
                {
                    'aud': ['joe', 'test', 'valid'],
                    'sub': 'spiffe://test.com.br',
                    'exp': timegm(
                        (
                            datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                        ).utctimetuple()
                    ),
                },
                rsa_private_key,
                headers={'alg': 'PS384', 'typ': 'JOSE'},
            ),
            {'joe', 'test', 'valid'},
            "spiffe://test.com.br",
        ),
    ],
)
def test_parse_insecure_valid(test_input_token, test_input_audience, expected):
    result = JwtSvid.parse_insecure(test_input_token, test_input_audience)
    assert result._token == test_input_token
    assert str(result._spiffe_id) == expected


"""
    parse_and_validate tests

"""


@pytest.mark.parametrize(
    'test_input_token,test_input_jwt_bundle, test_input_audience, expected',
    [
        (
            '',
            None,
            {'spire'},
            INVALID_INPUT_ERROR.format('token cannot be empty.'),
        ),
        (
            'eyJhbGciOiJFUzI1NiIsImtpZCI6Imd1eTdsOWZSQzhkQW1IUmFtaFpQbktRa3lId2FHQzR0IiwidHlwIjoiSldUIn0.eyJhdWQiOlsib3RoZXItc2VydmljZSJdLCJleHAiOjE2MTIyOTAxODMsImlhdCI6MTYxMjI4OTg4Mywic3ViIjoic3hthrtmZlOi8vZXhhbXBsZS5vcmcvc2VydmljZSJ9.W7CLQvYVBQ8Zg3ELcuB1K9hE4I9wyCMB_8PJTZXbjnlMBcgd0VDbSm5OjoqcGQF975eaVl_AdkryJ_lzxsEQ4A',
            None,
            {'spire'},
            INVALID_INPUT_ERROR.format('jwt_bundle cannot be empty.'),
        ),
    ],
)
def test_parse_and_validate_invalid_parameters(
    test_input_token, test_input_jwt_bundle, test_input_audience, expected
):
    with pytest.raises(ArgumentError) as exception:
        JwtSvid.parse_and_validate(
            test_input_token, test_input_jwt_bundle, test_input_audience
        )
    assert str(exception.value) == expected


def test_parse_and_validate_invalid_missing_kid_header():
    token = generate_test_jwt_token(kid='')

    with pytest.raises(InvalidTokenError) as exception:
        JwtSvid.parse_and_validate(token, JWT_BUNDLE, {'test'})
    assert str(exception.value) == 'key_id cannot be empty.'


def test_parse_and_validate_invalid_missing_sub():
    token = generate_test_jwt_token(spiffe_id='')

    with pytest.raises(InvalidTokenError) as exception:
        JwtSvid.parse_and_validate(token, JWT_BUNDLE, {'test'})
    assert str(exception.value) == 'SPIFFE ID cannot be empty.'


def test_parse_and_validate_invalid_missing_kid():
    key_id = 'kid10'
    token = generate_test_jwt_token(kid=key_id)

    with pytest.raises(AuthorityNotFoundError) as exception:
        JwtSvid.parse_and_validate(token, JWT_BUNDLE, {'test'})
    assert str(exception.value) == 'Key (' + key_id + ') not found in authorities.'


def test_parse_and_validate_invalid_kid_mismatch():
    rsa_key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwt_bundle = JwtBundle(
        TEST_TRUST_DOMAIN,
        {'kid1': TEST_KEY.public_key(), 'kid10': rsa_key2.public_key()},
    )
    token = generate_test_jwt_token(kid='kid10')

    with pytest.raises(InvalidTokenError) as exception:
        JwtSvid.parse_and_validate(token, jwt_bundle, {'test'})
    assert str(exception.value) == 'Signature verification failed.'


def test_parse_and_validate_valid_token_RSA():
    token = generate_test_jwt_token()
    jwt_svid = JwtSvid.parse_and_validate(token, JWT_BUNDLE, {'test'})
    assert jwt_svid._audience == TEST_AUDIENCE
    assert str(jwt_svid._spiffe_id) == TEST_SPIFFE_ID
    assert jwt_svid._expiry == TEST_EXPIRY
    assert jwt_svid._token == token


def test_parse_and_validate_valid_token_EC():
    ec_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    jwt_bundle = JwtBundle(TEST_TRUST_DOMAIN, {'kid_ec': ec_key.public_key()})

    ec_key_pem, _ = extract_key_pair_pems(ec_key)
    token = generate_test_jwt_token(ec_key_pem, 'kid_ec', alg='ES512')
    jwt_svid = JwtSvid.parse_and_validate(token, jwt_bundle, {'test'})
    assert jwt_svid._audience == TEST_AUDIENCE
    assert str(jwt_svid._spiffe_id) == TEST_SPIFFE_ID
    assert jwt_svid._expiry == TEST_EXPIRY
    assert jwt_svid._token == token


def test_parse_and_validate_valid_token_multiple_keys_bundle():
    ec_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
    jwt_bundle = JwtBundle(
        TEST_TRUST_DOMAIN,
        {'kid_rsa': TEST_KEY.public_key(), 'kid_ec': ec_key.public_key()},
    )
    ec_key_pem, _ = extract_key_pair_pems(ec_key)

    token = generate_test_jwt_token(ec_key_pem, kid='kid_ec', alg='ES512')
    jwt_svid1 = JwtSvid.parse_and_validate(token, jwt_bundle, {'test'})
    assert jwt_svid1._audience == TEST_AUDIENCE
    assert str(jwt_svid1._spiffe_id) == TEST_SPIFFE_ID
    assert jwt_svid1._expiry == TEST_EXPIRY
    assert jwt_svid1._token == token

    token2 = generate_test_jwt_token(kid='kid_rsa')
    jwt_svid2 = JwtSvid.parse_and_validate(token2, jwt_bundle, {'test'})
    assert jwt_svid2._audience == TEST_AUDIENCE
    assert str(jwt_svid2._spiffe_id) == TEST_SPIFFE_ID
    assert jwt_svid2._expiry == TEST_EXPIRY
    assert jwt_svid2._token == token2
