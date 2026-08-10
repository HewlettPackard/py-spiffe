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

from dataclasses import dataclass
from typing import Set
import pytest
import datetime
from calendar import timegm
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from spiffe.svid.jwt_svid import JwtSvid
from spiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from spiffe.spiffe_id.spiffe_id import TrustDomain
from spiffe.errors import ArgumentError
from spiffe.svid.errors import (
    TokenExpiredError,
    JwtSvidError,
    InvalidTokenError,
    MissingClaimError,
)
from spiffe.bundle.jwt_bundle.errors import AuthorityNotFoundError
from testutils.jwt import (
    TEST_TRUST_DOMAIN,
    TEST_KEY,
    TEST_KEY_PEM,
    TEST_KEY_ID,
    TEST_ALG,
    generate_test_jwt_token,
    TEST_AUDIENCE,
    TEST_SPIFFE_ID,
    TEST_EXPIRY,
    extract_key_pair_pems,
)

JWT_BUNDLE = JwtBundle(TEST_TRUST_DOMAIN, {'kid1': TEST_KEY.public_key()})

rsa_private_key = rsa.generate_private_key(
    backend=default_backend(), public_exponent=65537, key_size=2048
).private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)

ec_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend()).private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)

"""
    parse_insecure tests
"""


def test_parse_insecure_invalid_input() -> None:
    with pytest.raises(ArgumentError) as exception:
        JwtSvid.parse_insecure('', set())

    assert str(exception.value) == 'token cannot be empty'


@dataclass(frozen=True)
class ParseInsecureClaimsCase:
    token: str
    audience: Set[str]
    expected_error: str


@pytest.mark.parametrize(
    'case',
    [
        ParseInsecureClaimsCase(
            jwt.encode(
                {
                    'sub': 'spiffeid://somewhere.over.the',
                    'exp': timegm(
                        (
                            datetime.datetime.now(datetime.timezone.utc)
                            + datetime.timedelta(hours=72)
                        ).utctimetuple()
                    ),
                },
                rsa_private_key,
                headers={'alg': 'RS256', 'typ': 'JOSE'},
            ),
            {'spire'},
            str(MissingClaimError('aud')),
        ),  # no aud
        ParseInsecureClaimsCase(
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
        ParseInsecureClaimsCase(
            jwt.encode(
                {
                    'aud': ['test-audience', 'other'],
                    'exp': timegm(
                        (
                            datetime.datetime.now(datetime.timezone.utc)
                            - datetime.timedelta(hours=1)
                        ).utctimetuple()
                    ),
                },
                rsa_private_key,
                headers={'alg': 'RS512', 'typ': 'JWT'},
            ),
            {'test-audience', 'other'},
            str(MissingClaimError('sub')),
        ),  # no sub
        ParseInsecureClaimsCase(
            jwt.encode(
                {
                    'aud': ['test-audience', 'other'],
                    'sub': 'spiffeid://somewhere.over.the',
                    'exp': timegm(
                        (
                            datetime.datetime.now(datetime.timezone.utc)
                            - datetime.timedelta(hours=1)
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
def test_parse_insecure_invalid_claims(case: ParseInsecureClaimsCase) -> None:
    with pytest.raises(JwtSvidError) as exception:
        JwtSvid.parse_insecure(case.token, case.audience)

    assert str(exception.value) == case.expected_error


@dataclass(frozen=True)
class ParseInsecureTokenCase:
    token: str
    audience: Set[str]


@pytest.mark.parametrize(
    'case',
    [
        ParseInsecureTokenCase(
            'eyJhbGciOiJFUzI1NiIsImtpZCI6Imd1eTdsOWZSQzhkQW1IUmFtaFpQbktRa3lId2FHQzR0IiwidHlwIjoiSldUIn0.eyJhdWQiOlsib3RoZXItc2VydmljZSJdLCJleHAiOjE2MTIyOTAxODMsImlhdCI6MTYxMjI4OTg4Mywic3ViIjoic3hthrtmZlOi8vZXhhbXBsZS5vcmcvc2VydmljZSJ9.W7CLQvYVBQ8Zg3ELcuB1K9hE4I9wyCMB_8PJTZXbjnlMBcgd0VDbSm5OjoqcGQF975eaVl_AdkryJ_lzxsEQ4A',
            {'spire'},
        ),  # middle
        ParseInsecureTokenCase(
            'errJhbGciOiJFUzI1NiIsImtpZCI6Imd1eTdsOWZSQzhkQW1IUmFtaFpQbktRa3lId2FHQzR0IiwidHlwIjoiSldUIn0.eyJhdWQiOlsib3RoZXItc2VydmljZSJdLCJleHAiOjE2MTIyOTAxODMsImlhdCI6MTYxMjI4OTg4Mywic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvc2VydmljZSJ9.W7CLQvYVBQ8Zg3ELcuB1K9hE4I9wyCMB_8PJTZXbjnlMBcgd0VDbSm5OjoqcGQF975eaVl_AdkryJ_lzxsEQ4A',
            {'spire'},
        ),  # first
    ],
)
def test_parse_insecure_invalid_token(case: ParseInsecureTokenCase) -> None:
    with pytest.raises(InvalidTokenError):
        JwtSvid.parse_insecure(case.token, case.audience)


@dataclass(frozen=True)
class ParseInsecureValidCase:
    token: str
    audience: Set[str]
    expected_spiffe_id: str


@pytest.mark.parametrize(
    'case',
    [
        ParseInsecureValidCase(
            jwt.encode(
                {
                    'aud': ['joe'],
                    'sub': 'spiffe://test.org',
                    'exp': timegm(
                        (
                            datetime.datetime.now(datetime.timezone.utc)
                            + datetime.timedelta(hours=100)
                        ).utctimetuple()
                    ),
                },
                rsa_private_key,
                headers={'alg': 'RS256', 'typ': 'JWT'},
            ),
            {'joe'},
            'spiffe://test.org',
        ),
        ParseInsecureValidCase(
            jwt.encode(
                {
                    'aud': ['joe', 'test', 'valid'],
                    'sub': 'spiffe://test.com.br',
                    'exp': timegm(
                        (
                            datetime.datetime.now(datetime.timezone.utc)
                            + datetime.timedelta(hours=1)
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
def test_parse_insecure_valid(case: ParseInsecureValidCase) -> None:
    result = JwtSvid.parse_insecure(case.token, case.audience)
    assert result._token == case.token
    assert str(result._spiffe_id) == case.expected_spiffe_id


"""
    parse_and_validate tests

"""


def test_parse_and_validate_invalid_parameters() -> None:
    with pytest.raises(ArgumentError) as err:
        JwtSvid.parse_and_validate('', JWT_BUNDLE, {'spire'})
    assert str(err.value) == 'token cannot be empty'


def test_parse_and_validate_invalid_missing_kid_header() -> None:
    token = generate_test_jwt_token(kid='')

    with pytest.raises(InvalidTokenError) as exception:
        JwtSvid.parse_and_validate(token, JWT_BUNDLE, {'test'})
    assert str(exception.value) == 'key_id cannot be empty'


def test_parse_and_validate_invalid_missing_sub() -> None:
    token = generate_test_jwt_token(spiffe_id='')

    with pytest.raises(InvalidTokenError) as exception:
        JwtSvid.parse_and_validate(token, JWT_BUNDLE, {'test'})

    assert "non-empty 'sub' claim" in str(exception.value)


def test_parse_and_validate_invalid_missing_kid() -> None:
    key_id = 'kid10'
    token = generate_test_jwt_token(kid=key_id)

    with pytest.raises(AuthorityNotFoundError) as exception:
        JwtSvid.parse_and_validate(token, JWT_BUNDLE, {'test'})
    assert str(exception.value) == 'Authority not found for key ID: kid10'


def test_parse_and_validate_invalid_kid_mismatch() -> None:
    rsa_key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwt_bundle = JwtBundle(
        TEST_TRUST_DOMAIN,
        {'kid1': TEST_KEY.public_key(), 'kid10': rsa_key2.public_key()},
    )
    token = generate_test_jwt_token(kid='kid10')

    with pytest.raises(InvalidTokenError) as exception:
        JwtSvid.parse_and_validate(token, jwt_bundle, {'test'})
    assert str(exception.value) == 'Signature verification failed'


def test_parse_and_validate_valid_token_RSA() -> None:
    token = generate_test_jwt_token()
    jwt_svid = JwtSvid.parse_and_validate(token, JWT_BUNDLE, {'test'})
    assert jwt_svid._audience == TEST_AUDIENCE
    assert str(jwt_svid._spiffe_id) == TEST_SPIFFE_ID
    assert jwt_svid._expiry == TEST_EXPIRY
    assert jwt_svid._token == token


def test_parse_and_validate_valid_token_EC() -> None:
    ec_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
    jwt_bundle = JwtBundle(TEST_TRUST_DOMAIN, {'kid_ec': ec_key.public_key()})

    ec_key_pem, _ = extract_key_pair_pems(ec_key)
    token = generate_test_jwt_token(ec_key_pem, 'kid_ec', alg='ES512')
    jwt_svid = JwtSvid.parse_and_validate(token, jwt_bundle, {'test'})
    assert jwt_svid._audience == TEST_AUDIENCE
    assert str(jwt_svid._spiffe_id) == TEST_SPIFFE_ID
    assert jwt_svid._expiry == TEST_EXPIRY
    assert jwt_svid._token == token


def test_parse_and_validate_valid_token_single_string_aud() -> None:
    """PyJWT returns aud as a plain string when only one audience is present.
    Verify the audience is parsed as {'single-audience'}, not split into characters.
    """
    token = jwt.encode(
        {
            'aud': 'single-audience',
            'sub': TEST_SPIFFE_ID,
            'exp': TEST_EXPIRY,
        },
        algorithm=TEST_ALG,
        key=TEST_KEY_PEM,
        headers={'alg': TEST_ALG, 'typ': 'JWT', 'kid': TEST_KEY_ID},
    )
    jwt_svid = JwtSvid.parse_and_validate(token, JWT_BUNDLE, {'single-audience'})
    assert jwt_svid._audience == {'single-audience'}
    assert str(jwt_svid._spiffe_id) == TEST_SPIFFE_ID
    assert jwt_svid._token == token


def test_parse_and_validate_valid_token_future_iat() -> None:
    """A token whose 'iat' claim is in the future must still validate.

    PyJWT verifies 'iat' by default and rejects such tokens with a
    "token is not yet valid (iat)" error, so JwtSvid disables 'iat'
    verification. This guards against a regression of that setting.
    """
    future_iat = timegm(
        (
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        ).utctimetuple()
    )
    token = jwt.encode(
        {
            'aud': list(TEST_AUDIENCE),
            'sub': TEST_SPIFFE_ID,
            'exp': TEST_EXPIRY,
            'iat': future_iat,
        },
        algorithm=TEST_ALG,
        key=TEST_KEY_PEM,
        headers={'alg': TEST_ALG, 'typ': 'JWT', 'kid': TEST_KEY_ID},
    )

    jwt_svid = JwtSvid.parse_and_validate(token, JWT_BUNDLE, {'test'})

    assert jwt_svid._audience == TEST_AUDIENCE
    assert str(jwt_svid._spiffe_id) == TEST_SPIFFE_ID
    assert jwt_svid._expiry == TEST_EXPIRY
    # linter thinks iat is a string, because it's the _claims dict is
    # of type [str, str].
    assert int(jwt_svid._claims['iat']) == future_iat
    assert jwt_svid._token == token


def test_parse_and_validate_valid_token_multiple_keys_bundle() -> None:
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


def _trust_domain_mismatch_message(subject_trust_domain: str, bundle_trust_domain: str) -> str:
    return (
        f"JWT-SVID subject trust domain '{subject_trust_domain}' does not match "
        f"the trust domain '{bundle_trust_domain}' of the supplied JwtBundle"
    )


def test_parse_and_validate_subject_trust_domain_matches_bundle() -> None:
    """A token whose 'sub' trust domain matches the bundle's trust domain must succeed."""
    token = generate_test_jwt_token(spiffe_id='spiffe://test.com/workload')
    jwt_svid = JwtSvid.parse_and_validate(token, JWT_BUNDLE, {'test'})
    assert str(jwt_svid._spiffe_id) == 'spiffe://test.com/workload'
    assert jwt_svid._spiffe_id.trust_domain == JWT_BUNDLE.trust_domain


def test_parse_and_validate_subject_trust_domain_matches_bundle_case_insensitive() -> None:
    """Trust domain comparison must use SPIFFE-normalized (lowercase) names."""
    token = generate_test_jwt_token(spiffe_id='spiffe://TEST.COM/workload')
    jwt_svid = JwtSvid.parse_and_validate(token, JWT_BUNDLE, {'test'})
    assert str(jwt_svid._spiffe_id) == 'spiffe://test.com/workload'
    assert jwt_svid._spiffe_id.trust_domain == JWT_BUNDLE.trust_domain


@pytest.mark.parametrize(
    'subject_spiffe_id',
    [
        'spiffe://other.org/workload',
        'spiffe://evil-test.com/workload',
        'spiffe://test.com.evil.org/workload',
    ],
)
def test_parse_and_validate_subject_trust_domain_mismatch(subject_spiffe_id: str) -> None:
    """A correctly signed token whose 'sub' claims a different trust domain than the
    supplied JwtBundle must be rejected, including lookalike / suffix-confusion domains.
    """
    token = generate_test_jwt_token(spiffe_id=subject_spiffe_id)
    subject_trust_domain = TrustDomain(subject_spiffe_id)
    expected = _trust_domain_mismatch_message(
        str(subject_trust_domain), str(TEST_TRUST_DOMAIN)
    )

    with pytest.raises(InvalidTokenError) as exception:
        JwtSvid.parse_and_validate(token, JWT_BUNDLE, {'test'})

    assert str(exception.value) == expected


def test_parse_and_validate_subject_trust_domain_mismatch_shared_key_across_bundles() -> None:
    """Reusing the same signing key and 'kid' across bundles for two different trust
    domains must not allow a token issued for one trust domain to validate against a
    JwtBundle for a different trust domain.
    """
    trust_domain_b = TrustDomain('other.org')
    shared_kid = 'shared-kid'
    jwt_bundle_a = JwtBundle(TEST_TRUST_DOMAIN, {shared_kid: TEST_KEY.public_key()})
    jwt_bundle_b = JwtBundle(trust_domain_b, {shared_kid: TEST_KEY.public_key()})

    token_for_b = generate_test_jwt_token(
        kid=shared_kid, spiffe_id='spiffe://other.org/workload'
    )
    expected = _trust_domain_mismatch_message('other.org', 'test.com')

    # Signature verifies fine against bundle_a (same key/kid reused), but the subject's
    # trust domain does not match bundle_a's trust domain, so it must be rejected.
    with pytest.raises(InvalidTokenError) as exception:
        JwtSvid.parse_and_validate(token_for_b, jwt_bundle_a, {'test'})
    assert str(exception.value) == expected

    # Validating against the correct bundle (matching trust domain) succeeds.
    jwt_svid = JwtSvid.parse_and_validate(token_for_b, jwt_bundle_b, {'test'})
    assert str(jwt_svid._spiffe_id) == 'spiffe://other.org/workload'
