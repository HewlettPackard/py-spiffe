import pytest
import datetime
from calendar import timegm
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from pyspiffe.svid import INVALID_INPUT_ERROR
from pyspiffe.svid.jwt_svid import JwtSvid
from pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from pyspiffe.spiffe_id.trust_domain import TrustDomain
from pyspiffe.svid.exceptions import (
    TokenExpiredError,
    JwtSvidError,
    InvalidTokenError,
    MissingClaimError,
)
from pyspiffe.bundle.jwt_bundle.exceptions import AuthorityNotFoundError
from test.svid.test_utils import get_keys_pems, create_jwt

# parse and validate tests initializers
AUDIENCE = ['spire', 'test', 'valid']
SPIFFE_ID = 'spiffe://test.orgcom/'
RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_KEY_PEM, _ = get_keys_pems(RSA_KEY)
JWT_BUNDLE = JwtBundle(TrustDomain('test.orgcom'), {'kid1': RSA_KEY.public_key()})
EXPIRY = timegm(
    (datetime.datetime.utcnow() + datetime.timedelta(hours=4)).utctimetuple()
)


"""
    parse_insecure tests
"""


@pytest.mark.parametrize(
    'test_input_token,test_input_audience, expected',
    [
        ('', [], INVALID_INPUT_ERROR.format('token cannot be empty')),
        ('', None, INVALID_INPUT_ERROR.format('token cannot be empty')),
        (None, [], INVALID_INPUT_ERROR.format('token cannot be empty')),
        (None, None, INVALID_INPUT_ERROR.format('token cannot be empty')),
    ],
)
def test_parse_insecure_invalid_input(test_input_token, test_input_audience, expected):
    with pytest.raises(ValueError) as exception:
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
                'secret',
                headers={'alg': 'RS256', 'typ': 'JOSE'},
            ),
            ["spire"],
            str(MissingClaimError('aud')),
        ),  # no aud
        (
            jwt.encode(
                {
                    'aud': ['spire'],
                    'sub': 'spiffeid://somewhere.over.the',
                },
                'secret',
                headers={'alg': 'ES384', 'typ': 'JWT'},
            ),
            ["spire"],
            str(MissingClaimError('exp')),
        ),  # no exp
        (
            jwt.encode(
                {
                    'aud': ['spire'],
                    'exp': timegm(
                        (
                            datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                        ).utctimetuple()
                    ),
                },
                'secret',
                headers={'alg': 'RS512', 'typ': 'JWT'},
            ),
            ["spire"],
            str(MissingClaimError('sub')),
        ),  # no sub
        (
            jwt.encode(
                {
                    'aud': ['spire'],
                    'sub': 'spiffeid://somewhere.over.the',
                    'exp': timegm(
                        (
                            datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                        ).utctimetuple()
                    ),
                },
                'secret',
                headers={'alg': 'PS512', 'typ': 'JOSE'},
            ),
            ["spire"],
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
            ["spire"],
        ),  # middle
        (
            'errJhbGciOiJFUzI1NiIsImtpZCI6Imd1eTdsOWZSQzhkQW1IUmFtaFpQbktRa3lId2FHQzR0IiwidHlwIjoiSldUIn0.eyJhdWQiOlsib3RoZXItc2VydmljZSJdLCJleHAiOjE2MTIyOTAxODMsImlhdCI6MTYxMjI4OTg4Mywic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvc2VydmljZSJ9.W7CLQvYVBQ8Zg3ELcuB1K9hE4I9wyCMB_8PJTZXbjnlMBcgd0VDbSm5OjoqcGQF975eaVl_AdkryJ_lzxsEQ4A',
            ["spire"],
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
                    'aud': ['spire'],
                    'sub': 'spiffe://test.org/',
                    'exp': timegm(
                        (
                            datetime.datetime.utcnow() + datetime.timedelta(hours=100)
                        ).utctimetuple()
                    ),
                },
                'secret',
                headers={'alg': 'RS256', 'typ': 'JWT'},
            ),
            ['spire'],
            'spiffe://test.org/',
        ),
        (
            jwt.encode(
                {
                    'aud': ['spire', 'test', 'valid'],
                    'sub': 'spiffe://test.orgcom.br/',
                    'exp': timegm(
                        (
                            datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                        ).utctimetuple()
                    ),
                },
                'secret key',
                headers={'alg': 'PS384', 'typ': 'JOSE'},
            ),
            ['spire', 'test'],
            "spiffe://test.orgcom.br/",
        ),
    ],
)
def test_parse_insecure_valid(test_input_token, test_input_audience, expected):
    result = JwtSvid.parse_insecure(test_input_token, test_input_audience)
    assert result.token == test_input_token
    assert str(result.spiffe_id) == expected


"""
    parse_and_validate tests

"""


@pytest.mark.parametrize(
    'test_input_token,test_input_jwt_bundle, test_input_audience, expected',
    [
        (
            '',
            None,
            ['spire'],
            INVALID_INPUT_ERROR.format('token cannot be empty'),
        ),
        (
            'eyJhbGciOiJFUzI1NiIsImtpZCI6Imd1eTdsOWZSQzhkQW1IUmFtaFpQbktRa3lId2FHQzR0IiwidHlwIjoiSldUIn0.eyJhdWQiOlsib3RoZXItc2VydmljZSJdLCJleHAiOjE2MTIyOTAxODMsImlhdCI6MTYxMjI4OTg4Mywic3ViIjoic3hthrtmZlOi8vZXhhbXBsZS5vcmcvc2VydmljZSJ9.W7CLQvYVBQ8Zg3ELcuB1K9hE4I9wyCMB_8PJTZXbjnlMBcgd0VDbSm5OjoqcGQF975eaVl_AdkryJ_lzxsEQ4A',
            None,
            ['spire'],
            INVALID_INPUT_ERROR.format('jwt_bundle cannot be empty'),
        ),
    ],
)
def test_parse_and_validate_invalid_parameters(
    test_input_token, test_input_jwt_bundle, test_input_audience, expected
):
    with pytest.raises(ValueError) as exception:
        JwtSvid.parse_and_validate(
            test_input_token, test_input_jwt_bundle, test_input_audience
        )
    assert str(exception.value) == expected


def test_parse_and_validate_invalid_missing_kid_header():
    token = create_jwt(RSA_KEY_PEM, '', 'RS256', AUDIENCE, SPIFFE_ID, EXPIRY)

    with pytest.raises(InvalidTokenError) as exception:
        JwtSvid.parse_and_validate(token, JWT_BUNDLE, ['spire'])
    assert str(exception.value) == 'key_id cannot be empty.'


def test_parse_and_validate_invalid_missing_sub():
    token = create_jwt(RSA_KEY_PEM, 'kid1', 'RS256', AUDIENCE, '', EXPIRY)

    with pytest.raises(InvalidTokenError) as exception:
        JwtSvid.parse_and_validate(token, JWT_BUNDLE, 'spire')
    assert str(exception.value) == 'SPIFFE ID cannot be empty.'


def test_parse_and_validate_invalid_missing_kid():
    key_id = 'kid10'
    token = create_jwt(RSA_KEY_PEM, key_id, 'RS256', AUDIENCE, SPIFFE_ID, EXPIRY)

    with pytest.raises(AuthorityNotFoundError) as exception:
        JwtSvid.parse_and_validate(token, JWT_BUNDLE, ['spire'])
    assert str(exception.value) == 'Key (' + key_id + ') not found in authorities.'


def test_parse_and_validate_invalid_kid_mismatch():
    rsa_key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwt_bundle = JwtBundle(
        TrustDomain('test.orgcom'),
        {'kid1': RSA_KEY.public_key(), 'kid10': rsa_key2.public_key()},
    )
    token = create_jwt(RSA_KEY_PEM, 'kid10', 'RS256', AUDIENCE, SPIFFE_ID, EXPIRY)

    with pytest.raises(InvalidTokenError) as exception:
        JwtSvid.parse_and_validate(token, jwt_bundle, ['spire'])
    assert str(exception.value) == 'Signature verification failed'


def test_parse_and_validate_valid_token_RSA():
    token = create_jwt(RSA_KEY_PEM, 'kid1', 'RS256', AUDIENCE, SPIFFE_ID, EXPIRY)
    jwt_svid = JwtSvid.parse_and_validate(token, JWT_BUNDLE, ['spire'])
    assert jwt_svid.audience == AUDIENCE
    assert str(jwt_svid.spiffe_id) == SPIFFE_ID
    assert jwt_svid.expiry == EXPIRY
    assert jwt_svid.token == token


def test_parse_and_validate_valid_token_EC():
    ec_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    jwt_bundle = JwtBundle(TrustDomain('test.orgcom'), {'kid_ec': ec_key.public_key()})

    ec_key_pem, _ = get_keys_pems(ec_key)
    token = create_jwt(ec_key_pem, 'kid_ec', 'ES512', AUDIENCE, SPIFFE_ID, EXPIRY)
    jwt_svid = JwtSvid.parse_and_validate(token, jwt_bundle, ['spire'])
    assert jwt_svid.audience == AUDIENCE
    assert str(jwt_svid.spiffe_id) == SPIFFE_ID
    assert jwt_svid.expiry == EXPIRY
    assert jwt_svid.token == token


def test_parse_and_validate_valid_token_multiple_keys_bundle():
    ec_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
    jwt_bundle = JwtBundle(
        TrustDomain('test.orgcom'),
        {'kid_rsa': RSA_KEY.public_key(), 'kid_ec': ec_key.public_key()},
    )
    ec_key_pem, _ = get_keys_pems(ec_key)

    token = create_jwt(ec_key_pem, 'kid_ec', 'ES512', AUDIENCE, SPIFFE_ID, EXPIRY)
    jwt_svid1 = JwtSvid.parse_and_validate(token, jwt_bundle, ['spire'])
    assert jwt_svid1.audience == AUDIENCE
    assert str(jwt_svid1.spiffe_id) == SPIFFE_ID
    assert jwt_svid1.expiry == EXPIRY
    assert jwt_svid1.token == token

    token2 = create_jwt(RSA_KEY_PEM, 'kid_rsa', 'RS256', AUDIENCE, SPIFFE_ID, EXPIRY)
    jwt_svid2 = JwtSvid.parse_and_validate(token2, jwt_bundle, ['spire'])
    assert jwt_svid2.audience == AUDIENCE
    assert str(jwt_svid2.spiffe_id) == SPIFFE_ID
    assert jwt_svid2.expiry == EXPIRY
    assert jwt_svid2.token == token2
