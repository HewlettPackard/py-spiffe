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
    InvalidClaimError,
    InvalidTokenError,
)
from pyspiffe.bundle.jwt_bundle.exceptions import AuthorityNotFoundError
from test.svid.test_utils import get_keys_pems

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
            str(InvalidClaimError('aud')),
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
            str(InvalidClaimError('exp')),
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
            str(InvalidClaimError('sub')),
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
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwt_bundle = JwtBundle(TrustDomain('test.orgcom'), {'kid1': rsa_key.public_key()})
    rsa_key_pem, _ = get_keys_pems(rsa_key)
    audience = ['spire', 'test', 'valid']
    spiffe_id = 'spiffe://test.orgcom/'
    expiry = timegm(
        (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).utctimetuple()
    )
    token = jwt.encode(
        {
            'aud': audience,
            'sub': spiffe_id,
            'exp': expiry,
        },
        algorithm="RS256",
        key=rsa_key_pem,
    )

    with pytest.raises(InvalidTokenError) as exception:
        JwtSvid.parse_and_validate(token, jwt_bundle, ['spire'])
    assert str(exception.value) == 'key_id cannot be empty.'


def test_parse_and_validate_invalid_missing_sub():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwt_bundle = JwtBundle(TrustDomain('test.orgcom'), {'kid1': rsa_key.public_key()})
    rsa_key_pem, _ = get_keys_pems(rsa_key)
    audience = ['spire', 'test', 'valid']
    expiry = timegm(
        (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).utctimetuple()
    )
    token = jwt.encode(
        {
            'aud': audience,
            'exp': expiry,
        },
        algorithm="RS256",
        key=rsa_key_pem,
        headers={'alg': 'RS256', 'typ': 'JWT', 'kid': 'kid1'},
    )

    with pytest.raises(InvalidTokenError) as exception:
        JwtSvid.parse_and_validate(token, jwt_bundle, 'spire')
    assert str(exception.value) == 'SPIFFE ID cannot be empty.'


def test_parse_and_validate_invalid_missing_kid():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwt_bundle = JwtBundle(TrustDomain('test.orgcom'), {'kid1': rsa_key.public_key()})
    rsa_key_pem, _ = get_keys_pems(rsa_key)
    audience = ['spire', 'test', 'valid']
    spiffe_id = 'spiffe://test.orgcom/'
    expiry = timegm(
        (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).utctimetuple()
    )
    token = jwt.encode(
        {
            'aud': audience,
            'sub': spiffe_id,
            'exp': expiry,
        },
        algorithm="RS256",
        key=rsa_key_pem,
        headers={'alg': 'RS256', 'typ': 'JWT', 'kid': 'kid10'},
    )

    with pytest.raises(AuthorityNotFoundError) as exception:
        JwtSvid.parse_and_validate(token, jwt_bundle, ['spire'])
    assert str(exception.value) == 'Key (kid10) not found in authorities.'


def test_parse_and_validate_invalid_kid_mismatch():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwt_bundle = JwtBundle(
        TrustDomain('test.orgcom'),
        {'kid1': rsa_key.public_key(), 'kid10': rsa_key2.public_key()},
    )
    rsa_key_pem, _ = get_keys_pems(rsa_key)
    audience = ['spire', 'test', 'valid']
    spiffe_id = 'spiffe://test.orgcom/'
    expiry = timegm(
        (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).utctimetuple()
    )
    token = jwt.encode(
        {
            'aud': audience,
            'sub': spiffe_id,
            'exp': expiry,
        },
        algorithm="RS256",
        key=rsa_key_pem,
        headers={'alg': 'RS256', 'typ': 'JWT', 'kid': 'kid10'},
    )

    with pytest.raises(InvalidTokenError) as exception:
        JwtSvid.parse_and_validate(token, jwt_bundle, ['spire'])
    assert str(exception.value) == 'Signature verification failed'


def test_parse_and_validate_valid_token_RSA():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwt_bundle = JwtBundle(TrustDomain('test.orgcom'), {'kid1': rsa_key.public_key()})
    rsa_key_pem, _ = get_keys_pems(rsa_key)
    audience = ['spire', 'test', 'valid']
    spiffe_id = 'spiffe://test.orgcom/'
    expiry = timegm(
        (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).utctimetuple()
    )
    token = jwt.encode(
        {
            'aud': audience,
            'sub': spiffe_id,
            'exp': expiry,
        },
        algorithm="RS256",
        key=rsa_key_pem,
        headers={'alg': 'RS256', 'typ': 'JWT', 'kid': 'kid1'},
    )
    jwt_svid = JwtSvid.parse_and_validate(token, jwt_bundle, ['spire'])
    assert jwt_svid.audience == audience
    assert str(jwt_svid.spiffe_id) == spiffe_id
    assert jwt_svid.expiry == expiry
    assert jwt_svid.token == token


def test_parse_and_validate_valid_token_EC():
    ec_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    jwt_bundle = JwtBundle(TrustDomain('test.orgcom'), {'kid_ec': ec_key.public_key()})
    ec_key_pem, _ = get_keys_pems(ec_key)
    audience = ['spire', 'test', 'valid']
    spiffe_id = 'spiffe://test.orgcom/'
    expiry = timegm(
        (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).utctimetuple()
    )
    token = jwt.encode(
        {
            'aud': audience,
            'sub': spiffe_id,
            'exp': expiry,
        },
        algorithm="ES256",
        key=ec_key_pem,
        headers={'alg': 'ES256', 'typ': 'JOSE', 'kid': 'kid_ec'},
    )
    jwt_svid = JwtSvid.parse_and_validate(token, jwt_bundle, ['spire'])
    assert jwt_svid.audience == audience
    assert str(jwt_svid.spiffe_id) == spiffe_id
    assert jwt_svid.expiry == expiry
    assert jwt_svid.token == token


def test_parse_and_validate_valid_token_multiple_keys_bundle():
    ec_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    audience = ['spire', 'test', 'valid']
    spiffe_id = 'spiffe://test.orgcom/'
    expiry = timegm(
        (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).utctimetuple()
    )

    jwt_bundle = JwtBundle(
        TrustDomain('test.orgcom'),
        {'kid_rsa': rsa_key.public_key(), 'kid_ec': ec_key.public_key()},
    )
    ec_key_pem, _ = get_keys_pems(ec_key)
    token = jwt.encode(
        {
            'aud': audience,
            'sub': spiffe_id,
            'exp': expiry,
        },
        algorithm="ES512",
        key=ec_key_pem,
        headers={'alg': 'ES512', 'typ': 'JOSE', 'kid': 'kid_ec'},
    )
    rsa_key_pem, _ = get_keys_pems(rsa_key)
    token2 = jwt.encode(
        {
            'aud': audience,
            'sub': spiffe_id,
            'exp': expiry,
        },
        algorithm="RS256",
        key=rsa_key_pem,
        headers={'alg': 'RS256', 'kid': 'kid_rsa'},
    )
    jwt_svid1 = JwtSvid.parse_and_validate(token, jwt_bundle, ['spire'])
    assert jwt_svid1.audience == audience
    assert str(jwt_svid1.spiffe_id) == spiffe_id
    assert jwt_svid1.expiry == expiry
    assert jwt_svid1.token == token

    jwt_svid2 = JwtSvid.parse_and_validate(token2, jwt_bundle, ['spire'])
    assert jwt_svid2.audience == audience
    assert str(jwt_svid2.spiffe_id) == spiffe_id
    assert jwt_svid2.expiry == expiry
    assert jwt_svid2.token == token2
