import pytest
import datetime
from calendar import timegm
import jwt
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
from test_utils import generate_rsa_key_pair, generate_ec_key_pair

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
def test_invalid_input_parse_insecure(test_input_token, test_input_audience, expected):
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
                    'sub': 'spiffeid://somwhere.over.the',
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
                    'sub': 'spiffeid://somwhere.over.the',
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
def test_invalid_claims_parse_insecure(test_input_token, test_input_audience, expected):
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
def test_invalid_token_parse_insecure(test_input_token, test_input_audience):
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
def test_valid_parse_insecure(test_input_token, test_input_audience, expected):
    result = JwtSvid.parse_insecure(test_input_token, test_input_audience)
    assert result.token == test_input_token
    assert str(result.spiffeId) == expected


"""
    parse_and_validate tests

"""


@pytest.mark.parametrize(
    'test_input_token,test_input_jwtBundle, test_input_audience, expected',
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
def test_invalid_parameters_parse_and_validate(
    test_input_token, test_input_jwtBundle, test_input_audience, expected
):
    with pytest.raises(ValueError) as exception:
        JwtSvid.parse_and_validate(
            test_input_token, test_input_jwtBundle, test_input_audience
        )
    assert str(exception.value) == expected


def test_valid_parse_and_validate_RSA():
    rsakeypem, rsapubpem = generate_rsa_key_pair()
    jwt_bundle = JwtBundle(TrustDomain('test.orgcom'), {'kid1': rsapubpem})
    token = jwt.encode(
        {
            'aud': ['spire', 'test', 'valid'],
            'sub': 'spiffe://test.orgcom/',
            'exp': timegm(
                (
                    datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                ).utctimetuple()
            ),
        },
        algorithm="RS256",
        key=rsakeypem,
        headers={'alg': 'RS256', 'typ': 'JWT', 'kid': 'kid1'},
    )
    JwtSvid.parse_and_validate(token, jwt_bundle, 'spire')
    assert True


def test_valid_parse_and_validate_EC():
    rsakeypem, rsapubpem = generate_ec_key_pair()
    jwt_bundle = JwtBundle(TrustDomain('test.orgcom'), {'kid1': rsapubpem})
    token = jwt.encode(
        {
            'aud': ['spire', 'test', 'valid'],
            'sub': 'spiffe://test.orgcom/',
            'exp': timegm(
                (
                    datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                ).utctimetuple()
            ),
        },
        algorithm="ES256",
        key=rsakeypem,
        headers={'alg': 'ES256', 'typ': 'JWT', 'kid': 'kid1'},
    )
    JwtSvid.parse_and_validate(token, jwt_bundle, 'spire')
    assert True
