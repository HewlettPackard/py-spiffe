import pytest
import datetime
from calendar import timegm
import jwt

from pyspiffe.svid.jwt_svid import (
    JwtSvid,
    EMPTY_TOKEN_ERROR,
    INVALID_INPUT_ERROR,
    MISSING_X_ERROR,
    AUDIENCE_NOT_MATCH_ERROR,
    TOKEN_EXPIRED_ERROR,
    UNSUPPORTED_VALUE_ERROR,
)
from pyspiffe.svid.exceptions import (
    TokenExpiredError,
    JwtSvidError,
    InvalidClaimError,
    UnsupportedAlgorithmError,
    UnsupportedTypeError,
)


"""
    _validate_aud tests
"""


@pytest.mark.parametrize(
    'test_input_aud_claim,test_input_audience, expected',
    [
        (
            None,
            None,
            INVALID_INPUT_ERROR.format('expected_audience cannot be empty'),
        ),
        (
            [],
            [],
            INVALID_INPUT_ERROR.format('expected_audience cannot be empty'),
        ),
        (
            ['None'],
            None,
            INVALID_INPUT_ERROR.format('expected_audience cannot be empty'),
        ),
    ],
)
def test_invalid_input_validate_aud(
    test_input_aud_claim, test_input_audience, expected
):
    with pytest.raises(ValueError) as exception:
        JwtSvid._validate_aud(test_input_aud_claim, test_input_audience)

    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_aud_claim,test_input_audience, expected',
    [
        (None, ['None'], INVALID_INPUT_ERROR.format('audience_claim cannot be empty')),
        (
            [],
            ['something'],
            INVALID_INPUT_ERROR.format('audience_claim cannot be empty'),
        ),
        ([''], [''], INVALID_INPUT_ERROR.format('audience_claim cannot be empty')),
        ([''], ['test'], INVALID_INPUT_ERROR.format('audience_claim cannot be empty')),
        (
            ['', '', ''],
            ['test'],
            INVALID_INPUT_ERROR.format('audience_claim cannot be empty'),
        ),
        (['something'], [''], AUDIENCE_NOT_MATCH_ERROR),
        (['something'], ['nothing'], AUDIENCE_NOT_MATCH_ERROR),
        (['something'], ['something else', 'matters'], AUDIENCE_NOT_MATCH_ERROR),
        (['something'], ['something', 'matters'], AUDIENCE_NOT_MATCH_ERROR),
        (['something', 'else'], ['else', 'matters'], AUDIENCE_NOT_MATCH_ERROR),
    ],
)
def test_invalid_validate_aud(test_input_aud_claim, test_input_audience, expected):
    with pytest.raises(InvalidClaimError) as exception:
        JwtSvid._validate_aud(test_input_aud_claim, test_input_audience)

    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_aud_claim,test_input_audience',
    [
        (['something'], ['something']),
        (['something', 'else'], ['else']),
        (['something', 'else', 'unforgiven', 'nothing'], ['nothing', 'unforgiven']),
        (['something else', 'else', 'matters'], ['something else', 'matters']),
    ],
)
def test_valid_validate_aud(test_input_aud_claim, test_input_audience):
    JwtSvid._validate_aud(test_input_aud_claim, test_input_audience)
    assert True


"""
    _validate_exp tests

"""


@pytest.mark.parametrize(
    'test_input_exp',
    [
        (''),
        ('test'),
    ],
)
def test_invalid_input_validate_exp(test_input_exp):
    with pytest.raises(ValueError):
        JwtSvid._validate_exp(test_input_exp)
    assert True


@pytest.mark.parametrize(
    'test_input_exp, expected',
    [
        (
            timegm(
                (
                    datetime.datetime.utcnow() - datetime.timedelta(hours=24)
                ).utctimetuple()
            ),
            TOKEN_EXPIRED_ERROR,
        ),
        (
            timegm(
                (
                    datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                ).utctimetuple()
            ),
            TOKEN_EXPIRED_ERROR,
        ),
        (
            timegm(
                (
                    datetime.datetime.utcnow() - datetime.timedelta(minutes=1)
                ).utctimetuple()
            ),
            TOKEN_EXPIRED_ERROR,
        ),
        ("1611075778", TOKEN_EXPIRED_ERROR),
    ],
)
def test_expired_input_validate_exp(test_input_exp, expected):
    with pytest.raises(TokenExpiredError) as exception:
        JwtSvid._validate_exp(test_input_exp)
    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_exp',
    [
        (
            timegm(
                (
                    datetime.datetime.utcnow() + datetime.timedelta(hours=24)
                ).utctimetuple()
            )
        ),
        (
            timegm(
                (
                    datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                ).utctimetuple()
            )
        ),
    ],
)
def test_valid_input_validate_exp(test_input_exp):
    JwtSvid._validate_exp(test_input_exp)
    assert True


"""
    _validate_claims tests
"""


@pytest.mark.parametrize(
    'test_input_payload, test_input_audience, expected',
    [
        ({'aud': 'ttt', 'exp': 'ttt'}, [], MISSING_X_ERROR.format('sub')),
        ({'sub': 'ttt', 'exp': 'ttt'}, [], MISSING_X_ERROR.format('aud')),
        ({'sub': 'ttt', 'aud': 'ttt'}, [], MISSING_X_ERROR.format('exp')),
        ({'sub': 'ttt', 'aud': 'ttt', 'exp': ''}, [], MISSING_X_ERROR.format('exp')),
        ({}, [], MISSING_X_ERROR.format('aud')),
    ],
)
def test_invalid_input_validate_claims(
    test_input_payload, test_input_audience, expected
):
    with pytest.raises(JwtSvidError) as exception:
        JwtSvid._validate_claims(test_input_payload, test_input_audience)

    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_payload, test_input_audience',
    [
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.utcnow() + datetime.timedelta(hours=24)
                    ).utctimetuple()
                ),
                'aud': ['something'],
                'sub': 'spiffeid://somwhere.over.the',
            },
            ['something'],
        ),
    ],
)
def test_valid_input_validate_claims(test_input_payload, test_input_audience):
    JwtSvid._validate_claims(test_input_payload, test_input_audience)
    assert True


"""
    _validate_header tests
"""


@pytest.mark.parametrize(
    'test_input_header, expected',
    [
        # ({''}, INVALID_INPUT_ERROR.format('header cannot be empty or alg must be specified')),
        (
            None,
            INVALID_INPUT_ERROR.format(
                'header cannot be empty or alg must be specified'
            ),
        ),
        (
            {'alg': ''},
            INVALID_INPUT_ERROR.format(
                'header cannot be empty or alg must be specified'
            ),
        ),
    ],
)
def test_invalid_input_validate_header(test_input_header, expected):
    with pytest.raises(ValueError) as exception:
        JwtSvid._validate_header(test_input_header)

    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_header, expected',
    [
        ({'alg': 'eee'}, UNSUPPORTED_VALUE_ERROR.format('eee')),
        ({'alg': 'RS256 RS384'}, UNSUPPORTED_VALUE_ERROR.format('RS256 RS384')),
    ],
)
def test_invalid_algorithm_validate_header(test_input_header, expected):
    with pytest.raises(UnsupportedAlgorithmError) as exception:
        JwtSvid._validate_header(test_input_header)

    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_header, expected',
    [
        ({'alg': 'RS256', 'typ': 'xxx'}, UNSUPPORTED_VALUE_ERROR.format('xxx')),
    ],
)
def test_invalid_type_validate_header(test_input_header, expected):
    with pytest.raises(UnsupportedTypeError) as exception:
        JwtSvid._validate_header(test_input_header)

    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_header',
    [
        ({'alg': 'RS256', 'typ': 'JOSE'}),
        ({'alg': 'PS512', 'typ': 'JWT'}),
        ({'alg': 'ES384', 'typ': ''}),
        ({'alg': 'PS256'}),
    ],
)
def test_invalid_type_validate_header(test_input_header):
    JwtSvid._validate_header(test_input_header)

    assert True


"""
    parse_insecure tests
"""


@pytest.mark.parametrize(
    'test_input_token,test_input_audience, expected',
    [
        ('', [], EMPTY_TOKEN_ERROR),
        ('', None, EMPTY_TOKEN_ERROR),
        (None, [], EMPTY_TOKEN_ERROR),
        (None, None, EMPTY_TOKEN_ERROR),
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
            MISSING_X_ERROR.format('aud'),
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
            MISSING_X_ERROR.format('exp'),
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
            MISSING_X_ERROR.format('sub'),
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
            TOKEN_EXPIRED_ERROR,
        ),  # expired token
    ],
)
def test_invalid_parse_insecure(test_input_token, test_input_audience, expected):
    with pytest.raises(JwtSvidError) as exception:
        JwtSvid.parse_insecure(test_input_token, test_input_audience)

    assert str(exception.value) == expected


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

    TBD

"""
