import pytest
import datetime
from calendar import timegm

from pyspiffe.svid.jwt_svid_validator import (
    JwtSvidValidator,
    INVALID_INPUT_ERROR,
    AUDIENCE_NOT_MATCH_ERROR,
)
from pyspiffe.svid.exceptions import (
    TokenExpiredError,
    InvalidClaimError,
    InvalidAlgorithmError,
    InvalidTypeError,
)


"""
    validate_claims tests
"""


@pytest.mark.parametrize(
    'test_input_claim,test_input_audience, expected',
    [
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.utcnow() + datetime.timedelta(hours=24)
                    ).utctimetuple()
                ),
                'aud': 'None',
                'sub': 'spiffeid://somwhere.over.the',
            },
            None,
            INVALID_INPUT_ERROR.format('expected_audience cannot be empty'),
        ),
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.utcnow() + datetime.timedelta(hours=24)
                    ).utctimetuple()
                ),
                'aud': ['test'],
                'sub': 'spiffeid://somwhere.over.the',
            },
            [],
            INVALID_INPUT_ERROR.format('expected_audience cannot be empty'),
        ),
    ],
)
def test_invalid_input_validate_claims(test_input_claim, test_input_audience, expected):
    with pytest.raises(ValueError) as exception:
        JwtSvidValidator().validate_claims(test_input_claim, test_input_audience)

    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_claim,test_input_audience, expected',
    [
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.utcnow() + datetime.timedelta(hours=24)
                    ).utctimetuple()
                ),
                'aud': None,
                'sub': 'spiffeid://somwhere.over.the',
            },
            ['even more things'],
            str(InvalidClaimError('aud')),
        ),
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.utcnow() + datetime.timedelta(hours=24)
                    ).utctimetuple()
                ),
                'aud': [],
                'sub': 'spiffeid://somwhere.over.the',
            },
            ['even more things'],
            str(InvalidClaimError('aud')),
        ),
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.utcnow() + datetime.timedelta(hours=24)
                    ).utctimetuple()
                ),
                'aud': [''],
                'sub': 'spiffeid://somwhere.over.the',
            },
            [''],
            str(InvalidClaimError('audience_claim cannot be empty')),
        ),
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.utcnow() + datetime.timedelta(hours=24)
                    ).utctimetuple()
                ),
                'aud': ['', '', ''],
                'sub': 'spiffeid://somwhere.over.the',
            },
            ['test'],
            str(InvalidClaimError('audience_claim cannot be empty')),
        ),
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
            [''],
            str(InvalidClaimError(AUDIENCE_NOT_MATCH_ERROR)),
        ),
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
            ['something', 'matters'],
            str(InvalidClaimError(AUDIENCE_NOT_MATCH_ERROR)),
        ),
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
            ['else', 'matters'],
            str(InvalidClaimError(AUDIENCE_NOT_MATCH_ERROR)),
        ),
    ],
)
def test_invalid_aud_validate_claim(test_input_claim, test_input_audience, expected):
    with pytest.raises(InvalidClaimError) as exception:
        JwtSvidValidator().validate_claims(test_input_claim, test_input_audience)

    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_claim, test_input_audience',
    [
        (
            {
                'exp': '1611075778',
                'aud': ['something', 'more things', 'even more things'],
                'sub': 'spiffeid://somwhere.over.the',
            },
            ['something'],
        ),
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.utcnow() - datetime.timedelta(hours=24)
                    ).utctimetuple()
                ),
                'aud': ['something', 'more things', 'even more things'],
                'sub': 'spiffeid://somwhere.over.the',
            },
            ['even more things'],
        ),
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                    ).utctimetuple()
                ),
                'aud': ['something', 'more things', 'even more things'],
                'sub': 'spiffeid://somwhere.over.the',
            },
            ['even more things'],
        ),
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.utcnow() - datetime.timedelta(minutes=1)
                    ).utctimetuple()
                ),
                'aud': ['something', 'more things', 'even more things'],
                'sub': 'spiffeid://somwhere.over.the',
            },
            ['more things'],
        ),
    ],
)
def test_token_expired_validate_claim(test_input_claim, test_input_audience):
    with pytest.raises(TokenExpiredError) as exception:
        JwtSvidValidator().validate_claims(test_input_claim, test_input_audience)
    assert str(exception.value) == str(TokenExpiredError())


@pytest.mark.parametrize(
    'test_input_claim, test_input_audience, expected',
    [
        ({'aud': 'ttt', 'exp': 'ttt'}, [], str(InvalidClaimError('sub'))),
        ({'sub': 'ttt', 'exp': 'ttt'}, ['ttt'], str(InvalidClaimError('aud'))),
        ({'sub': 'ttt', 'aud': 'ttt'}, ['ttt'], str(InvalidClaimError('exp'))),
        (
            {'sub': 'ttt', 'aud': 'ttt', 'exp': ''},
            [],
            str(InvalidClaimError('exp')),
        ),
        ({}, [], str(InvalidClaimError('aud'))),
    ],
)
def test_missing_required_claim_validate_claims(
    test_input_claim, test_input_audience, expected
):
    with pytest.raises(InvalidClaimError) as exception:
        JwtSvidValidator().validate_claims(test_input_claim, test_input_audience)

    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_claim, test_input_audience',
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
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
                    ).utctimetuple()
                ),
                'aud': ['something', 'more things'],
                'sub': 'spiffeid://somwhere.over.the',
            },
            ['something', 'more things'],
        ),
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
                    ).utctimetuple()
                ),
                'aud': ['something', 'more things', 'even more things'],
                'sub': 'spiffeid://somwhere.over.the',
            },
            ['something', 'more things'],
        ),
    ],
)
def test_valid_input_validate_claims(test_input_claim, test_input_audience):
    JwtSvidValidator().validate_claims(test_input_claim, test_input_audience)
    assert True


"""
    validate_header tests
"""


@pytest.mark.parametrize(
    'test_input_header, expected',
    [
        (
            None,
            INVALID_INPUT_ERROR.format('header alg cannot be empty'),
        ),
        (
            '',
            INVALID_INPUT_ERROR.format('header alg cannot be empty'),
        ),
        (
            {'tttt': 'eee'},
            INVALID_INPUT_ERROR.format('header alg cannot be empty'),
        ),
        ({'alg': ''}, INVALID_INPUT_ERROR.format('header alg cannot be empty')),
    ],
)
def test_invalid_input_validate_header(test_input_header, expected):
    with pytest.raises(ValueError) as exception:
        JwtSvidValidator().validate_header(test_input_header)

    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_header, expected',
    [
        ({'alg': 'eee'}, str(InvalidAlgorithmError('eee'))),
        ({'alg': 'RS256 RS384'}, str(InvalidAlgorithmError('RS256 RS384'))),
    ],
)
def test_invalid_algorithm_validate_header(test_input_header, expected):
    with pytest.raises(InvalidAlgorithmError) as exception:
        JwtSvidValidator().validate_header(test_input_header)

    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_header, expected',
    [
        ({'alg': 'RS256', 'typ': 'xxx'}, str(InvalidTypeError('xxx'))),
    ],
)
def test_invalid_type_validate_header(test_input_header, expected):
    with pytest.raises(InvalidTypeError) as exception:
        JwtSvidValidator().validate_header(test_input_header)

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
def test_valid_validate_header(test_input_header):
    JwtSvidValidator().validate_header(test_input_header)

    assert True
