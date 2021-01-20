import pytest
import datetime
from calendar import timegm

from src.pyspiffe.svid.jwt_svid import (
    JwtSvid,
    EMPTY_TOKEN_ERROR,
    INVALID_INPUT_ERROR,
    MISSING_X_ERROR,
    AUDIENCE_NOT_MATCH_ERROR,
    SIGNATURE_EXPIRED_ERROR,
)
from src.pyspiffe.exceptions import JwtSvidError


"""
    _validate_aud tests
"""


@pytest.mark.parametrize(
    'test_input_aud_claim,test_input_audience, expected',
    [
        (
            None,
            None,
            INVALID_INPUT_ERROR.format('audience_claims and audience cannot be empty'),
        ),
        (
            [],
            [],
            INVALID_INPUT_ERROR.format('audience_claims and audience cannot be empty'),
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
        (None, ['None'], AUDIENCE_NOT_MATCH_ERROR),
        (['None'], None, AUDIENCE_NOT_MATCH_ERROR),
        ([], ['something'], AUDIENCE_NOT_MATCH_ERROR),
        (['something'], [], AUDIENCE_NOT_MATCH_ERROR),
        (['something'], [''], AUDIENCE_NOT_MATCH_ERROR),
        (['something'], ['nothing'], AUDIENCE_NOT_MATCH_ERROR),
        (['something'], ['something else', 'matters'], AUDIENCE_NOT_MATCH_ERROR),
    ],
)
def test_invalid_validate_aud(test_input_aud_claim, test_input_audience, expected):
    with pytest.raises(JwtSvidError) as exception:
        JwtSvid._validate_aud(test_input_aud_claim, test_input_audience)

    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_aud_claim,test_input_audience',
    [
        ([''], ['']),
        (['something'], ['something']),
        (['something', 'else'], ['else']),
        (['something', 'else', 'nothing'], ['nothing', 'unforgiven']),
        (['something', 'else', 'matters'], ['something else', 'matters']),
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
    with pytest.raises(ValueError) as exception:
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
            SIGNATURE_EXPIRED_ERROR,
        ),
        (
            timegm(
                (
                    datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                ).utctimetuple()
            ),
            SIGNATURE_EXPIRED_ERROR,
        ),
        (
            timegm(
                (
                    datetime.datetime.utcnow() - datetime.timedelta(minutes=1)
                ).utctimetuple()
            ),
            SIGNATURE_EXPIRED_ERROR,
        ),
        ("1611075778", SIGNATURE_EXPIRED_ERROR),
    ],
)
def test_expired_input_validate_exp(test_input_exp, expected):
    with pytest.raises(JwtSvidError) as exception:
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
    parse_insecure tests
"""


@pytest.mark.parametrize(
    'test_input_token,test_input_audience, expected',
    [
        ('', [], EMPTY_TOKEN_ERROR),
        ('', None, EMPTY_TOKEN_ERROR),
        (None, [], EMPTY_TOKEN_ERROR),
        (None, None, EMPTY_TOKEN_ERROR),
        (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcGlmZmVJRDovL3Rlcy5kb21haW4vIiwibmFtZSI6IkdsYXVjaW1hciBBZ3VpYXIiLCJpYXQiOjE1MTYyMzkwMjJ9.DZhQWvCRCY96yXJzRUMiSnB6mlMUQW4il0UQ4LXAKlU",
            [],
            MISSING_X_ERROR.format('aud'),
        ),  # no aud
        (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcGlmZmVJRDovL3Rlcy5kb21haW4vIiwibmFtZSI6IkdsYXVjaW1hciBBZ3VpYXIiLCJpYXQiOjE1MTYyMzkwMjIsImF1ZCI6InNwaXJlIn0.hL6rIVn5dFuQ4KKWxZ7yag7Gi68m174RqaU04720PZU",
            ["spire"],
            MISSING_X_ERROR.format('exp'),
        ),  # no exp
        (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiR2xhdSIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjM5MDIyLCJhdWQiOlsic3BpcmUiXX0.Cc6vnXybg_7DTYpObYkCNIuJqzROlRj3jVe0g4qO-W4",
            ["spire"],
            MISSING_X_ERROR.format('sub'),
        ),  # no sub
        (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcGlmZmVJRDovL3Rlcy5kb21haW4vIiwibmFtZSI6IkdsYXVjaW1hciBBZ3VpYXIiLCJpYXQiOjE1MTYyMzkwMjIsImF1ZCI6InNwaXJlIiwiZXhwIjoiMTU0NTE4NTQ5NiJ9.HQ6F_uvq597L1TunY6RSe0OpOAF-r2vAVGIFDQrde1c",
            ["spire"],
            SIGNATURE_EXPIRED_ERROR,
        ),
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
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcGlmZmU6Ly90ZXN0Lm9yZy8iLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6NDcyMTUwNTQzNywiYXVkIjpbInNwaXJlIl19.cvoi48geyYPAP88RQbBXyEXoRX09II5xAR0XKULWDwQ",
            ["spire"],
            "spiffe://test.org/",
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
