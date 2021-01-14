import pytest

from src.pyspiffe.svid.jwt_svid import JwtSvid, EMPTY_TOKEN_ERROR, MISSING_X_CLAIM_ERROR


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
            MISSING_X_CLAIM_ERROR.format('aud'),
        ),  # no aud
        (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcGlmZmVJRDovL3Rlcy5kb21haW4vIiwibmFtZSI6IkdsYXVjaW1hciBBZ3VpYXIiLCJpYXQiOjE1MTYyMzkwMjIsImF1ZCI6InNwaXJlIn0.hL6rIVn5dFuQ4KKWxZ7yag7Gi68m174RqaU04720PZU",
            ["spire"],
            MISSING_X_CLAIM_ERROR.format('exp'),
        ),  # no exp
        (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiR2xhdSIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjM5MDIyLCJhdWQiOlsic3BpcmUiXX0.Cc6vnXybg_7DTYpObYkCNIuJqzROlRj3jVe0g4qO-W4",
            ["spire"],
            MISSING_X_CLAIM_ERROR.format('sub'),
        ),  # no sub
    ],
)
def test_invalid_parse_insecure(test_input_token, test_input_audience, expected):
    with pytest.raises(ValueError) as exception:
        result = JwtSvid.parse_insecure(test_input_token, test_input_audience)

    assert str(exception.value) == expected


"""
@pytest.mark.parametrize(
    'test_input_token,test_input_audience, expected',
    [
        ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcGlmZmVJRDovL3Rlcy5kb21haW4vIiwibmFtZSI6IkdsYXVjaW1hciBBZ3VpYXIiLCJpYXQiOjE1MTYyMzkwMjIsImF1ZCI6InNwaXJlIiwiZXhwIjoiMTU0NTE4NTQ5NiJ9.HQ6F_uvq597L1TunY6RSe0OpOAF-r2vAVGIFDQrde1c", ["spire"], True),  
    ],
)
def test_valid_parse_insecure(test_input_token, test_input_audience, expected):
    result = JwtSvid.parse_insecure(test_input_token, test_input_audience)
    print (result)
    assert expected
"""
"""
    parse_and_validate tests
"""


@pytest.mark.parametrize(
    'test_input_token, test_input_bundle, test_input_audience, expected',
    [
        ('', None, [], EMPTY_TOKEN_ERROR),
        ('', None, None, EMPTY_TOKEN_ERROR),
        (None, None, [], EMPTY_TOKEN_ERROR),
        (None, None, None, EMPTY_TOKEN_ERROR),
    ],
)
def test_invalid_parse_and_validate(
    test_input_token, test_input_bundle, test_input_audience, expected
):
    with pytest.raises(ValueError) as exception:
        result = JwtSvid.parse_and_validate(
            test_input_token, test_input_bundle, test_input_audience
        )

    assert str(exception.value) == expected
