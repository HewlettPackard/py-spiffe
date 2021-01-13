import pytest

from src.pyspiffe.svid.jwt_svid import JwtSvid


"""
    parse_insecure tests
"""


@pytest.mark.parametrize(
    'test_input_token,test_input_audience, expected',
    [
        ('', [], None),
        ('', None, None),
        (None, [], None),
        (None, None, None),
    ],
)
def test_invalid_parse_insecure(test_input_token, test_input_audience, expected):
    result = JwtSvid.parse_insecure(test_input_token, test_input_audience)
    assert result == expected


"""
    parse_and_validate tests
"""


@pytest.mark.parametrize(
    'test_input_token, test_input_bundle, test_input_audience, expected',
    [
        ('', None, [], None),
        ('', None, None, None),
        (None, None, [], None),
        (None, None, None, None),
    ],
)
def test_invalid_parse_and_validate(
    test_input_token, test_input_bundle, test_input_audience, expected
):
    result = JwtSvid.parse_and_validate(
        test_input_token, test_input_bundle, test_input_audience
    )
    assert result == expected
