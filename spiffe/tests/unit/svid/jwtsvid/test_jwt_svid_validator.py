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

import pytest
import datetime
from calendar import timegm

from spiffe.svid.jwt_svid_validator import (
    JwtSvidValidator,
    AUDIENCE_NOT_MATCH_ERROR,
)
from spiffe.errors import ArgumentError
from spiffe.svid.errors import (
    TokenExpiredError,
    InvalidClaimError,
    InvalidAlgorithmError,
    InvalidTypeError,
    MissingClaimError,
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
                        datetime.datetime.now(datetime.timezone.utc)
                        + datetime.timedelta(hours=24)
                    ).utctimetuple()
                ),
                'aud': 'None',
                'sub': 'spiffeid://somewhere.over.the',
            },
            None,
            'expected_audience cannot be empty',
        ),
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.now(datetime.timezone.utc)
                        + datetime.timedelta(hours=24)
                    ).utctimetuple()
                ),
                'aud': ['test'],
                'sub': 'spiffeid://somewhere.over.the',
            },
            set(),
            'expected_audience cannot be empty',
        ),
    ],
)
def test_invalid_input_validate_claims(test_input_claim, test_input_audience, expected):
    with pytest.raises(ArgumentError) as exception:
        JwtSvidValidator().validate_claims(test_input_claim, test_input_audience)

    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_claim,test_input_audience, expected',
    [
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.now(datetime.timezone.utc)
                        + datetime.timedelta(hours=24)
                    ).utctimetuple()
                ),
                'aud': [''],
                'sub': 'spiffeid://somewhere.over.the',
            },
            {''},
            str(InvalidClaimError('audience_claim cannot be empty')),
        ),
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.now(datetime.timezone.utc)
                        + datetime.timedelta(hours=24)
                    ).utctimetuple()
                ),
                'aud': ['', '', ''],
                'sub': 'spiffeid://somewhere.over.the',
            },
            {'test'},
            str(InvalidClaimError('audience_claim cannot be empty')),
        ),
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.now(datetime.timezone.utc)
                        + datetime.timedelta(hours=24)
                    ).utctimetuple()
                ),
                'aud': ['something'],
                'sub': 'spiffeid://somewhere.over.the',
            },
            {''},
            str(InvalidClaimError(AUDIENCE_NOT_MATCH_ERROR)),
        ),
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.now(datetime.timezone.utc)
                        + datetime.timedelta(hours=24)
                    ).utctimetuple()
                ),
                'aud': ['something'],
                'sub': 'spiffeid://somewhere.over.the',
            },
            {'something', 'matters'},
            str(InvalidClaimError(AUDIENCE_NOT_MATCH_ERROR)),
        ),
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.now(datetime.timezone.utc)
                        + datetime.timedelta(hours=24)
                    ).utctimetuple()
                ),
                'aud': ['something'],
                'sub': 'spiffeid://somewhere.over.the',
            },
            {'else', 'matters'},
            str(InvalidClaimError(AUDIENCE_NOT_MATCH_ERROR)),
        ),
    ],
)
def test_validate_claims_invalid_aud(test_input_claim, test_input_audience, expected):
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
                'sub': 'spiffeid://somewhere.over.the',
            },
            {'something'},
        ),
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.now(datetime.timezone.utc)
                        - datetime.timedelta(hours=24)
                    ).utctimetuple()
                ),
                'aud': ['something', 'more things', 'even more things'],
                'sub': 'spiffeid://somewhere.over.the',
            },
            {'even more things'},
        ),
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.now(datetime.timezone.utc)
                        - datetime.timedelta(hours=1)
                    ).utctimetuple()
                ),
                'aud': ['something', 'more things', 'even more things'],
                'sub': 'spiffeid://somewhere.over.the',
            },
            {'even more things'},
        ),
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.now(datetime.timezone.utc)
                        - datetime.timedelta(minutes=1)
                    ).utctimetuple()
                ),
                'aud': {'something', 'more things', 'even more things'},
                'sub': 'spiffeid://somewhere.over.the',
            },
            {'more things'},
        ),
    ],
)
def test_validate_claims_token_expired(test_input_claim, test_input_audience):
    with pytest.raises(TokenExpiredError) as exception:
        JwtSvidValidator().validate_claims(test_input_claim, test_input_audience)
    assert str(exception.value) == str(TokenExpiredError())


@pytest.mark.parametrize(
    'test_input_claim, test_input_audience',
    [
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.now(datetime.timezone.utc)
                        + datetime.timedelta(hours=24)
                    ).utctimetuple()
                ),
                'aud': 'something',
                'sub': 'spiffe://someone',
            },
            {'something'},
        ),
    ],
)
def test_validate_claims_single_string_aud(test_input_claim, test_input_audience):
    JwtSvidValidator().validate_claims(test_input_claim, test_input_audience)
    assert True


@pytest.mark.parametrize(
    'test_input_claim, test_input_audience, expected',
    [
        (
            {'aud': None, 'exp': 'ttt', 'sub': 'spiffeid://somewhere.over.the'},
            set(),
            str(MissingClaimError('aud')),
        ),
        (
            {'aud': [], 'exp': 'ttt', 'sub': 'spiffeid://somewhere.over.the'},
            set(),
            str(MissingClaimError('aud')),
        ),
        ({'aud': 'ttt', 'exp': 'ttt'}, set(), str(MissingClaimError('sub'))),
        ({'sub': 'ttt', 'exp': 'ttt'}, {'ttt'}, str(MissingClaimError('aud'))),
        ({'sub': 'ttt', 'aud': 'ttt'}, {'ttt'}, str(MissingClaimError('exp'))),
        ({'sub': 'ttt', 'aud': 'ttt', 'exp': ''}, {}, str(MissingClaimError('exp'))),
        ({}, set(), str(MissingClaimError('aud'))),
    ],
)
def test_validate_claims_missing_required_claim(
    test_input_claim, test_input_audience, expected
):
    with pytest.raises(MissingClaimError) as exception:
        JwtSvidValidator().validate_claims(test_input_claim, test_input_audience)

    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_claim, test_input_audience',
    [
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.now(datetime.timezone.utc)
                        + datetime.timedelta(hours=24)
                    ).utctimetuple()
                ),
                'aud': ['something'],
                'sub': 'spiffeid://somewhere.over.the',
            },
            {'something'},
        ),
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.now(datetime.timezone.utc)
                        + datetime.timedelta(minutes=5)
                    ).utctimetuple()
                ),
                'aud': ['something', 'more things'],
                'sub': 'spiffeid://somewhere.over.the',
            },
            {'something', 'more things'},
        ),
        (
            {
                'exp': timegm(
                    (
                        datetime.datetime.now(datetime.timezone.utc)
                        + datetime.timedelta(minutes=15)
                    ).utctimetuple()
                ),
                'aud': ['something', 'more things', 'even more things'],
                'sub': 'spiffeid://somewhere.over.the',
            },
            {'something', 'more things'},
        ),
    ],
)
def test_validate_claims_valid_input(test_input_claim, test_input_audience):
    JwtSvidValidator().validate_claims(test_input_claim, test_input_audience)

    assert True


"""
    validate_headers tests
"""


@pytest.mark.parametrize(
    'test_input_header, expected',
    [
        (
            None,
            'header cannot be empty',
        ),
        (
            '',
            'header cannot be empty',
        ),
        (
            {'ttt': 'eee'},
            'header alg cannot be empty',
        ),
        ({'alg': ''}, 'header alg cannot be empty'),
    ],
)
def test_validate_header_invalid_input(test_input_header, expected):
    with pytest.raises(ArgumentError) as exception:
        JwtSvidValidator().validate_header(test_input_header)

    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_header, expected',
    [
        ({'alg': 'eee'}, str(InvalidAlgorithmError('eee'))),
        ({'alg': 'RS256 RS384'}, str(InvalidAlgorithmError('RS256 RS384'))),
    ],
)
def test_validate_header_invalid_algorithm(test_input_header, expected):
    with pytest.raises(InvalidAlgorithmError) as exception:
        JwtSvidValidator().validate_header(test_input_header)

    assert str(exception.value) == expected


@pytest.mark.parametrize(
    'test_input_header, expected',
    [
        ({'alg': 'RS256', 'typ': 'xxx'}, str(InvalidTypeError('xxx'))),
    ],
)
def test_validate_header_invalid_type(test_input_header, expected):
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
def test_validate_header_valid_headers(test_input_header):
    JwtSvidValidator().validate_header(test_input_header)

    assert True
