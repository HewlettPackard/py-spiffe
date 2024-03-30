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

"""
This module manages the validations of JWT tokens.
"""

import datetime
from typing import Dict, Any, Set

from spiffe.errors import ArgumentError
from spiffe.svid.errors import (
    TokenExpiredError,
    InvalidClaimError,
    InvalidAlgorithmError,
    InvalidTypeError,
    MissingClaimError,
)

AUDIENCE_NOT_MATCH_ERROR = 'audience does not match expected value'
"""str: audience does not match error message."""


class JwtSvidValidator(object):
    """Performs validations on a given token checking compliance to SPIFFE specification.
    See `SPIFFE JWT-SVID standard <https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md>`

    """

    _REQUIRED_CLAIMS = ['aud', 'exp', 'sub']
    _SUPPORTED_ALGORITHMS = [
        'RS256',
        'RS384',
        'RS512',
        'ES256',
        'ES384',
        'ES512',
        'PS256',
        'PS384',
        'PS512',
    ]

    _SUPPORTED_TYPES = ['JWT', 'JOSE']

    def __init__(self) -> None:
        pass

    def validate_header(self, parameters: Dict[str, str]) -> None:
        """Validates token headers by verifying if headers specifies supported algorithms and token type.

        Type is optional but in case it is present, it must be set to one of the supported values (JWT or JOSE).

        Args:
            parameters: Header parameters.

        Returns:
            None.

        Raises:
            ArgumentError: In case header is not specified.
            InvalidAlgorithmError: In case specified 'alg' is not supported as specified by the SPIFFE standard.
            InvalidTypeError: In case 'typ' is present in header but is not set to 'JWT' or 'JOSE'.
        """
        if not parameters:
            raise ArgumentError('header cannot be empty')

        alg = parameters.get('alg')
        if not alg:
            raise ArgumentError('header alg cannot be empty')

        if alg not in self._SUPPORTED_ALGORITHMS:
            raise InvalidAlgorithmError(alg)

        typ = parameters.get('typ')
        if typ and typ not in self._SUPPORTED_TYPES:
            raise InvalidTypeError(typ)

    def validate_claims(self, payload: Dict[str, Any], expected_audience: Set[str]) -> None:
        """Validates payload for required claims (aud, exp, sub).

        Args:
            payload: Token payload.
            expected_audience: Audience as a set of strings used to validate the 'aud' claim.

        Returns:
            None

        Raises:
            MissingClaimError: In case a required claim is not present.
            InvalidClaimError: In case a claim contains an invalid value or expected_audience is not a subset of audience_claim.
            TokenExpiredError: In case token is expired.
            ArgumentError: In case expected_audience is empty.
        """
        for claim in self._REQUIRED_CLAIMS:
            if not payload.get(claim):
                raise MissingClaimError(claim)

        self._validate_exp(str(payload.get('exp')))
        self._validate_aud(set(payload.get('aud', [])), expected_audience)

    @staticmethod
    def _validate_exp(expiration_date: str) -> None:
        """Verifies expiration.

        Note: If and when https://github.com/jpadilla/pyjwt/issues/599 is fixed, this can be simplified/removed.

        Args:
            expiration_date: Date to check if it is expired.

        Raises:
            TokenExpiredError: In case it is expired.
        """
        int_date = int(expiration_date)
        utctime = datetime.datetime.now(datetime.timezone.utc).timestamp()
        if int_date < utctime:
            raise TokenExpiredError()

    @staticmethod
    def _validate_aud(audience_claim: Set[str], expected_audience: Set[str]) -> None:
        """Verifies if expected_audience is present in audience_claim. The aud claim MUST be present.

        Args:
            audience_claim: List of token's audience claim to be validated.
            expected_audience: Set of the claims expected to be present in the token's audience claim.

        Raises:
            InvalidClaimError: In expected_audience is not a subset of audience_claim or it is empty.
            ArgumentError: In case expected_audience is empty.
        """
        if not expected_audience:
            raise ArgumentError('expected_audience cannot be empty')

        if not audience_claim or all(aud == '' for aud in audience_claim):
            raise InvalidClaimError('audience_claim cannot be empty')

        if not all(aud in audience_claim for aud in expected_audience):
            raise InvalidClaimError(AUDIENCE_NOT_MATCH_ERROR)
