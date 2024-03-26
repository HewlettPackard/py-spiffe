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
This module manages JWT SVID objects.
"""

import jwt
from jwt import PyJWTError
from typing import Dict, Set
from spiffe.errors import ArgumentError
from cryptography.hazmat.primitives import serialization
from spiffe.spiffe_id.spiffe_id import SpiffeId, SpiffeIdError
from spiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from spiffe.bundle.jwt_bundle.errors import AuthorityNotFoundError
from spiffe.svid.jwt_svid_validator import JwtSvidValidator
from spiffe.svid.errors import InvalidTokenError


class JwtSvid(object):
    """Represents a SPIFFE JWT SVID as defined in the SPIFFE standard.
    See `SPIFFE JWT-SVID standard <https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md>`

    """

    def __init__(
        self,
        spiffe_id: SpiffeId,
        audience: Set[str],
        expiry: int,
        claims: Dict[str, str],
        token: str,
    ) -> None:
        """Creates a JwtSvid instance.

        Args:
            spiffe_id: A valid SpiffeId instance.
            audience: The intended recipients of JWT-SVID as present in the 'aud' claims.
            expiry: Date and time in UTC specifying expiry date of the JwtSvid.
            claims: Key-value pairs with all the claims present in the token.
            token: Encoded token.
        """
        self._spiffe_id = spiffe_id
        self._audience = set(audience)
        self._expiry = expiry
        self._claims = claims
        self._token = token

    @property
    def spiffe_id(self) -> SpiffeId:
        """Returns the SpiffeId."""
        return self._spiffe_id

    @property
    def audience(self) -> Set[str]:
        """Returns the Audience."""
        return self._audience

    @property
    def expiry(self) -> int:
        """Returns the Expiry."""
        return self._expiry

    @property
    def token(self) -> str:
        """Returns the token."""
        return self._token

    @classmethod
    def parse_insecure(cls, token: str, audience: Set[str]) -> 'JwtSvid':
        """Parses and validates a JWT-SVID token and returns an instance of a JwtSvid with a SPIFFE ID parsed from the 'sub', audience from 'aud',
        and expiry from 'exp' claim. The JWT-SVID signature is not verified.

        Args:
            token: A token as a string that is parsed and validated.
            audience: Audience is a set of strings used to validate the 'aud' claim.

        Returns:
            An instance of JwtSvid with a SPIFFE ID parsed from the 'sub', audience from 'aud', and expiry
            from 'exp' claim.

        Raises:
            ArgumentError: When the token is blank or cannot be parsed, or in case header is not specified or in case expected_audience is empty or
                if the SPIFFE ID in the 'sub' claim doesn't comply with the SPIFFE standard.
            InvalidAlgorithmError: In case specified 'alg' is not supported as specified by the SPIFFE standard.
            InvalidTypeError: If 'typ' is present in header but is not set to 'JWT' or 'JOSE'.
            InvalidClaimError: If a required claim ('exp', 'aud', 'sub') is not present in payload or expected_audience is not a subset of audience_claim.
            TokenExpiredError: If token is expired.
            InvalidTokenError: If token is malformed and fails to decode.
        """
        if not token:
            raise ArgumentError('token cannot be empty')
        try:
            header_params = jwt.get_unverified_header(token)
            validator = JwtSvidValidator()
            validator.validate_header(header_params)
            claims = jwt.decode(token, options={'verify_signature': False})
            validator.validate_claims(claims, audience)
            spiffe_id = SpiffeId(claims['sub'])
            return JwtSvid(spiffe_id, claims['aud'], claims['exp'], claims, token)
        except PyJWTError as err:
            raise InvalidTokenError(str(err))

    @classmethod
    def parse_and_validate(
        cls, token: str, jwt_bundle: JwtBundle, audience: Set[str]
    ) -> 'JwtSvid':
        """Parses and validates a JWT-SVID token and returns an instance of JwtSvid.

        The JWT-SVID signature is verified using the JWT bundle source.

        Args:
            token: A token as a string that is parsed and validated.
            jwt_bundle: An instance of JwtBundle that provides the JWT authorities to verify the signature.
            audience: A set of strings used to validate the 'aud' claim.

        Returns:
            An instance of JwtSvid with a SPIFFE ID parsed from the 'sub', audience from 'aud', and expiry
            from 'exp' claim.

        Raises:
            JwtSvidError:   When the token expired or the expiration claim is missing,
                            when the algorithm is not supported, when the header 'kid' is missing,
                            when the signature cannot be verified, or
                            when the 'aud' claim has an audience that is not in the audience list provided as parameter.
            ArgumentError:     When the token is blank or cannot be parsed.
            BundleNotFoundError:    If the bundle for the trust domain of the SPIFFE ID from the 'sub'
                                    cannot be found the jwt_bundle_source.
            AuthorityNotFoundError: If the authority cannot be found in the bundle using the value from the 'kid' header.
            InvalidTokenError: In case token is malformed and fails to decode.
        """
        if not token:
            raise ArgumentError('token cannot be empty')

        if not jwt_bundle:
            raise ArgumentError('jwt_bundle cannot be empty')
        try:
            header_params = jwt.get_unverified_header(token)
            validator = JwtSvidValidator()
            validator.validate_header(header_params)
            key_id = header_params.get('kid')
            signing_key = jwt_bundle.get_jwt_authority(key_id)
            if not signing_key:
                raise AuthorityNotFoundError(key_id if key_id else '')

            public_key_pem = signing_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode('UTF-8')

            claims = jwt.decode(
                token,
                algorithms=header_params.get('alg'),
                key=public_key_pem,
                audience=audience,
                options={
                    'verify_signature': True,
                    'verify_aud': True,
                    'verify_exp': True,
                },
            )

            spiffe_id = SpiffeId(claims.get('sub', None))

            return JwtSvid(spiffe_id, claims['aud'], claims['exp'], claims, token)
        except PyJWTError as err:
            raise InvalidTokenError(str(err)) from err
        except ArgumentError as err:
            raise InvalidTokenError(str(err)) from err
        except SpiffeIdError as err:
            raise InvalidTokenError(str(err)) from err
