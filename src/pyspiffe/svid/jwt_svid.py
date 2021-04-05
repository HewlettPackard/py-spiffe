"""
This module manages JWT SVID objects.
"""

import jwt
from jwt import PyJWTError
from typing import Dict, Set
from pyspiffe.svid import INVALID_INPUT_ERROR
from cryptography.hazmat.primitives import serialization
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from pyspiffe.bundle.jwt_bundle.exceptions import AuthorityNotFoundError
from pyspiffe.svid.jwt_svid_validator import JwtSvidValidator
from pyspiffe.svid.exceptions import InvalidTokenError


class JwtSvid(object):
    """Represents a SPIFFE JWT SVID as defined in the SPIFFE standard.
    See `SPIFFE JWT-SVID standard <https://github.com/spiffe/spiffe/blob/master/standards/JWT-SVID.md>`

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
            spiffe_id: A valid spiffeId instance.
            audience: Set of audience expected to be in the 'aud' claims.
            expiry: Date and time in UTC specifying expiry date of the JwtSvid.
            claims: Key-value pairs with all the claims present in the token.
            token: Encoded token.
        """
        self.spiffe_id = spiffe_id
        self.audience = audience
        self.expiry = expiry
        self.claims = claims
        self.token = token

    @classmethod
    def parse_insecure(cls, token: str, expected_audience: Set[str]) -> 'JwtSvid':
        """Parses and validates a JWT-SVID token and returns an instance of a JwtSvid with a SPIFFE ID parsed from the 'sub', audience from 'aud',
        and expiry from 'exp' claim. The JWT-SVID signature is not verified.

        Args:
            token: A token as a string that is parsed and validated.
            expected_audience: Audience as a set of strings used to validate the 'aud' claim.

        Returns:
            An instance of JwtSvid with a SPIFFE ID parsed from the 'sub', audience from 'aud', and expiry
            from 'exp' claim.

        Raises:
            ValueError: When the token is blank or cannot be parsed, or in case header is not specified or in case expected_audience is empty or
                if the SPIFFE ID in the 'sub' claim doesn't comply with the SPIFFE standard.
            InvalidAlgorithmError: In case specified 'alg' is not supported as specified by the SPIFFE standard.
            InvalidTypeError: If 'typ' is present in header but is not set to 'JWT' or 'JOSE'.
            InvalidClaimError: If a required claim ('exp', 'aud', 'sub') is not present in payload or expected_audience is not a subset of audience_claim.
            TokenExpiredError: If token is expired.
            InvalidTokenError: If token is malformed and fails to decode.
        """
        if not token:
            raise ValueError(INVALID_INPUT_ERROR.format('token cannot be empty'))
        try:
            token_header = jwt.get_unverified_header(token)
            validator = JwtSvidValidator()
            validator.validate_header(token_header)
            claims = jwt.decode(token, options={'verify_signature': False})
            validator.validate_claims(claims, expected_audience)
            spiffe_id = SpiffeId.parse(claims['sub'])
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
            ValueError:     When the token is blank or cannot be parsed.
            BundleNotFoundError:    If the bundle for the trust domain of the spiffe id from the 'sub'
                                    cannot be found the jwt_bundle_source.
            AuthorityNotFoundError: If the authority cannot be found in the bundle using the value from the 'kid' header.
            InvalidTokenError: In case token is malformed and fails to decode.
        """
        if not token:
            raise ValueError(INVALID_INPUT_ERROR.format('token cannot be empty'))

        if not jwt_bundle:
            raise ValueError(INVALID_INPUT_ERROR.format('jwt_bundle cannot be empty'))
        try:
            token_header = jwt.get_unverified_header(token)
            validator = JwtSvidValidator()
            validator.validate_header(token_header)
            key_id = token_header.get('kid')
            signing_key = jwt_bundle.get_jwt_authority(key_id)
            if not signing_key:
                raise AuthorityNotFoundError(key_id)

            public_key_pem = signing_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode('UTF-8')

            claims = jwt.decode(
                token,
                algorithms=token_header.get('alg'),
                key=public_key_pem,
                audience=audience,
                options={
                    'verify_signature': True,
                    'verify_aud': True,
                    'verify_exp': True,
                },
            )

            spiffe_id = SpiffeId.parse(claims.get('sub', None))
            return JwtSvid(spiffe_id, claims['aud'], claims['exp'], claims, token)
        except PyJWTError as err:
            raise InvalidTokenError(str(err))
        except ValueError as value_err:
            raise InvalidTokenError(str(value_err))
