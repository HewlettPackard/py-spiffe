"""
This module manages JWT SVID objects.
"""

import jwt
from jwt import PyJWTError
from typing import List, Dict
from pyspiffe.svid import INVALID_INPUT_ERROR
from cryptography.hazmat.primitives import serialization
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from pyspiffe.svid.jwt_svid_validator import JwtSvidValidator
from pyspiffe.svid.exceptions import InvalidTokenError


class JwtSvid(object):
    """Represents a SPIFFE JWT SVID as defined in the SPIFFE standard.
    See `SPIFFE JWT-SVID standard <https://github.com/spiffe/spiffe/blob/master/standards/JWT-SVID.md>`

    """

    def __init__(
        self,
        spiffeId: SpiffeId,
        audience: List[str],
        expiry: int,
        claims: Dict[str, str],
        token: str,
    ) -> None:
        """Creates a JwtSvid instance.

        Args:
            spiffeId: A valid spiffeId instance.
            audience: List of audience expected to be in the 'aud' claims.
            expiry: Date and time in UTC specifing expiry date of the JwtSvid.
            claims: Key-value pairs with all the claims present in the token.
            token: Encoded token.
        """
        self.spiffeId = spiffeId
        self.audience = audience
        self.expiry = expiry
        self.claims = claims
        self.token = token

    @classmethod
    def parse_insecure(cls, token: str, expected_audience: List) -> 'JwtSvid':
        """Parses and validates a JWT-SVID token and returns an instance of a JwtSvid with a SPIFFE ID parsed from the 'sub', audience from 'aud',
        and expiry from 'exp' claim. The JWT-SVID signature is not verified.

        Args:
            token: A token as a string that is parsed and validated.
            audience: Audience as a list of strings used to validate the 'aud' claim.

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
            spiffe_ID = SpiffeId.parse(claims['sub'])
            return JwtSvid(spiffe_ID, claims['aud'], claims['exp'], claims, token)
        except PyJWTError as err:
            raise InvalidTokenError(str(err))

    @classmethod
    def parse_and_validate(
        cls, token: str, jwt_bundle: JwtBundle, audience: List[str]
    ) -> 'JwtSvid':
        """Parses and validates a JWT-SVID token and returns an instance of JwtSvid.

        The JWT-SVID signature is verified using the JWT bundle source.

        Args:
            token: A token as a string that is parsed and validated.
            jwt_bundle: An instance of JwtBundle that provides the JWT authorities to verify the signature.
            audience: A list of strings used to validate the 'aud' claim.

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
            signing_key = jwt_bundle.find_jwt_authority(token_header.get('kid', None))

            public_key_pem = signing_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode('UTF-8')

            claims = jwt.decode(
                token,
                algorithms=token_header.get('alg', None),
                key=public_key_pem,
                audience=audience,
                options={
                    'verify_signature': True,
                    'verify_aud': True,
                    'verify_exp': True,
                },
            )
            spiffe_ID = SpiffeId.parse(claims['sub'])
            return JwtSvid(spiffe_ID, claims['aud'], claims['exp'], claims, token)
        except PyJWTError as err:
            raise InvalidTokenError(str(err))
        except ValueError as value_err:
            raise InvalidTokenError(str(value_err))
