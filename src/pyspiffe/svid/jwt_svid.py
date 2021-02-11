"""
This module manages JWT SVID objects.
"""

import jwt
from jwt import PyJWTError
from typing import List, Dict
from pyspiffe.svid import INVALID_INPUT_ERROR
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
        audience: List,
        expiry: int,
        claims: Dict,
        token: str,
    ) -> None:
        """Creates a JwtSvid instance.

        Args:
            spiffeId: a valid spiffeId instance.
            audience: list of audience expected to be in the 'aud' claims.
            expiry: date and time in UTC specifing expiry date of the JwtSvid.
            claims: key-value pairs with all the claims present in the token.
            token: encoded token.
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
            token: a token as a string that is parsed and validated.
            audience: audience as a list of strings used to validate the 'aud' claim.

        Returns:
            an instance of JwtSvid with a SPIFFE ID parsed from the 'sub', audience from 'aud', and expiry
            from 'exp' claim.

        Raises:
            ValueError: when the token is blank or cannot be parsed, or in case header is not specified or in case expected_audience is empty or
                if the SPIFFE ID in the 'sub' claim doesn't comply with the SPIFFE standard.
            InvalidAlgorithmError: in case specified 'alg' is not supported as specified by the SPIFFE standard.
            InvalidTypeError: in case 'typ' is present in header but is not set to 'JWT' or 'JOSE'.
            InvalidClaimError: in case a required claim ('exp', 'aud', 'sub') is not present in payload or expected_audience is not a subset of audience_claim.
            TokenExpiredError: in case token is expired.
            InvalidTokenError: in case token is malformed and fails to decode.
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
            token: a token as a string that is parsed and validated.
            jwt_bundle: an instance of JwtBundle that provides the JWT authorities to verify the signature.
            audience: a list of strings used to validate the 'aud' claim.

        Returns:
            an instance of JwtSvid with a SPIFFE ID parsed from the 'sub', audience from 'aud', and expiry
            from 'exp' claim.

        Raises:
            JwtSvidError:   when the token expired or the expiration claim is missing,
                            when the algorithm is not supported, when the header 'kid' is missing,
                            when the signature cannot be verified, or
                            when the 'aud' claim has an audience that is not in the audience list provided as parameter.
            ValueError:     when the token is blank or cannot be parsed.
            BundleNotFoundError:    if the bundle for the trust domain of the spiffe id from the 'sub'
                                    cannot be found the jwt_bundle_source.
            AuthorityNotFoundError: if the authority cannot be found in the bundle using the value from the 'kid' header.
            InvalidTokenError: in case token is malformed and fails to decode.
        """
        if not token:
            raise ValueError(INVALID_INPUT_ERROR.format('token cannot be empty'))

        if not jwt_bundle:
            raise ValueError(INVALID_INPUT_ERROR.format('jwt_bundle cannot be empty'))
        try:
            token_header = jwt.get_unverified_header(token)
            validator = JwtSvidValidator()
            validator.validate_header(token_header)
            signing_key = jwt_bundle.findJwtAuthority(token_header['kid'])
            claims = jwt.decode(
                token,
                algorithms=token_header['alg'],
                key=signing_key,
                audience=audience,
                options={
                    'verify_signature': True,
                    'verify_aud': True,
                    'verify_exp': True,
                },
            )
            # TODO:validate required claims
            spiffe_ID = SpiffeId.parse(claims['sub'])
            return JwtSvid(spiffe_ID, claims['aud'], claims['exp'], claims, token)
        except PyJWTError as err:
            raise InvalidTokenError(str(err))
