
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from pyspiffe.exceptions import JwtSvidError

import datetime
from calendar import timegm
import jwt
from jwt import exceptions

EMPTY_TOKEN_ERROR = 'Token cannot be empty.'
INVALID_INPUT_ERROR = 'Invalid input {}.'
MISSING_X_ERROR = 'Token is missing {}.'
AUDIENCE_NOT_MATCH_ERROR = 'Audience does not match payload[aud] in Token.'
TOKEN_EXPIRED_ERROR = 'Token has expired.'


class JwtSvid(object):
    """
    Represents a SPIFFE JWT SVID as defined in the SPIFFE standard.
    See <a href="https://github.com/spiffe/spiffe/blob/master/standards/JWT-SVID.md">https://github.com/spiffe/spiffe/blob/master/standards/JWT-SVID.md</a>.
    """

    _required_claims = ['aud', 'exp', 'sub']

    def __init__(
        self, spiffeId: SpiffeId, audience: [], expiry: datetime, claims: {}, token: str
    ):
        self.spiffeId = spiffeId
        self.audience = audience
        self.expiry = expiry
        self.claims = claims
        self.token = token

    """
    Parses and validates a JWT-SVID token and returns an instance of a JwtSvid with a SPIFFE ID parsed from the 'sub', audience from 'aud', 
    and expiry from 'exp' claim. The JWT-SVID signature is not verified.
    
    Args:
        token(str): a token as a string that is parsed and validated
        param audience(List): audience as a list of strings used to validate the 'aud' claim
     
    Returns:
        an instance of JwtSvid with a SPIFFE ID parsed from the 'sub', audience from 'aud', and expiry
        from 'exp' claim.
    
    Raises:
        JwtSvidError:   when the token expired or the expiration claim is missing, or 
                        when the 'aud' has an audience that is not in the audience provided as parameter
        ValueError:     when the token is blank or cannot be parsed

    """

    @classmethod
    def parse_insecure(cls, token: str, audience: []) -> 'JwtSvid':
        if not token:
            raise ValueError(EMPTY_TOKEN_ERROR)

        claims = jwt.decode(token, options={'verify_signature': False})
        cls._validate_claims(claims, audience)
        spiffe_ID = SpiffeId.parse(claims['sub'])
        result = JwtSvid(spiffe_ID, claims['aud'], claims['exp'], claims, token)

        return result

    """ 
    **WIP**
    Parses and validates a JWT-SVID token and returns an instance of {@link JwtSvid}.
    
    The JWT-SVID signature is verified using the JWT bundle source.

    Args:
        token:               a token as a string that is parsed and validated
        jwt_bundle_source:   an implementation of a {@link JwtBundle} that provides the JWT authorities to
                                verify the signature
        audience:            a list of strings used to validate the 'aud' claim
    
    Returns:
        an instance of JwtSvid with a SPIFFE ID parsed from the 'sub', audience from 'aud', and expiry
        from 'exp' claim.
    
    Raises:
        JwtSvidError:           when the token expired or the expiration claim is missing,
                                when the algorithm is not supported, when the header 'kid' is missing,
                                when the signature cannot be verified, or
                                when the 'aud' claim has an audience that is not in the audience list
                                provided as parameter
        ValueError:             when the token is blank or cannot be parsed
        BundleNotFoundError:    if the bundle for the trust domain of the spiffe id from the 'sub'
                                cannot be found the jwt_bundle_source
        AuthorityNotFoundError: if the authority cannot be found in the bundle using the value from
                                the 'kid' header
    """

    @classmethod
    def parse_and_validate(
        cls, token: str, jwt_bundle: JwtBundle, audience: []
    ) -> 'JwtSvid':

        token_header = jwt.get_unverified_header(token)
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
                'require': cls._required_claims,
            },
        )

        spiffe_ID = SpiffeId.parse(claims['sub'])
        result = JwtSvid(spiffe_ID, claims['aud'], claims['exp'], claims, token)

        return result

    # If and when https://github.com/jpadilla/pyjwt/issues/599 is fixed, this can be simplified/removed.
    @classmethod
    def _validate_exp(cls, expiration_date: str) -> None:
        expiration_date = int(expiration_date)
        utctime = timegm(datetime.datetime.utcnow().utctimetuple())
        if expiration_date < utctime:
            raise JwtSvidError(TOKEN_EXPIRED_ERROR)

    ###
    ### Verifies if any item specified by audience is present in audience_clains.
    ### Raises:
    ###     JwtSvidError: in case none of the items specified by audience is present in audience_claims.
    ###
    @classmethod
    def _validate_aud(cls, audience_claim: [], expected_audience: []) -> None:
        if not audience_claim and not expected_audience:
            raise ValueError(
                INVALID_INPUT_ERROR.format(
                    'audience_claims and audience cannot be empty'
                )
            )
        try:
            if not any(aud in audience_claim for aud in expected_audience):
                raise JwtSvidError(AUDIENCE_NOT_MATCH_ERROR)
        except Exception:
            raise JwtSvidError(AUDIENCE_NOT_MATCH_ERROR)

    ###
    ### Validates payload for required claims (aud, exp, sub), signature expiration and audience.
    ###
    ### Raises:
    ###     JwtSvidError: in case a required claim is not present in payload, token is expired or aud claimm does not match audience parameter.
    ###
    @classmethod
    def _validate_claims(cls, payload: {}, audience: []) -> None:
        try:
            for claim in cls._required_claims:
                if not payload[claim]:
                    raise JwtSvidError(MISSING_X_ERROR.format(claim))
            cls._validate_exp(payload['exp'])
            cls._validate_aud(payload['aud'], audience)
        except KeyError as key_error:
            raise JwtSvidError(MISSING_X_ERROR.format(key_error.args[0]))
