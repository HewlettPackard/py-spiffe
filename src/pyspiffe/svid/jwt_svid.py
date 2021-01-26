from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from pyspiffe.svid.exceptions import (
    TokenExpiredError,
    InvalidClaimError,
    JwtSvidError,
    UnsupportedAlgorithmError,
    UnsupportedTypeError,
)
import datetime
from calendar import timegm
import jwt
from jwt import exceptions


EMPTY_TOKEN_ERROR = 'Token cannot be empty.'
INVALID_INPUT_ERROR = 'Invalid input {}.'
MISSING_X_ERROR = 'Token is missing {}.'
AUDIENCE_NOT_MATCH_ERROR = 'Audience does not match payload[aud] in Token.'
TOKEN_EXPIRED_ERROR = 'Token has expired.'
UNSUPPORTED_VALUE_ERROR = '{} is not supported.'


class JwtSvid(object):
    """
    Represents a SPIFFE JWT SVID as defined in the SPIFFE standard.
    See <a href="https://github.com/spiffe/spiffe/blob/master/standards/JWT-SVID.md">https://github.com/spiffe/spiffe/blob/master/standards/JWT-SVID.md</a>.
    """

    _required_claims = ['aud', 'exp', 'sub']
    _supported_algorithms = [
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
    _supported_types = ['JWT', 'JOSE']

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
        token_header = jwt.get_unverified_header(token)
        cls._validate_header(token_header)
        claims = jwt.decode(token, options={'verify_signature': False})
        cls._validate_claims(claims, audience)
        spiffe_ID = SpiffeId.parse(claims['sub'])
        result = JwtSvid(spiffe_ID, claims['aud'], claims['exp'], claims, token)

        return result

    """
    WIP
    Parses and validates a JWT-SVID token and returns an instance of JwtSvid.

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

    ###
    ### Verifies if header specifies supported algortihms.
    ### Raises:
    ###     UnsupportedAlgorithmError: in case alg specified in token is not supported.
    ###     ValueError: inc ase header is not specified.
    ###
    @classmethod
    def _validate_header(cls, header: {}) -> None:
        if not header or not header['alg']:
            raise ValueError(
                INVALID_INPUT_ERROR.format(
                    'header cannot be empty or alg must be specified'
                )
            )

        if header['alg'] not in cls._supported_algorithms:
            raise UnsupportedAlgorithmError(
                UNSUPPORTED_VALUE_ERROR.format(header['alg'])
            )
        try:
            if header['typ'] and header['typ'] not in cls._supported_types:
                raise UnsupportedTypeError(
                    UNSUPPORTED_VALUE_ERROR.format(header['typ'])
                )
        except KeyError:
            pass

    # If and when https://github.com/jpadilla/pyjwt/issues/599 is fixed, this can be simplified/removed.
    @classmethod
    def _validate_exp(cls, expiration_date: str) -> None:
        expiration_date = int(expiration_date)
        utctime = timegm(datetime.datetime.utcnow().utctimetuple())
        if expiration_date < utctime:
            raise TokenExpiredError(TOKEN_EXPIRED_ERROR)

    ###
    ### Verifies if expected_audience is present in audience_claim. The aud claim MUST be present.
    ### Raises:
    ###     InvalidClaimError: in expected_audience is not a subset of audience_claim.
    ###     ValueError: in case expected audience is empty
    ###
    @classmethod
    def _validate_aud(cls, audience_claim: [], expected_audience: []) -> None:
        if not expected_audience:
            raise ValueError(
                INVALID_INPUT_ERROR.format('expected_audience cannot be empty')
            )

        if not audience_claim or all(aud == '' for aud in audience_claim):
            raise InvalidClaimError(
                INVALID_INPUT_ERROR.format('audience_claim cannot be empty')
            )

        if not all(aud in audience_claim for aud in expected_audience):
            raise InvalidClaimError(AUDIENCE_NOT_MATCH_ERROR)

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
