from src.pyspiffe.spiffe_id.spiffe_id import SpiffeId
from src.pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
import datetime
from calendar import timegm
import jwt
from jwt import exceptions

EMPTY_TOKEN_ERROR = 'Token cannot be empty.'
MISSING_X_ERROR = "Token is missing {}."
AUDIENCE_NOT_MATCH_ERROR = "Audience does not match payload['aud'] in Token."


class JwtSvid(object):
    """
    Represents a SPIFFE JWT SVID as defined in the SPIFFE standard.
    See <a href="https://github.com/spiffe/spiffe/blob/master/standards/JWT-SVID.md">https://github.com/spiffe/spiffe/blob/master/standards/JWT-SVID.md</a>.

    :param _spiffeId:       SPIFFE ID as present in the 'sub' claim
    :param _audience:       identifies the recipients that the JWT is intended for, as present in the 'aud' claim
    :param _expiry:         identifies the expiration time on or after which the JWT MUST NOT be accepted for processing, as present in 'exp' claim
    :param _claims:         dictionary containing the parsed claims from token
    :param _token:          serialized JWT token
    """

    _required_claims = ['aud', 'exp', 'sub']

    def __init__(
        self, spiffeId: SpiffeId, audience: [], expiry: datetime, claims: {}, token: str
    ):
        self._spiffeId = spiffeId
        self._audience = audience
        self._expiry = expiry
        self._claims = claims
        self._token = token

    """
        Raises valueerror in case exp is not an interger
    """

    @classmethod
    def _validate_exp(cls, exp, now, interval):
        exp = int(exp)

        if exp < (now - interval):
            raise exception.ExpiredSignatureError("Token signature has expired.")

    @classmethod
    def _validate_aud(cls, audience_claims, audience):

        if audience is None:
            # Application did not specify an audience, but
            # the token has the 'aud' claim
            raise InvalidAudienceError("Invalid audience")

        if isinstance(audience_claims, str):
            audience_claims = [audience_claims]
        if not isinstance(audience_claims, list):
            raise ValueError("Invalid claim format in token.")
        if any(not isinstance(c, str) for c in audience_claims):
            raise ValueError("Invalid claim format in token.")

        if isinstance(audience, str):
            audience = [audience]

        if not any(aud in audience_claims for aud in audience):
            raise InvalidAudienceError("Invalid audience")

    @classmethod
    def _validate_claims(cls, payload: {}, audience: []) -> None:
        try:
            for claim in cls._required_claims:
                if payload.get(claim) is None:
                    raise ValueError(MISSING_X_ERROR.format(claim))

            now = timegm(datetime.utcnow().utctimetuple())
            """check if the interval is needed"""
            cls._validate_exp(payload['exp'], now, 0)
            cls._validate_aud(payload['aud'], audience)

        except KeyError as key_error:
            raise ValueError(MISSING_X_ERROR.format(key_error.args[0]))

    """
    Parses and validates JWT-SVID token and returns an instance of a {@link JwtSvid}. The JWT-SVID signature is not verified.
    
    Args:
        token(str): a token as a string that is parsed and validated
        audience(List): audience as a list of strings used to validate the 'aud' claim
    
    Returns:
        an instance of a {@link JwtSvid} with a SPIFFE ID parsed from the 'sub', audience from 'aud', and expiry
        from 'exp' claim.
    
    Raises:
        JwtSvidError:   when the token expired or the expiration claim is missing, or 
                        when the 'aud' has an audience that is not in the audience provided as parameter
        ValueError:     when the token is blank or cannot be parsed
    """

    @classmethod
    def parse_insecure(cls, token: str, audience: []) -> 'JwtSvid':
        if token is None or token == '':
            raise ValueError(EMPTY_TOKEN_ERROR)

        claims = jwt.decode(token, options={'verify_signature': False})
        cls._validate_claims(claims, audience)

        """
            TODO: I expect this will raise an exception in case it is not valdated
        """
        # spiffe_ID = SpiffeId.parse(claims['sub'])
        result = JwtSvid(spiffe_ID, claims['aud'], claims['exp'], claims, token)

        return result

    """ 
    Parses and validates a JWT-SVID token and returns an instance of {@link JwtSvid}.
    
    The JWT-SVID signature is verified using the JWT bundle source.

    Args:
        token:               a token as a string that is parsed and validated
        jwt_bundle_source:   an implementation of a {@link JwtBundle} that provides the JWT authorities to
                                verify the signature
        audience:            a list of strings used to validate the 'aud' claim
    
    Returns:
        an instance of {@link JwtSvid} with a SPIFFE ID parsed from the 'sub', audience from 'aud', and expiry
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
        if token is None or token == '':
            raise ValueError(EMPTY_TOKEN_ERROR)

        header = jwt.get_unverified_header(token)
        try:
            algorithm = header['alg']
            key_id = header['kid']
        except KeyError as key_error:
            raise ValueError(MISSING_X_ERROR.format(key_error.args[0]))

        signing_key = jwt_bundle.findJwtAuthority(key_id)

        claims = jwt.decode(
            token,
            algorithms=algorithm,
            key=signing_key,
            audience=audience,
            options={
                'verify_aud': True,
                'verify_exp': True,
                'require': cls._required_claims,
            },
        )

        # spiffe_ID = SpiffeId.parse(claims['sub'])

        result = JwtSvid(spiffe_ID, claims['aud'], claims['exp'], claims, token)

        return result
