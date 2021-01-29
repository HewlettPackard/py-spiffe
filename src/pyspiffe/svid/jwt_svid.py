import jwt
import datetime
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from pyspiffe.svid.jwt_svid_validator import JwtSvidValidator


INVALID_INPUT_ERROR = 'Invalid input: {}.'


class JwtSvid(object):
    """
    Represents a SPIFFE JWT SVID as defined in the SPIFFE standard.
    See <a href="https://github.com/spiffe/spiffe/blob/master/standards/JWT-SVID.md">https://github.com/spiffe/spiffe/blob/master/standards/JWT-SVID.md</a>.

    Attributes:
        spiffeId (SpiffeId): token spiffeId.
        audience (List): audience claim.
        expiry (datetime): date and time in UTC specifing expiry date.
        claims (Dictionary): key-value pairs with all the claims present in the token.
        token (str): encoded token.
    """

    def __init__(
        self, spiffeId: SpiffeId, audience: [], expiry: datetime, claims: {}, token: str
    ) -> None:
        self.spiffeId = spiffeId
        self.audience = audience
        self.expiry = expiry
        self.claims = claims
        self.token = token

    """
    Parses and validates a JWT-SVID token and returns an instance of a JwtSvid with a SPIFFE ID parsed from the 'sub', audience from 'aud',
    and expiry from 'exp' claim. The JWT-SVID signature is not verified.

    Args:
        token(str): a token as a string that is parsed and validated.
        param audience(List): audience as a list of strings used to validate the 'aud' claim.

    Returns:
        an instance of JwtSvid with a SPIFFE ID parsed from the 'sub', audience from 'aud', and expiry
        from 'exp' claim.

    Raises:
        ValueError: when the token is blank or cannot be parsed, in case header is not specified,
        InvalidAlgorithmError: in case specified 'alg' is not supported as specified by the SPIFFE standard.
        InvalidTypeError: in case 'typ' is present in header but is not set to 'JWT' or 'JOSE'.
        InvalidClaimError: in case a required claim is not present in payload or expected_audience is not a subset of audience_claim.
        TokenExpiredError: in case token is expired.
        ValueError: in case expected_audience is empty or if the string spiffe_id doesn't comply the SPIFFE standard.
    """

    @classmethod
    def parse_insecure(cls, token: str, expected_audience: []) -> 'JwtSvid':
        if not token:
            raise ValueError(INVALID_INPUT_ERROR.format('token cannot be empty'))
        token_header = jwt.get_unverified_header(token)
        validator = JwtSvidValidator()
        validator.validate_header(token_header)
        claims = jwt.decode(token, options={'verify_signature': False})
        validator.validate_claims(claims, expected_audience)
        spiffe_ID = SpiffeId.parse(claims['sub'])
        result = JwtSvid(spiffe_ID, claims['aud'], claims['exp'], claims, token)

        return result

    """
    WIP
    Parses and validates a JWT-SVID token and returns an instance of JwtSvid.

    The JWT-SVID signature is verified using the JWT bundle source.

    Args:
        token (str): a token as a string that is parsed and validated.
        jwt_bundle (JwtBundle): an implementation of a {@link JwtBundle} that provides the JWT authorities to verify the signature.
        audience (List): a list of strings used to validate the 'aud' claim.

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
