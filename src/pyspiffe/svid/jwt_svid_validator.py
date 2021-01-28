import datetime
from calendar import timegm

from pyspiffe.svid.exceptions import (
    TokenExpiredError,
    InvalidClaimError,
    InvalidAlgorithmError,
    InvalidTypeError,
)

AUDIENCE_NOT_MATCH_ERROR = 'audience does not match expected value'
INVALID_INPUT_ERROR = 'Invalid input: {}.'


class JwtSvidValidator(object):
    """Performs validations on a given token checking compliance to SPIFFE specification.
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

    def __init__(self) -> None:
        pass

    """
    Validates token header by verifing if header specifies supported algortihms and token type.

    Args:
        header ({}): token header.

    Returns:
        None.

    Raises:
        ValueError: in case header is not specified.
        InvalidAlgorithmError: in case specified 'alg' is not supported as specified by the SPIFFE standard.
        InvalidTypeError: in case 'typ' is present in header but is not set to 'JWT' or 'JOSE'.
    """

    def validate_header(self, header: {}) -> None:
        if not header:
            raise ValueError(INVALID_INPUT_ERROR.format('header cannot be empty'))

        if header['alg'] not in self._supported_algorithms:
            raise InvalidAlgorithmError(header['alg'])
        try:
            if header['typ'] and header['typ'] not in self._supported_types:
                raise InvalidTypeError(header['typ'])
        except KeyError:
            pass

    """
    Validates payload for required claims (aud, exp, sub) - signature expiration and audience.

    Args:
        payload ({}): token playload.
        expected_audience(List): audience as a list of strings used to validate the 'aud' claim.

    Returns:
        None

    Raises:
        InvalidClaimError: in case a required claim is not present in payload or expected_audience is not a subset of audience_claim.
        TokenExpiredError: in case token is expired.
        ValueError: in case expected_audience is empty.
    """

    def validate_claims(self, payload: {}, expected_audience: []) -> None:
        try:
            for claim in self._required_claims:
                if not payload[claim]:
                    raise InvalidClaimError(claim)
            self._validate_exp(payload['exp'])
            self._validate_aud(payload['aud'], expected_audience)
        except KeyError as key_error:
            raise InvalidClaimError(key_error.args[0])

    ###
    ### Verifies token expiration.
    ### Note: If and when https://github.com/jpadilla/pyjwt/issues/599 is fixed, this can be simplified/removed.
    ### Raises:
    ###     TokenExpiredError: in case token is expired.
    ###
    def _validate_exp(self, expiration_date: str) -> None:
        expiration_date = int(expiration_date)
        utctime = timegm(datetime.datetime.utcnow().utctimetuple())
        if expiration_date < utctime:
            raise TokenExpiredError()

    ###
    ### Verifies if expected_audience is present in audience_claim. The aud claim MUST be present.
    ### Raises:
    ###     InvalidClaimError: in expected_audience is not a subset of audience_claim.
    ###     ValueError: in case expected_audience is empty.
    ###
    def _validate_aud(self, audience_claim: [], expected_audience: []) -> None:
        if not expected_audience:
            raise ValueError(
                INVALID_INPUT_ERROR.format('expected_audience cannot be empty')
            )

        if not audience_claim or all(aud == '' for aud in audience_claim):
            raise InvalidClaimError('audience_claim cannot be empty')

        if not all(aud in audience_claim for aud in expected_audience):
            raise InvalidClaimError(AUDIENCE_NOT_MATCH_ERROR)
