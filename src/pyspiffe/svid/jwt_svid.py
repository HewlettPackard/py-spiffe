from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle

import jwt


class JwtSvid(object):
    """
    Represents a SPIFFE JWT SVID.
    TODO: check pep8 sobre como nomear métodos e fazer comentários
    conversar com Max L sobre esse Bundle source
    """

    def __init__(
        self, spiffeId: SpiffeId, audience: [], expiry: str, claims: {}, token: str
    ):
        self.spiffeId = spiffeId
        self.audience = audience
        self.expiry = expiry
        self.claims = claims
        self.token = token

    """
    Parses and validates a JWT-SVID token and returns an instance of {@link JwtSvid}.
    <p>
    The JWT-SVID signature is verified using the JWT bundle source.
    
    token           a token as a string that is parsed and validated
    jwtBundleSource an implementation of a {@link JwtBundle} that provides the JWT authorities to
                            verify the signature
    audience        audience as a list of strings used to validate the 'aud' claim
    
    @return an instance of a {@link JwtSvid} with a SPIFFE ID parsed from the 'sub', audience from 'aud', and expiry
    from 'exp' claim.
    @throws JwtSvidException when the token expired or the expiration claim is missing,
                                            when the algorithm is not supported, when the header 'kid' is missing,
                                            when the signature cannot be verified, or
                                            when the 'aud' claim has an audience that is not in the audience list
                                            provided as parameter
    @throws IllegalArgumentException          when the token is blank or cannot be parsed
    @throws BundleNotFoundException           if the bundle for the trust domain of the spiffe id from the 'sub'
    cannot be found
                                            in the JwtBundleSource
    @throws AuthorityNotFoundException        if the authority cannot be found in the bundle using the value from
    the 'kid' header
    
    """

    @staticmethod
    def parse_and_validate(
        token: str, jwtBundleSource: JwtBundle, audience: []
    ) -> 'JwtSvid':
        return None

    """/**
    Parses and validates a JWT-SVID token and returns an instance of a {@link JwtSvid}.
    <p>
    The JWT-SVID signature is not verified.
    
    @param token    a token as a string that is parsed and validated
    @param audience audience as a list of strings used to validate the 'aud' claim
    @return an instance of a {@link JwtSvid} with a SPIFFE ID parsed from the 'sub', audience from 'aud', and expiry
    from 'exp' claim.
    @throws JwtSvidException when the token expired or the expiration claim is missing, or when
    *                                           the 'aud' has an audience that is not in the audience provided as parameter
    @throws IllegalArgumentException          when the token cannot be parsed
    """

    @staticmethod
    def parse_insecure(token: str, audience: []) -> 'JwtSvid':
        return None
