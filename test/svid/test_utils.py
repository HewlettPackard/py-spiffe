"""
This module has utility pub/private key functions for testing usage.
"""
import jwt
import datetime
from calendar import timegm
from typing import List
from pyspiffe.utils.certificate_utils import PRIVATE_KEY_TYPES
from pyspiffe.spiffe_id.trust_domain import TrustDomain
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def get_keys_pems(private_key: PRIVATE_KEY_TYPES):
    """This function returns private and public pem byte strings for the given private_key.

    Args:
        private_key: A private_key object.

    Returns:
        Returns the private key pem byte string and public key pem byte string of the provided private_key.

    """
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key = private_key.public_key()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_key_pem, public_key_pem


DEFAULT_TRUST_DOMAIN = TrustDomain('test.com')
"""Default Trust Domain to be used when creating a default test JWT. Trust Domain=test.com/"""

DEFAULT_SPIFFE_ID = 'spiffe://test.com/'
"""Default SPIFFE ID to be used when creating a default test JWT. SPIFFE ID=spiffe://test.com/"""

DEFAULT_ALG = 'RS256'
"""Default algorithm to be used when creating a default test JWT. Alg=RS256."""

DEFAULT_KEY_ID = 'kid1'
"""Default Key ID to be used when creating a default test JWT. kid=kid1."""

DEFAULT_AUDIENCE: List[str] = ['spire', 'test', 'valid']
"""Default audience to be used when creating a default test JWT. Audience=['spire', 'test', 'valid']."""

DEFAULT_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
"""Default Key to be used when creating a default test JWT. An RSA key"""

DEFAULT_KEY_PEM = get_keys_pems(DEFAULT_KEY)[0]

DEFAULT_EXPIRY = timegm(
    (datetime.datetime.utcnow() + datetime.timedelta(hours=4)).utctimetuple()
)
"""Default expiration time to be used when creating a default test JWT. Exp is set to four hours from now."""


def create_jwt(
    private_key_pem: str = DEFAULT_KEY_PEM,
    kid: str = DEFAULT_KEY_ID,
    alg: str = DEFAULT_ALG,
    audience: List[str] = None,
    spiffe_id: str = DEFAULT_SPIFFE_ID,
    expiry: int = DEFAULT_EXPIRY,
):
    """Helper function that returns a JWT token for the specified parameters.

    Calling create_jwt() without any parameter creates a default JWT using:
    a default RSA Key, 'kid1' as kid, 'RS256' as alg, ['spire', 'test', 'valid'] as aud,
    spiffe://test.com/ as SPIFFE ID and a 4 hours period of validity.

    Args:
        private_key_pem: A private_key_pem string to encode the token.
        kid: The key id to be set in the header's 'kid'.
        alg: A string specifying the algorithm to use for encoding and to be set in header's 'alg'.
        audience: The audience list to be set to 'aud' claim.
        spiffe_id: The spiffe_id to be set to 'sub' claim.
        expiry: The expiration date for the token.

    Returns:
        Returns the JWT token for the specified input.

    """
    audience = audience if audience else DEFAULT_AUDIENCE

    token = jwt.encode(
        {
            'aud': audience,
            'sub': spiffe_id,
            'exp': expiry,
        },
        algorithm=alg,
        key=private_key_pem,
        headers={'alg': alg, 'typ': 'JWT', 'kid': kid},
    )
    return token
