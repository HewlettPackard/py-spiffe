"""This module has utility pub/private key functions for testing usage.
"""

import jwt
import datetime
from calendar import timegm
from typing import Union, List
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa, ed25519, ed448


_PRIVATE_KEY_TYPES = Union[
    dsa.DSAPrivateKey,
    rsa.RSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
]


def get_keys_pems(private_key: _PRIVATE_KEY_TYPES):
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


def create_jwt(
    private_key_pem: str,
    kid: str,
    alg: str,
    audience: List[str],
    spiffe_id: str,
):
    """This function returns a JWT token for the specified parameters.

    Args:
        private_key_pem: A private_key_pem string to encode the token.
        kid: The key id to be set in the header's 'kid'.
        #TODO: search the best word
        alg: A string specifying the algorithm to use for encoding and to be set in header's 'alg'.
        audience: The audience list to be set to 'aud' claim.
        spiffe_id: The spiffe_id to be set to 'sub' claim.

    Returns:
        Returns the JWT token for the specified input.

    """
    expiry = timegm(
        (datetime.datetime.utcnow() + datetime.timedelta(hours=4)).utctimetuple()
    )
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
