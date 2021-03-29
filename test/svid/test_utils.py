"""
This module has utility pub/private key functions for testing suage
"""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa, ed25519, ed448
from typing import Union

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
        Returns the private key pem byte string and public key byte string of the provided private_key.

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
