"""
This module has utility pub/private key functions for testing suage
"""
from cryptography.hazmat.primitives import serialization


def get_keys_pems(private_key):
    rsakeypem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key = private_key.public_key()

    rsapubpem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return rsakeypem, rsapubpem
