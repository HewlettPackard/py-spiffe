"""
This module has utility pub/private key functions for testing suage
"""
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


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


def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    rsakeypem, rsapubpem = get_keys_pems(private_key)
    return rsakeypem, rsapubpem


def generate_ec_key_pair():
    key = ec.generate_private_key(ec.SECP384R1(), default_backend())

    rsakeypem, rsapubpem = get_keys_pems(key)
    return rsakeypem, rsapubpem


def save_to_file(path, private_pem, public_pem):
    with open(path + "/rsakey.pem", "wb") as f:
        f.write(private_pem)
    with open(path + "/rsapub.pem", "wb") as f:
        f.write(public_pem)
