"""
(C) Copyright 2021 Hewlett Packard Enterprise Development LP

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

from pathlib import Path

from utils.utils import read_file_bytes

"""
Testing Utilities for Keys and JWT Tokens

This module provides utility functions to work with public/private keys and generate JWT tokens for testing purposes.
"""

import jwt
import datetime
from calendar import timegm
from typing import Set
from pyspiffe.utils.certificate_utils import PRIVATE_KEY_TYPES
from pyspiffe.spiffe_id.spiffe_id import TrustDomain
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

TEST_JWKS_DIR = Path(__file__).parent / 'jwks'
JWKS_1_EC_KEY = read_file_bytes(TEST_JWKS_DIR / 'jwks_1_ec_key.json')
JWKS_2_EC_1_RSA_KEYS = read_file_bytes(TEST_JWKS_DIR / 'jwks_3_keys.json')
JWKS_MISSING_KEY_ID = read_file_bytes(TEST_JWKS_DIR / 'jwks_missing_kid.json')
JWKS_MISSING_X = read_file_bytes(TEST_JWKS_DIR / 'jwks_ec_missing_x.json')


def extract_key_pair_pems(private_key: PRIVATE_KEY_TYPES):
    """
    Extracts PEM-formatted byte strings of a private key and its corresponding public key.

    Args:
        private_key: An object representing a private key.

    Returns:
        A tuple containing two byte strings: the private key PEM and the public key PEM.
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


TEST_TRUST_DOMAIN = TrustDomain('test.com')
TEST_SPIFFE_ID = 'spiffe://test.com'
TEST_ALG = 'RS256'
TEST_KEY_ID = 'kid1'
TEST_AUDIENCE = {'joe', 'test', 'other'}
TEST_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
TEST_KEY_PEM = extract_key_pair_pems(TEST_KEY)[0]
TEST_EXPIRY = timegm(
    (
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=4)
    ).utctimetuple()
)


def generate_test_jwt_token(
    private_key_pem: str = TEST_KEY_PEM,
    kid: str = TEST_KEY_ID,
    alg: str = TEST_ALG,
    audience: Set[str] = None,
    spiffe_id: str = TEST_SPIFFE_ID,
    expiry: int = TEST_EXPIRY,
):
    """
    Generates a JWT token for testing with specified or default parameters.

    This function facilitates the creation of JWT tokens with flexible parameters or default values.

    Args:
        private_key_pem: The PEM-formatted private key for signing the token.
        kid: The key ID to include in the JWT header.
        alg: The algorithm to use for signing the token.
        audience: A set of audiences intended to receive the token.
        spiffe_id: The SPIFFE ID to use as the subject of the token.
        expiry: The expiry time of the token in UNIX timestamp format.

    Returns:
        The generated JWT token as a string.
    """
    audience = audience if audience else TEST_AUDIENCE

    token = jwt.encode(
        {
            'aud': list(audience),
            'sub': spiffe_id,
            'exp': expiry,
        },
        algorithm=alg,
        key=private_key_pem,
        headers={'alg': alg, 'typ': 'JWT', 'kid': kid},
    )
    return token
