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

"""
JwtBundle module manages JwtBundle objects.
"""

import threading
from json import JSONDecodeError
from jwt.api_jwk import PyJWKSet
from jwt.exceptions import InvalidKeyError, PyJWKSetError
from typing import Dict, Union, Optional
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa, ed25519, ed448

from spiffe.spiffe_id.spiffe_id import TrustDomain
from spiffe.bundle.jwt_bundle.errors import JwtBundleError, ParseJWTBundleError
from spiffe.errors import ArgumentError

_PUBLIC_KEY_TYPES = Union[
    dsa.DSAPublicKey,
    rsa.RSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
]


class JwtBundle(object):
    """Represents a JWT Bundle.

    JwtBundle is a collection of trusted JWT public keys for a trust domain.
    """

    def __init__(
        self, trust_domain: TrustDomain, jwt_authorities: Dict[str, _PUBLIC_KEY_TYPES]
    ) -> None:
        """Creates a JwtBundle instance.

        Args:
            trust_domain: The TrustDomain to associate with the JwtBundle instance.
            jwt_authorities: A dictionary with key_id->PublicKey valid for the given TrustDomain.

        Raises:
            JWTBundleError: In case the trust_domain is empty.
        """
        self.lock = threading.Lock()

        if not trust_domain:
            raise JwtBundleError("Trust domain cannot be empty")

        self._trust_domain = trust_domain
        self._jwt_authorities = jwt_authorities.copy() if jwt_authorities else {}

    @property
    def trust_domain(self) -> TrustDomain:
        """Returns the trust domain of the bundle."""
        return self._trust_domain

    @property
    def jwt_authorities(self) -> Dict[str, _PUBLIC_KEY_TYPES]:
        """Returns a copy of JWT authorities in the bundle."""
        with self.lock:
            return self._jwt_authorities.copy()

    def get_jwt_authority(self, key_id: Optional[str]) -> Optional[_PUBLIC_KEY_TYPES]:
        """Returns the authority for the specified key_id.

        Args:
            key_id: Key id of the token to return the correspondent authority.

        Returns:
            The authority associated with the supplied key_id.
            None if the key_id is not found.

        Raises:
            ArgumentError: When key_id is not valid (empty or None).
        """
        if not key_id:
            raise ArgumentError('key_id cannot be empty')

        with self.lock:
            return self._jwt_authorities.get(key_id)

    @classmethod
    def parse(cls, trust_domain: TrustDomain, bundle_bytes: bytes) -> 'JwtBundle':
        """Parses a bundle from bytes. The data must be a standard RFC 7517 JWKS document.

        Args:
            trust_domain: A TrustDomain to associate to the bundle.
            bundle_bytes: An array of bytes that represents a set of JWKs.

        Returns:
            An instance of 'JWTBundle' with the JWT authorities associated to the given trust domain.

        Raises:
            ArgumentError: In case the trust_domain is empty or bundle_bytes is empty.
            ParseJWTBundleError: In case the set of jwt_authorities cannot be parsed from the bundle_bytes.
        """

        if not trust_domain:
            raise ArgumentError("Trust domain cannot be empty")

        if not bundle_bytes:
            raise ArgumentError('Bundle bytes cannot be empty')

        try:
            jwks = PyJWKSet.from_json(bundle_bytes.decode('utf-8'))

            jwt_authorities = {}
            for jwk in jwks.keys:
                if not jwk.key_id:
                    raise ParseJWTBundleError(
                        'Error adding authority from JWKS: "keyID" cannot be empty'
                    )

                jwt_authorities[jwk.key_id] = jwk.key

            return JwtBundle(trust_domain, jwt_authorities)
        except InvalidKeyError as err:
            raise ParseJWTBundleError(str(err)) from err
        except PyJWKSetError as err:
            if str(err) == "The JWK Set did not contain any keys":
                return JwtBundle(trust_domain, {})
            else:
                raise ParseJWTBundleError(
                    '"bundle_bytes" does not represent a valid jwks'
                ) from err
        except (JSONDecodeError, AttributeError) as err:
            raise ParseJWTBundleError(
                '"bundle_bytes" does not represent a valid jwks'
            ) from err

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, JwtBundle):
            return False
        with self.lock:
            return (
                self._trust_domain.__eq__(o._trust_domain)
                and self._jwt_authorities == o._jwt_authorities
            )

    def __hash__(self):
        trust_domain_hash = hash(self.trust_domain)
        authorities_hash = hash(tuple(hash(authority) for authority in self._jwt_authorities))
        return hash((trust_domain_hash, authorities_hash))
