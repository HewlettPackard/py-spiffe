"""
JwtBundle module manages JwtBundle objects.
"""
import threading
from json import JSONDecodeError
from jwt.api_jwk import PyJWKSet
from jwt.exceptions import InvalidKeyError
from typing import Dict, Union, Optional
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa, ed25519, ed448
from pyspiffe.spiffe_id.trust_domain import TrustDomain, EMPTY_DOMAIN_ERROR
from pyspiffe.bundle.jwt_bundle.exceptions import JwtBundleError, ParseJWTBundleError
from pyspiffe.exceptions import ArgumentError

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
            raise JwtBundleError(EMPTY_DOMAIN_ERROR)

        self._trust_domain = trust_domain
        self._jwt_authorities = jwt_authorities.copy() if jwt_authorities else {}

    def trust_domain(self) -> TrustDomain:
        """Returns the trust domain of the bundle."""
        return self._trust_domain

    def jwt_authorities(self) -> Dict[str, _PUBLIC_KEY_TYPES]:
        """Returns a copy of JWT authorities in the bundle."""
        with self.lock:
            return self._jwt_authorities.copy()

    def get_jwt_authority(self, key_id: str) -> Optional[_PUBLIC_KEY_TYPES]:
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
            raise ArgumentError(EMPTY_DOMAIN_ERROR)

        if not bundle_bytes:
            raise ArgumentError('Bundle bytes cannot be empty')

        try:
            jwks = PyJWKSet.from_json(bundle_bytes)
        except InvalidKeyError as ike:
            raise ParseJWTBundleError(
                'Cannot parse jwks from bundle_bytes: ' + str(ike)
            )
        except (JSONDecodeError, AttributeError):
            raise ParseJWTBundleError(
                'Cannot parse jwks. bundle_bytes does not represent a valid jwks'
            )

        jwt_authorities = {}
        for jwk in jwks.keys:
            if not jwk.key_id:
                raise ParseJWTBundleError(
                    'Error adding authority from JWKS: keyID cannot be empty'
                )

            jwt_authorities[jwk.key_id] = jwk.key

        return JwtBundle(trust_domain, jwt_authorities)
