"""
JwtBundle module manages JwtBundle objects.
"""
import threading
from typing import Dict, Union, Optional
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa, ed25519, ed448

from pyspiffe.spiffe_id.trust_domain import TrustDomain, EMPTY_DOMAIN_ERROR
from pyspiffe.bundle.jwt_bundle.exceptions import JwtBundleError

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
        """
        self.lock = threading.Lock()

        if not trust_domain:
            raise JwtBundleError(EMPTY_DOMAIN_ERROR)

        self._trust_domain = trust_domain
        self._jwt_authorities = jwt_authorities.copy() if jwt_authorities else {}

    def trust_domain(self) -> TrustDomain:
        """Returns the trust domain of the bundle. """
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
            ValueError: When key_id is not valid (empty or None).
        """
        if not key_id:
            raise ValueError('key_id cannot be empty.')

        with self.lock:
            return self._jwt_authorities.get(key_id)
