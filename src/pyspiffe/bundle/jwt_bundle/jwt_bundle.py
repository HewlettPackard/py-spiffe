"""
JwtBundle module manages JwtBundle objects.
"""
from pyspiffe.bundle.jwt_bundle.exceptions import AuthorityNotFoundError
from pyspiffe.spiffe_id.trust_domain import TrustDomain
from typing import Dict, Union
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa, ed25519, ed448

_PUBLIC_KEY_TYPES = Union[
    dsa.DSAPublicKey,
    rsa.RSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
]


class JwtBundle(object):
    """Represents a JWT Bundle.

    JwtBundle is a collection of trusted JWT public keys for a trust domain
    """

    def __init__(
        self, trust_domain: TrustDomain, jwt_authorities: Dict[str, _PUBLIC_KEY_TYPES]
    ) -> None:
        """Creates a JwtBundle instance.

        Args:
            trust_domain: The TrustDomain to associate with the JwtBundle instance.
            jwt_authorities: A dictionay with key_id->PublicKey valid for the given TrustDomain.
        """
        self.trust_domain = trust_domain
        self.jwt_authorities = jwt_authorities

    def find_jwt_authority(self, key_id: str) -> _PUBLIC_KEY_TYPES:
        """Returns the authority for the specified key_id.

        Args:
            key_id: Key id of the token to return the correspondent authority.

        Returns:
            The authority assocaited with the supplied key_id.

        Raises:
            AuthorityNotFoundError: When no authority is found associated to the given key_id.
        """
        if not key_id:
            raise ValueError('key_id cannot be empty.')

        key = self.jwt_authorities.get(key_id, None)
        if not key:
            raise AuthorityNotFoundError(key_id)
        return key
