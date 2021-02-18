"""
This module manages JwtBundleSet objects.
"""

from typing import Mapping
from pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from pyspiffe.spiffe_id.trust_domain import TrustDomain


class JwtBundleSet(object):
    """JwtBundleSet is a set of JWTBundles objects, keyed by trust domain."""

    def __init__(self, bundles: Mapping[TrustDomain, JwtBundle]) -> None:
        """Creates a new initialized with the given JWT bundles.

        Args:
            bundles: A set of JwtBundles to initialize the JwtBundleSet.

        """
        self._bundles = bundles
        pass

    def add(self, jwt_bundle: JwtBundle):
        """Adds a new bundle into the set.

        If a bundle already exists for the trust domain, the existing bundle is
        replaced.

        Args:
            jwt_bundle: The new JwtBundle to add.
        """
        raise Exception('not implemented.')

    def get_jwt_bundle_for_trust_domain(self, trust_domain: TrustDomain) -> JwtBundle:
        """Returns the JWT bundle of the given trust domain.

        Args:
            trust_domain: The TrustDomain to get a JwtBundle.

        Returns:
            A JwtBundle for the given TrustDomain.
        """
        raise Exception('not implemented.')
