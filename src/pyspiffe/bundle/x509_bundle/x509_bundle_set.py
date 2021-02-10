"""
This module manages X509BundleSet objects.
"""

from typing import Mapping
from pyspiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from pyspiffe.spiffe_id.trust_domain import TrustDomain


class X509BundleSet(object):
    """X509BundleSet is a set of X509Bundles objects, keyed by trust domain."""

    def __init__(self, bundles: Mapping[TrustDomain, X509Bundle]) -> None:
        """Creates a new initialized with the given bundles.

        Args:
            bundles: A set of bundles to initialize the X509BundleSet.

        """
        self._bundles = bundles

    def add(self, bundle: X509Bundle):
        """Adds a new bundle into the set.

        If a bundle already exists for the trust domain, the existing bundle is
        replaced.

        Args:
            bundle: The new X509Bundle to add.
        """
        raise Exception('not implemented.')

    def get_x509_bundle_for_trust_domain(self, trust_domain: TrustDomain) -> X509Bundle:
        """Returns the X509 bundle for the given trust domain.

        Args:
            trust_domain: The TrustDomain to get an X509Bundle.

        Returns:
            A X509Bundle for the given TrustDomain.
        """
        raise Exception('not implemented.')
