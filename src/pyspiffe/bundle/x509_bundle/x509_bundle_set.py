"""
This module manages X509BundleSet objects.
"""
import copy
from typing import List, Optional, Dict

from pyspiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from pyspiffe.spiffe_id.trust_domain import TrustDomain

__all__ = ['X509Bundle']


class X509BundleSet(object):
    """X509BundleSet is a set of X509Bundles objects, keyed by trust domain."""

    def __init__(self, bundles_map: Dict[TrustDomain, X509Bundle]) -> None:
        """Creates a new initialized X509BundleSet with the given X509Bundle objects keyed by TrustDomain.

        Args:
            bundles_map: A map object of X509Bundle objects keyed by TrustDomain to initialize the X509BundleSet.
        """

        self._bundles = copy.copy(bundles_map)

    def put(self, bundle: X509Bundle) -> None:
        """Adds a new X509Bundle object or replace an existing one into the set.

        Args:
            bundle: The new X509Bundle to put into the set.
        """
        self._bundles[bundle.trust_domain()] = bundle

    def get_x509_bundle_for_trust_domain(
        self, trust_domain: TrustDomain
    ) -> Optional[X509Bundle]:
        """Returns the X509Bundle object for the given trust domain.

        Args:
            trust_domain: The TrustDomain to get an X509Bundle.

        Returns:
            A X509Bundle object for the given TrustDomain.
            None if the TrustDomain is not found in the set.
        """
        return self._bundles.get(trust_domain)

    @classmethod
    def of(cls, bundle_list: List[X509Bundle]) -> 'X509BundleSet':
        """Creates a new initialized X509BundleSet with the given X509Bundle objects keyed by TrustDomain.

        Args:
            bundle_list: A list X509Bundle objects to store in the new X509BundleSet.
        """
        bundles = {}
        for b in bundle_list:
            bundles[b.trust_domain()] = b

        return X509BundleSet(bundles)
