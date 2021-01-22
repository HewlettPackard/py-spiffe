from typing import Mapping
from pyspiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from pyspiffe.spiffe_id.trust_domain import TrustDomain


class X509BundleSet(object):
    bundles: Mapping[TrustDomain, X509Bundle]

    def new_set(
        self, bundles: Mapping[TrustDomain, X509Bundle]
    ) -> Mapping[TrustDomain, X509Bundle]:
        """
        NewSet creates a new, empty set.
        """
        raise Exception('not implemented')

    def add(self, bundle: X509Bundle):
        """
        Add adds a new bundle into the set. If a bundle already exists for the
        trust domain, the existing bundle is replaced.
        """
        raise Exception('not implemented')

    def get_jtw_bundle_for_trust_domain(self, trust_domain: TrustDomain) -> X509Bundle:
        """
        returns the JWT bundle of the given trust domain.
        """
        raise Exception('not implemented')
