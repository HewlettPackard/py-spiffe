from typing import Mapping
from .jwt_bundle import JwtBundle
from src.pyspiffe.spiffe_id.trust_domain import TrustDomain


class JwtBundleSet(object):
    bundles: Mapping[TrustDomain, JwtBundle]

    def new_set(
        self, bundles: Mapping[TrustDomain, JwtBundle]
    ) -> Mapping[TrustDomain, JwtBundle]:
        """
        NewSet creates a new, empty set.
        """
        raise Exception('not implemented')

    def add(self, bundle: JwtBundle):
        """
        Add adds a new bundle into the set. If a bundle already exists for the
        trust domain, the existing bundle is replaced.
        """
        raise Exception('not implemented')

    def get_jtw_bundle_for_trust_domain(self, trust_domain: TrustDomain) -> JwtBundle:
        """
        returns the JWT bundle of the given trust domain.
        """
        raise Exception('not implemented')
