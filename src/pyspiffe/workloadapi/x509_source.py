"""
This module defines the interface of an X.509 Source.
"""
from abc import ABC, abstractmethod
from typing import Optional

from pyspiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from pyspiffe.spiffe_id.trust_domain import TrustDomain
from pyspiffe.svid.x509_svid import X509Svid


class X509Source(ABC):
    """Source of X509-SVIDs and X.509 bundles maintained via the Workload API."""

    @abstractmethod
    def get_x509_svid(self) -> X509Svid:
        """Returns an X509-SVID from the source."""
        pass

    @abstractmethod
    def get_bundle_for_trust_domain(
        self, trust_domain: TrustDomain
    ) -> Optional[X509Bundle]:
        """Returns the X.509 bundle for the given trust domain."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Closes this X509Source."""
        pass
