"""
This module defines the source for JWT Bundles and SVIDs.
"""
from abc import ABC, abstractmethod
from typing import Optional


from pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from pyspiffe.spiffe_id.trust_domain import TrustDomain
from pyspiffe.svid.jwt_svid import JwtSvid


class JwtSource(ABC):
    """Source of JWT-SVIDs and JWT bundles maintained via the Workload API."""

    @abstractmethod
    def get_jwt_svid(self) -> JwtSvid:
        """Returns an JWT-SVID from the source."""
        pass

    @abstractmethod
    def get_bundle_for_trust_domain(
        self, trust_domain: TrustDomain
    ) -> Optional[JwtBundle]:
        """Returns the JWT bundle for the given trust domain."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Closes this JWTSource."""
        pass

    @abstractmethod
    def is_closed(self) -> bool:
        """Tests if the connection to Workload API is valid/open."""
        pass
