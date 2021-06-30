"""
This module defines the source for JWT Bundles and SVIDs.
"""
from abc import ABC, abstractmethod
from typing import Optional, Set


from pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from pyspiffe.spiffe_id.trust_domain import TrustDomain
from pyspiffe.svid.jwt_svid import JwtSvid
from pyspiffe.spiffe_id.spiffe_id import SpiffeId


class JwtSource(ABC):
    """Source of JWT-SVIDs and JWT bundles maintained via the Workload API."""

    @abstractmethod
    def get_jwt_svid(self, audiences: Set[str], subject: Optional[SpiffeId]) -> JwtSvid:
        """Returns an JWT-SVID from the source."""
        pass

    @abstractmethod
    def get_jwt_bundle(self, trust_domain: TrustDomain) -> Optional[JwtBundle]:
        """Returns the JWT bundle for the given trust domain."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Closes this JWTSource."""
        pass

    @abstractmethod
    def is_closed(self) -> bool:
        """Returns True if the connection to Workload API is closed."""
        pass
