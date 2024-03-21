""""
(C) Copyright 2021 Hewlett Packard Enterprise Development LP

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

"""
This module defines the source for JWT Bundles and SVIDs.
"""

from abc import ABC, abstractmethod
from typing import Optional, Set


from pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from pyspiffe.spiffe_id.spiffe_id import TrustDomain
from pyspiffe.svid.jwt_svid import JwtSvid
from pyspiffe.spiffe_id.spiffe_id import SpiffeId


class JwtSource(ABC):
    """Source of JWT-SVIDs and JWT bundles maintained via the Workload API."""

    @abstractmethod
    def fetch_svid(self, audiences: Set[str], subject: Optional[SpiffeId]) -> JwtSvid:
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
        """Returns True if the connection to Workload API is closed."""
        pass
