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
This module defines the interface of an X.509 Source.
"""

from abc import ABC, abstractmethod
from typing import Optional

from pyspiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from pyspiffe.spiffe_id.spiffe_id import TrustDomain
from pyspiffe.svid.x509_svid import X509Svid


class X509Source(ABC):
    """Source of X509-SVIDs and X.509 bundles maintained via the Workload API."""

    @abstractmethod
    def get_svid(self) -> X509Svid:
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
