"""
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
This module manages X509BundleSet objects.
"""

import threading
from typing import List, Optional, Dict, Set

from spiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from spiffe.spiffe_id.spiffe_id import TrustDomain

__all__ = ['X509BundleSet']


class X509BundleSet(object):
    """X509BundleSet is a set of X509Bundles objects, keyed by trust domain."""

    def __init__(self, bundles: Optional[Dict[TrustDomain, X509Bundle]]) -> None:
        """Creates a new X509BundleSet.

        When the bundles parameter is not provided, it creates an empty X509BundleSet.
        When the bundles dictionary parameter is provided, the new X509BundleSet is initialized
        with the X509Bundle objects keyed by TrustDomain.

        Args:
            bundles: A dict object of X509Bundle objects keyed by TrustDomain to initialize the X509BundleSet. Default: None.
        """

        self.lock = threading.Lock()
        self._bundles: Dict[str, X509Bundle] = {}

        if bundles:
            for trust_domain, bundle in bundles.items():
                self._bundles[trust_domain.name] = bundle

    def get_bundle_for_trust_domain(self, trust_domain: TrustDomain) -> Optional[X509Bundle]:
        """Returns the X509Bundle object for the given trust domain.

        Args:
            trust_domain: The TrustDomain to get an X509Bundle.

        Returns:
            A X509Bundle object for the given TrustDomain.
            None if the TrustDomain is not found in the set.
        """
        with self.lock:
            return self._bundles.get(trust_domain.name)

    @property
    def bundles(self) -> Set[X509Bundle]:
        """Returns the set of all X509Bundles."""
        with self.lock:
            return set(self._bundles.values())

    def put(self, bundle: X509Bundle) -> None:
        """Adds a new X509Bundle object or replace an existing one into the set.

        Args:
            bundle: The new X509Bundle to put into the set.
        """
        with self.lock:
            self._bundles[bundle.trust_domain.name] = bundle

    @classmethod
    def of(cls, bundle_list: List[X509Bundle]) -> 'X509BundleSet':
        """Creates a new initialized X509BundleSet with the given X509Bundle objects keyed by TrustDomain.

        Args:
            bundle_list: A list X509Bundle objects to store in the new X509BundleSet.
        """
        bundles = {}
        for b in bundle_list:
            bundles[b.trust_domain] = b

        return X509BundleSet(bundles)
