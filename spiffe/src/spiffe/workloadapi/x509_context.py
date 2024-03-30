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
This module provides an object for transferring X.509 SVID and Bundles materials.
"""

from typing import List

from spiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from spiffe.errors import ArgumentError
from spiffe.svid.x509_svid import X509Svid


class X509Context(object):
    """Represents the X.509 materials that are fetched from the Workload API.

    Contains a list of X509Svid and a X509BundleSet.
    """

    def __init__(self, x509_svids: List[X509Svid], x509_bundle_set: X509BundleSet) -> None:
        """Creates a new X509Context with a list of X509Svid object and a X509BundleSet.

        Args:
            x509_svids: A list of X509Svid objects.
            x509_bundle_set: An X509BundleSet object.
        """

        if not x509_svids:
            raise ArgumentError('X.509 SVID list cannot be empty')

        self._x509_svids = x509_svids.copy() if x509_svids else []
        self._x509_bundle_set = x509_bundle_set

    @property
    def default_svid(self) -> X509Svid:
        """Returns the default X509-SVID (the first in the list).

        See the SPIFFE Workload API standard Section 5.3.
        (https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md#53-default-identity)

        Returns:
            The first X509Svid object in the list, None in case the X509Context has no objects in the X509Svid list.

        """
        return self._x509_svids[0]

    @property
    def x509_svids(self) -> List[X509Svid]:
        """Returns the list of X509Svid objects."""
        return self._x509_svids.copy()

    @property
    def x509_bundle_set(self) -> X509BundleSet:
        """Returns the X509BundleSet object."""
        return self._x509_bundle_set
