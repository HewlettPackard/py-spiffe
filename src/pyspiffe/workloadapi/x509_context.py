"""
This module provides an object for transferring X.509 SVID and Bundles materials.
"""
from typing import List, Optional

from pyspiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from pyspiffe.svid.x509_svid import X509Svid

__all__ = ['X509Context']


class X509Context(object):
    """Represents the X.509 materials that are fetched from the Workload API.

    Contains a list of X509Svid and a X509BundleSet.
    """

    def __init__(
        self, x509_svids: List[X509Svid], x509_bundle_set: X509BundleSet
    ) -> None:
        """Creates a new X509Context with a list of X509Svid object and a X509BundleSet.

        Args:
            x509_svids: A list of X509Svid objects.
            x509_bundle_set: An X509BundleSet object.
        """

        self._x509_svids = x509_svids.copy() if x509_svids else []
        self._x509_bundle_set = x509_bundle_set

    def default_svid(self) -> Optional[X509Svid]:
        """Returns the default X509-SVID (the first in the list).

        See the SPIFFE Workload API standard Section 5.3.
        (https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE_Workload_API.md#53-default-identity)

        Returns:
            The first X509Svid object in the list, None in case the X509Context has no objects in the X509Svid list.

        """
        return self._x509_svids[0] if self._x509_svids else None

    def x509_svids(self) -> List[X509Svid]:
        """Returns the list of X509Svid objects."""
        return self._x509_svids.copy()

    def x509_bundle_set(self) -> X509BundleSet:
        """Returns the X509BundleSet object."""
        return self._x509_bundle_set
