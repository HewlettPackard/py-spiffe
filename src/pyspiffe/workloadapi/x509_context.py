from typing import List

from pyspiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from pyspiffe.svid.x509_svid import X509Svid

__all__ = ['X509Context']


class X509Context(object):
    """
    Represents the X.509 materials that are fetched from the Workload API.

    Contains a list of X509Svid and a X509BundleSet.
    """

    def __init__(
        self, x509_svids: List[X509Svid], x509_bundle_set: X509BundleSet
    ) -> None:

        if x509_svids:
            self._x509_svids = x509_svids.copy()
        else:
            self._x509_svids = []

        self._x509_bundle_set = x509_bundle_set

    def default_svid(self):
        """
        Default returns the default X509-SVID (the first in the list).

        See the SPIFFE Workload API standard Section 5.3.
        (https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE_Workload_API.md#53-default-identity)
        """
        return self._x509_svids[0]

    def x509_svids(self):
        return self._x509_svids.copy()

    def x509_bundle_set(self):
        return self._x509_bundle_set
