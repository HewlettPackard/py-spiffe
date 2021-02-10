"""
This module manages X509Svid objects.
"""

from typing import Mapping, Set
from datetime import datetime
from pyspiffe.spiffe_id.spiffe_id import SpiffeId


class X509Svid(object):
    """Represents a SPIFFE X509 SVID."""

    def __init__(
        self,
        spiffe_id: SpiffeId,
        audience: Set[str],
        expiry: datetime,
        claims: Mapping[str, object],
        token: str,
    ):
        """Creates a new X509Svid Object.

        Args:
            spiffe_id: SPIFFE ID of the JWT-SVID as present in the 'sub' claim.
            audience: Audience is the intended recipients of JWT-SVID as present in the 'aud' claim.
            expiry: Expiration time of JWT-SVID as present in 'exp' claim.
            claims: Parsed claims from token.
            token: Serialized JWT token.
        """
        self.spiffe_id = spiffe_id
        self.audience = audience
        self.expiry = expiry
        self.claims = claims
        self.token = token
