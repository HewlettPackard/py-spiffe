from typing import List
from src.pyspiffe.spiffe_id.spiffe_id import SpiffeId


class JwtSvid(object):
    """
    Represents a SPIFFE X.509 SVID.

    Contains a SPIFFE ID, a private key and a chain of X.509 certificates.

    :param spiffe_id: SPIFFE ID of the X509-SVID.
    :param private_key: Audience is the intended recipients of JWT-SVID as present in the 'aud' claim.
    :param chain: Expiration time of JWT-SVID as present in 'exp' claim.
    """

    def __init__(self, spiffe_id: SpiffeId, private_key: str, chain: List[str]):
        self.spiffe_id = spiffe_id
        self.privateKey = private_key
        self.chain = chain
