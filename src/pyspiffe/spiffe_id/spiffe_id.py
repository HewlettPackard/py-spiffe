from src.pyspiffe.spiffe_id.trust_domain import TrustDomain


class SpiffeId(object):
    """
    Represents a SPIFFE ID as defined in the SPIFFE standard.
    see <a href="https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md">https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md</a>

    :param trust_domain: The trust domain corresponds to the trust root of a system.
    :param path: The path component
    """

    schema: str = 'spiffe'

    def __init__(self, trust_domain: TrustDomain, path: str):
        self.trust_domain = trust_domain
        self.path = path
