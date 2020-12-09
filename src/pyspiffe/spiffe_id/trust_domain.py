class TrustDomain(object):
    """
    Represents the name of a SPIFFE trust domain (e.g. 'domain.test').

    :param trust_domain: The name of the Trust Domain
    """

    name: str

    def __init__(self, trust_domain: str):
        self.name = trust_domain
