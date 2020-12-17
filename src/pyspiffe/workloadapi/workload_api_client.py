from abc import ABC, abstractmethod

class WorkloadApiClient(ABC):
    """
    Abstract class definition for a SPIFFE Workload API Client.
    """

    @abstractmethod
    def fetch_x509_context(self):
        """
        Fetches an X.509 context on a one-shot blocking call.

        Fetch an instance of an X509Context containing the X.509
        materials fetched from the Workload API,

        Returns:

        X509Context (?? type): The X.509 context.
        """

    @abstractmethod
    def watch_x509_context(self, watcher):
        """
        Watches for X.509 context updates.

        A new Stream to the Workload API is opened for each call to
        this method, so that the client starts getting updates
        immediately after the Stream is ready and doesn't have to wait
        until the Workload API dispatches the next update based on the
        SVIDs TTL.

        Parameters:

        watcher (?? type): Watcher callback object.
        """

    @abstractmethod
    def fetch_jwt_svid(self, audiences, subject=None):
        """
        Fetches a SPIFFE JWT-SVID on one-shot blocking call.

        Parameters:

        audiences (set of String): Set of audiences for the JWT.
        subject (String) [Optional]: SPIFFE ID Subject for the JWT.

        Returns:

        JwtSvid: Instance of JwtSvid object
        """

    @abstractmethod
    def fetch_jwt_bundles(self):
        """
        Fetches the JWT bundles for JWT-SVID validation, keyed by trust
        domain.

        Returns:

        JwtBundleSet: Set of JwtBundle objects
        """

    @abstractmethod
    def validate_jwt_svid(self, token, audience):
        """
        Validates the JWT-SVID token. The parsed and validated JWT-SVID is
        returned.

        Parameters:

        token (String): JWT to validate.
        audience (String): Audience to validate against.

        Returns:

        JwtSvid: If the token and audience could be validated.
        """

    @abstractmethod
    def watch_jwt_bundles(self, watcher):
        """
        Watches for JWT bundles updates.

        Parameters:

        watcher (??): Watcher callback object.
        """
