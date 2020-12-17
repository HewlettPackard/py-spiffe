from pyspiffe.workloadapi.workload_api_client import WorkloadApiClient
from pyspiffe.internal.defaults import Defaults

class DefaultWorkloadApiClient(WorkloadApiClient):
    """
    Default implementation for a SPIFFE Workload API Client.
    """

    # TODO: Not sure we need all the arguments, see newClient()
    def __init__(self, spiffe_socket_path=None, exponential_backoff_policy=None,
                 executor_service=None):

        if spiffe_socket_path == None:
            self.spiffe_socket_path=Defaults.spiffe_socket_path
        else:
            self.spiffe_socket_path=spiffe_socket_path

        # TODO defaults for these, or delete them entirely
        self.exponential_backoff_policy=exponential_backoff_policy
        self.executor_service=executor_service


    # TODO: Is this pythonic? Any benefit of this being a factory object vs
    # just using the constructor?
    @classmethod
    def new_client(cls, spiffe_socket_path=None, exponential_backoff_policy=None,
                  executor_service=None):
        """
        Create a new Workload API Client.

        Parameters:

        spiffeSocketPath (String) [optional]: Path to Workload API UDS.
        exponentialBackoffPolicy (?? Type): Custom backoff policy instance. Do we need?
        executorService (?? Type): Custom gRPC executor. Do we need?

        Returns:

        DefaultWorkloadApiClient: New Workload API Client object.
        """

        return cls(spiffe_socket_path=spiffe_socket_path,
                   exponential_backoff_policy=exponential_backoff_policy,
                   executor_service=executor_service)


    def fetch_x509_context(self):
        """
        Fetches an X.509 context on a one-shot blocking call.

        Fetch an instance of an X509Context containing the X.509
        materials fetched from the Workload API,

        Returns:

        X509Context: The X.509 context.
        """

        pass


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

        pass


    def fetch_jwt_svid(self, audiences, subject=None):
        """
        Fetches a SPIFFE JWT-SVID on one-shot blocking call.

        Parameters:

        audiences (set of String): Set of audiences for the JWT.
        subject (String) [Optional]: SPIFFE ID Subject for the JWT.

        Returns:

        JwtSvid: Instance of JwtSvid object
        """

        pass


    def fetch_jwt_bundles(self):
        """
        Fetches the JWT bundles for JWT-SVID validation, keyed by trust
        domain.

        Returns:

        JwtBundleSet: Set of JwtBundle objects
        """

        pass


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

        pass


    def watch_jwt_bundles(self, watcher):
        """
        Watches for JWT bundles updates.

        Parameters:

        watcher (??): Watcher callback object.
        """

        pass

