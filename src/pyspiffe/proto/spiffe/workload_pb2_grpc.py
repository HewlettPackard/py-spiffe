# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

from . import workload_pb2 as workload__pb2


class SpiffeWorkloadAPIStub(object):
    """///////////////////////////////////////////////////////////////////////
    X509-SVID Profile
    ///////////////////////////////////////////////////////////////////////
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.FetchX509SVID = channel.unary_stream(
                '/SpiffeWorkloadAPI/FetchX509SVID',
                request_serializer=workload__pb2.X509SVIDRequest.SerializeToString,
                response_deserializer=workload__pb2.X509SVIDResponse.FromString,
                )
        self.FetchX509Bundles = channel.unary_stream(
                '/SpiffeWorkloadAPI/FetchX509Bundles',
                request_serializer=workload__pb2.X509BundlesRequest.SerializeToString,
                response_deserializer=workload__pb2.X509BundlesResponse.FromString,
                )
        self.FetchJWTSVID = channel.unary_unary(
                '/SpiffeWorkloadAPI/FetchJWTSVID',
                request_serializer=workload__pb2.JWTSVIDRequest.SerializeToString,
                response_deserializer=workload__pb2.JWTSVIDResponse.FromString,
                )
        self.FetchJWTBundles = channel.unary_stream(
                '/SpiffeWorkloadAPI/FetchJWTBundles',
                request_serializer=workload__pb2.JWTBundlesRequest.SerializeToString,
                response_deserializer=workload__pb2.JWTBundlesResponse.FromString,
                )
        self.ValidateJWTSVID = channel.unary_unary(
                '/SpiffeWorkloadAPI/ValidateJWTSVID',
                request_serializer=workload__pb2.ValidateJWTSVIDRequest.SerializeToString,
                response_deserializer=workload__pb2.ValidateJWTSVIDResponse.FromString,
                )


class SpiffeWorkloadAPIServicer(object):
    """///////////////////////////////////////////////////////////////////////
    X509-SVID Profile
    ///////////////////////////////////////////////////////////////////////
    """

    def FetchX509SVID(self, request, context):
        """Fetch X.509-SVIDs for all SPIFFE identities the workload is entitled to,
        as well as related information like trust bundles and CRLs. As this
        information changes, subsequent messages will be streamed from the
        server.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def FetchX509Bundles(self, request, context):
        """Fetch trust bundles and CRLs. Useful for clients that only need to
        validate SVIDs without obtaining an SVID for themself. As this
        information changes, subsequent messages will be streamed from the
        server.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def FetchJWTSVID(self, request, context):
        """///////////////////////////////////////////////////////////////////////
        JWT-SVID Profile
        ///////////////////////////////////////////////////////////////////////

        Fetch JWT-SVIDs for all SPIFFE identities the workload is entitled to,
        for the requested audience. If an optional SPIFFE ID is requested, only
        the JWT-SVID for that SPIFFE ID is returned.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def FetchJWTBundles(self, request, context):
        """Fetches the JWT bundles, formatted as JWKS documents, keyed by the
        SPIFFE ID of the trust domain. As this information changes, subsequent
        messages will be streamed from the server.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def ValidateJWTSVID(self, request, context):
        """Validates a JWT-SVID against the requested audience. Returns the SPIFFE
        ID of the JWT-SVID and JWT claims.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_SpiffeWorkloadAPIServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'FetchX509SVID': grpc.unary_stream_rpc_method_handler(
                    servicer.FetchX509SVID,
                    request_deserializer=workload__pb2.X509SVIDRequest.FromString,
                    response_serializer=workload__pb2.X509SVIDResponse.SerializeToString,
            ),
            'FetchX509Bundles': grpc.unary_stream_rpc_method_handler(
                    servicer.FetchX509Bundles,
                    request_deserializer=workload__pb2.X509BundlesRequest.FromString,
                    response_serializer=workload__pb2.X509BundlesResponse.SerializeToString,
            ),
            'FetchJWTSVID': grpc.unary_unary_rpc_method_handler(
                    servicer.FetchJWTSVID,
                    request_deserializer=workload__pb2.JWTSVIDRequest.FromString,
                    response_serializer=workload__pb2.JWTSVIDResponse.SerializeToString,
            ),
            'FetchJWTBundles': grpc.unary_stream_rpc_method_handler(
                    servicer.FetchJWTBundles,
                    request_deserializer=workload__pb2.JWTBundlesRequest.FromString,
                    response_serializer=workload__pb2.JWTBundlesResponse.SerializeToString,
            ),
            'ValidateJWTSVID': grpc.unary_unary_rpc_method_handler(
                    servicer.ValidateJWTSVID,
                    request_deserializer=workload__pb2.ValidateJWTSVIDRequest.FromString,
                    response_serializer=workload__pb2.ValidateJWTSVIDResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'SpiffeWorkloadAPI', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class SpiffeWorkloadAPI(object):
    """///////////////////////////////////////////////////////////////////////
    X509-SVID Profile
    ///////////////////////////////////////////////////////////////////////
    """

    @staticmethod
    def FetchX509SVID(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_stream(request, target, '/SpiffeWorkloadAPI/FetchX509SVID',
            workload__pb2.X509SVIDRequest.SerializeToString,
            workload__pb2.X509SVIDResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def FetchX509Bundles(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_stream(request, target, '/SpiffeWorkloadAPI/FetchX509Bundles',
            workload__pb2.X509BundlesRequest.SerializeToString,
            workload__pb2.X509BundlesResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def FetchJWTSVID(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/SpiffeWorkloadAPI/FetchJWTSVID',
            workload__pb2.JWTSVIDRequest.SerializeToString,
            workload__pb2.JWTSVIDResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def FetchJWTBundles(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_stream(request, target, '/SpiffeWorkloadAPI/FetchJWTBundles',
            workload__pb2.JWTBundlesRequest.SerializeToString,
            workload__pb2.JWTBundlesResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def ValidateJWTSVID(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/SpiffeWorkloadAPI/ValidateJWTSVID',
            workload__pb2.ValidateJWTSVIDRequest.SerializeToString,
            workload__pb2.ValidateJWTSVIDResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
