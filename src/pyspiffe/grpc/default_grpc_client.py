from pyspiffe.grpc.grpc_client import GrpcClient
from grpc import Channel
from grpc import insecure_channel as grpc_insecure_channel


class DefaultGrpcClient(GrpcClient):
    @staticmethod
    def insecure_channel(spiffe_socket: str) -> Channel:
        return grpc_insecure_channel(spiffe_socket)
