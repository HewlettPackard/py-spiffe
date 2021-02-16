from pyspiffe.grpc.default_grpc_client import DefaultGrpcClient


def test_instantiate():
    channel = DefaultGrpcClient.insecure_channel(spiffe_socket='gonzo')
    channel.close()
