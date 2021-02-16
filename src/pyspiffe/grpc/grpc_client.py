from abc import ABC, abstractmethod
from grpc import Channel


class GrpcClient(ABC):
    @staticmethod
    @abstractmethod
    def insecure_channel(spiffe_socket: str) -> Channel:
        pass
