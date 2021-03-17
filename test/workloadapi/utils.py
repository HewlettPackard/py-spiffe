from pyspiffe.proto.spiffe import workload_pb2_grpc
from concurrent import futures
from contextlib import contextmanager

import grpc


@contextmanager
def workload_api(cls):
    """Instantiate a WorkloadApi and return a stub for use in tests"""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    workload_pb2_grpc.add_SpiffeWorkloadAPIServicer_to_server(cls(), server)
    port = server.add_insecure_port('[::]:0')
    server.start()

    try:
        with grpc.insecure_channel('localhost:%d' % port) as channel:
            yield workload_pb2_grpc.SpiffeWorkloadAPIStub(channel)
    finally:
        server.stop(None)
