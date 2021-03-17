from pyspiffe.proto.spiffe import workload_pb2_grpc, workload_pb2


class FakeWorkloadApiEmptyResponse(workload_pb2_grpc.SpiffeWorkloadAPI):
    def FetchX509SVID(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        insecure=False,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return iter([workload_pb2.X509SVIDResponse(svids=[])])

    # TODO: implement the rest of the WorkloadApi methods


class FakeWorkloadApiInvalidResponse(workload_pb2_grpc.SpiffeWorkloadAPI):
    def FetchX509SVID(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        insecure=False,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        return iter([])

    # TODO: implement the rest of the WorkloadApi methods


class FakeWorkloadApiRaiseException(workload_pb2_grpc.SpiffeWorkloadAPI):
    def FetchX509SVID(
        request,
        target,
        options=(),
        channel_credentials=None,
        call_credentials=None,
        insecure=False,
        compression=None,
        wait_for_ready=None,
        timeout=None,
        metadata=None,
    ):
        raise ValueError('testing exception')

    # TODO: implement the rest of the WorkloadApi methods
