from pyspiffe.proto.spiffe import workload_pb2_grpc, workload_pb2

_TEST_CERTS_PATH = 'test/svid/x509svid/certs/{}'


class FakeWorkloadApi(workload_pb2_grpc.SpiffeWorkloadAPI):
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
        svid = workload_pb2.X509SVID()
        svid.spiffe_id = 'spiffe://example.org/service'
        chain_bytes = read_bytes(_TEST_CERTS_PATH.format('1-chain.der'))
        key_bytes = read_bytes(_TEST_CERTS_PATH.format('1-key.der'))
        svid.x509_svid = chain_bytes
        svid.x509_svid_key = key_bytes

        return iter([workload_pb2.X509SVIDResponse(svids=[svid])])

    # TODO: implement the rest of the WorkloadApi methods


def read_bytes(path):
    with open(path, 'rb') as file:
        return file.read()
