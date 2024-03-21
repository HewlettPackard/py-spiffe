from test.utils.utils import read_file_bytes

TEST_CERTS_PATH = 'test/svid/x509svid/certs/{}'
TEST_BUNDLE_PATH = 'test/bundle/x509bundle/certs/{}'
CHAIN1 = read_file_bytes(TEST_CERTS_PATH.format('1-chain.der'))
KEY1 = read_file_bytes(TEST_CERTS_PATH.format('1-key.der'))
CHAIN2 = read_file_bytes(TEST_CERTS_PATH.format('4-cert.der'))
KEY2 = read_file_bytes(TEST_CERTS_PATH.format('4-key.der'))
BUNDLE = read_file_bytes(TEST_BUNDLE_PATH.format('cert.der'))
FEDERATED_BUNDLE = read_file_bytes(TEST_BUNDLE_PATH.format('federated_bundle.der'))
CORRUPTED = read_file_bytes(TEST_CERTS_PATH.format('corrupted'))
