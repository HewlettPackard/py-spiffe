from pyspiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from pyspiffe.svid.x509_svid import X509Svid
from pyspiffe.workloadapi.x509_context import X509Context
from test.utils.utils import read_file_bytes

_TEST_CERTS_PATH = 'test/svid/x509svid/certs/{}'


def test_default_svid():
    chain_bytes = read_file_bytes(_TEST_CERTS_PATH.format('1-chain.der'))
    key_bytes = read_file_bytes(_TEST_CERTS_PATH.format('1-key.der'))

    default_svid = X509Svid.parse_raw(chain_bytes, key_bytes)
    other_svid = X509Svid.parse_raw(chain_bytes, key_bytes)

    svids = [default_svid, other_svid]
    bundle_set = X509BundleSet()

    x509_context = X509Context(svids, bundle_set)

    assert x509_context.default_svid() == default_svid


def test_x509_bundle_set():
    bundle_set = X509BundleSet()
    x509_context = X509Context(None, bundle_set)
    assert x509_context.x509_bundle_set() == bundle_set


def test_default_svid_emtpy_list():
    x509_context = X509Context(None, None)
    assert x509_context.default_svid() is None


def test_x509_svids():
    chain_bytes = read_file_bytes(_TEST_CERTS_PATH.format('1-chain.der'))
    key_bytes = read_file_bytes(_TEST_CERTS_PATH.format('1-key.der'))

    default_svid = X509Svid.parse_raw(chain_bytes, key_bytes)
    other_svid = X509Svid.parse_raw(chain_bytes, key_bytes)

    svids = [default_svid, other_svid]
    bundle_set = X509BundleSet()

    x509_context = X509Context(svids, bundle_set)

    assert x509_context.x509_svids() == svids
