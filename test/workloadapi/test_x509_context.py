from pyspiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from pyspiffe.svid.x509_svid import X509Svid
from pyspiffe.workloadapi.x509_context import X509Context
from test.utils.utils import read_file_bytes


_TEST_CERTS_PATH = 'test/svid/x509svid/certs/{}'
_CHAIN = read_file_bytes(_TEST_CERTS_PATH.format('1-chain.der'))
_KEY = read_file_bytes(_TEST_CERTS_PATH.format('1-key.der'))
_SVID1 = X509Svid.parse_raw(_CHAIN, _KEY)
_SVID2 = X509Svid.parse_raw(_CHAIN, _KEY)
_BUNDLE_SET = X509BundleSet()


def test_default_svid():
    svids = [_SVID1, _SVID2]
    x509_context = X509Context(svids, _BUNDLE_SET)
    assert x509_context.default_svid() == _SVID1


def test_x509_bundle_set():
    x509_context = X509Context(None, _BUNDLE_SET)
    assert x509_context.x509_bundle_set() == _BUNDLE_SET


def test_default_svid_emtpy_list():
    x509_context = X509Context(None, None)
    assert x509_context.default_svid() is None


def test_x509_svids():
    svids = [_SVID1, _SVID2]
    x509_context = X509Context(svids, _BUNDLE_SET)
    assert x509_context.x509_svids() == svids
