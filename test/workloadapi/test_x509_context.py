""""
(C) Copyright 2021 Hewlett Packard Enterprise Development LP

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

import pytest

from pyspiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from pyspiffe.exceptions import ArgumentError
from pyspiffe.svid.x509_svid import X509Svid
from pyspiffe.workloadapi.x509_context import X509Context
from test.utils.utils import read_file_bytes

_TEST_CERTS_PATH = 'test/svid/x509svid/certs/{}'
_CHAIN = read_file_bytes(_TEST_CERTS_PATH.format('1-chain.der'))
_KEY = read_file_bytes(_TEST_CERTS_PATH.format('1-key.der'))
_SVID1 = X509Svid.parse_raw(_CHAIN, _KEY)
_SVID2 = X509Svid.parse_raw(_CHAIN, _KEY)
_BUNDLE_SET = X509BundleSet(None)


def test_default_svid():
    svids = [_SVID1, _SVID2]
    x509_context = X509Context(svids, _BUNDLE_SET)
    assert x509_context.default_svid == _SVID1


def test_x509_bundle_set():
    svids = [_SVID1, _SVID2]
    x509_context = X509Context(svids, _BUNDLE_SET)
    assert x509_context.x509_bundle_set == _BUNDLE_SET


def test_default_svid_emtpy_list():
    with pytest.raises(ArgumentError) as err:
        X509Context([], _BUNDLE_SET)

    assert str(err.value) == 'X.509 SVID list cannot be empty.'


def test_x509_svids():
    svids = [_SVID1, _SVID2]
    x509_context = X509Context(svids, _BUNDLE_SET)
    assert x509_context.x509_svids == svids
