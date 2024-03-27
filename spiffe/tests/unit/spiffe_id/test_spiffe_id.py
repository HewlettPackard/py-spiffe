"""
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

from spiffe.spiffe_id.spiffe_id import SpiffeId, SpiffeIdError


@pytest.mark.parametrize(
    "id_str",
    [
        "spiffe://example.org",
        "spiffe://example.org/path/to/service",
        "spiffe://example.org/another/path",
        "spiffe://domain.test/a/b/c/d/e/f/g",
    ],
)
def test_spiffe_id_valid(id_str):
    spiffe_id = SpiffeId(id_str)
    assert str(spiffe_id) == id_str


@pytest.mark.parametrize(
    "id_str, expected_error",
    [
        ("", "Invalid SPIFFE ID: cannot be empty"),
        (
            "notspiffe://example.org",
            "Invalid SPIFFE ID 'notspiffe://example.org': does not start with 'spiffe://'",
        ),
        (
            "spiffe://",
            "Invalid SPIFFE ID 'spiffe://': Invalid trust domain: cannot be empty",
        ),
        (
            "spiffe://example.org?query=123",
            "Invalid SPIFFE ID 'spiffe://example.org?query=123': Invalid trust domain 'example.org?query=123': contains disallowed characters",
        ),
        (
            "spiffe://example.org/..",
            "Invalid SPIFFE ID 'spiffe://example.org/..': path segments '.' and '..' are not allowed",
        ),
        (
            "spiffe://example.org//service",
            "Invalid SPIFFE ID 'spiffe://example.org//service': path cannot contain empty segments",
        ),
        (
            "spiffe://example.org/service/",
            "Invalid SPIFFE ID 'spiffe://example.org/service/': path cannot contain empty segments",
        ),
        (
            "spiffe://example..org/path",
            "Invalid SPIFFE ID 'spiffe://example..org/path': Invalid trust domain 'example..org': cannot contain consecutive dots",
        ),
        (
            "spiffe://example-.org",
            "Invalid SPIFFE ID 'spiffe://example-.org': Invalid trust domain 'example-.org': contains disallowed characters",
        ),
    ],
)
def test_spiffe_id_invalid(id_str, expected_error):
    with pytest.raises(SpiffeIdError) as exc:
        SpiffeId(id_str)
    assert str(exc.value) == expected_error


@pytest.mark.parametrize(
    "id_str, trust_domain, path",
    [
        ("spiffe://example.org", "example.org", ""),
        ("spiffe://example.org/path/to/service", "example.org", "/path/to/service"),
    ],
)
def test_spiffe_id_components(id_str, trust_domain, path):
    spiffe_id = SpiffeId(id_str)
    assert spiffe_id.trust_domain._name == trust_domain
    assert spiffe_id._path == path


def test_spiffe_id_equality():
    id1 = SpiffeId("spiffe://example.org/path")
    id2 = SpiffeId("spiffe://example.org/path")
    assert id1 == id2
    # assert id1 == "spiffe://example.org/path"


def test_spiffe_id_inequality():
    id1 = SpiffeId("spiffe://example.org/path")
    id2 = SpiffeId("spiffe://example.org/different/path")
    assert id1 != id2
    assert id1 != "spiffe://example.org/different/path"


def test_spiffe_id_hash_equality():
    id1 = SpiffeId("spiffe://example.org/path")
    id2 = SpiffeId("spiffe://example.org/path")
    assert hash(id1) == hash(id2)


def test_spiffe_id_string_representation():
    id = SpiffeId("spiffe://example.org/path")
    assert str(id) == "spiffe://example.org/path"
