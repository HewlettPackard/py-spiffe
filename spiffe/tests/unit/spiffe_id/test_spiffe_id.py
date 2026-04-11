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
        "spiffe://1.2.3.4/service",
        "spiffe://a",
        "spiffe://a_b.example/foo",
        "spiffe://example.org/foo-bar",
        "spiffe://example.org/foo_bar",
        "spiffe://example.org/foo.bar",
        "spiffe://example.com/9eebccd2-12bf-40a6-b262-65fe0487d453",
        "spiffe://example..org/path",
        "spiffe://.example.org/path",
        "spiffe://example.org./path",
        "spiffe://-example.org/path",
        "spiffe://example-.org/path",
    ],
)
def test_spiffe_id_valid(id_str: str) -> None:
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
            "spiffe://user@example.org/service",
            "Invalid SPIFFE ID 'spiffe://user@example.org/service': Invalid trust domain 'user@example.org': contains disallowed characters",
        ),
        (
            "spiffe://user:pass@example.org/service",
            "Invalid SPIFFE ID 'spiffe://user:pass@example.org/service': Invalid trust domain 'user:pass@example.org': contains disallowed characters",
        ),
        (
            "spiffe://example.org:8080/service",
            "Invalid SPIFFE ID 'spiffe://example.org:8080/service': Invalid trust domain 'example.org:8080': contains disallowed characters",
        ),
        (
            "spiffe://1.2.3.4:8443/service",
            "Invalid SPIFFE ID 'spiffe://1.2.3.4:8443/service': Invalid trust domain '1.2.3.4:8443': contains disallowed characters",
        ),
        (
            "spiffe://[::1]/service",
            "Invalid SPIFFE ID 'spiffe://[::1]/service': Invalid trust domain '[::1]': contains disallowed characters",
        ),
        (
            "spiffe://[2001:db8::1]/service",
            "Invalid SPIFFE ID 'spiffe://[2001:db8::1]/service': Invalid trust domain '[2001:db8::1]': contains disallowed characters",
        ),
        (
            "spiffe://example%2eorg/service",
            "Invalid SPIFFE ID 'spiffe://example%2eorg/service': Invalid trust domain 'example%2eorg': contains disallowed characters",
        ),
        (
            "spiffe://example.org/foo%2Fbar",
            "Invalid SPIFFE ID 'spiffe://example.org/foo%2Fbar': invalid character in path segment",
        ),
        (
            "spiffe://example.org/%61pi",
            "Invalid SPIFFE ID 'spiffe://example.org/%61pi': invalid character in path segment",
        ),
        (
            "spiffe://example.org/service?x=1",
            "Invalid SPIFFE ID 'spiffe://example.org/service?x=1': invalid character in path segment",
        ),
        (
            "spiffe://example.org/service#frag",
            "Invalid SPIFFE ID 'spiffe://example.org/service#frag': invalid character in path segment",
        ),
        (
            "spiffe://example.org/foo/./bar",
            "Invalid SPIFFE ID 'spiffe://example.org/foo/./bar': path segments '.' and '..' are not allowed",
        ),
        (
            "spiffe://example.org/foo/../bar",
            "Invalid SPIFFE ID 'spiffe://example.org/foo/../bar': path segments '.' and '..' are not allowed",
        ),
        (
            "spiffe://example.org/foo//bar",
            "Invalid SPIFFE ID 'spiffe://example.org/foo//bar': path cannot contain empty segments",
        ),
        (
            "spiffe://example.org/foo;bar",
            "Invalid SPIFFE ID 'spiffe://example.org/foo;bar': invalid character in path segment",
        ),
        (
            "spiffe://example.org/foo:bar",
            "Invalid SPIFFE ID 'spiffe://example.org/foo:bar': invalid character in path segment",
        ),
        (
            "spiffe://example.org/foo@bar",
            "Invalid SPIFFE ID 'spiffe://example.org/foo@bar': invalid character in path segment",
        ),
        (
            "spiffe://example.org/foo bar",
            "Invalid SPIFFE ID 'spiffe://example.org/foo bar': invalid character in path segment",
        ),
    ],
)
def test_spiffe_id_invalid(id_str: str, expected_error: str) -> None:
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
def test_spiffe_id_components(id_str: str, trust_domain: str, path: str) -> None:
    spiffe_id = SpiffeId(id_str)
    assert spiffe_id.trust_domain._name == trust_domain
    assert spiffe_id.path == path


def test_spiffe_id_equality() -> None:
    id1 = SpiffeId("spiffe://example.org/path")
    id2 = SpiffeId("spiffe://example.org/path")
    assert id1 == id2
    assert id1 == "spiffe://example.org/path"


def test_spiffe_id_inequality() -> None:
    id1 = SpiffeId("spiffe://example.org/path")
    id2 = SpiffeId("spiffe://example.org/different/path")
    assert id1 != id2
    assert id1 != "spiffe://example.org/different/path"


def test_spiffe_id_hash_equality() -> None:
    id1 = SpiffeId("spiffe://example.org/path")
    id2 = SpiffeId("spiffe://example.org/path")
    assert hash(id1) == hash(id2)


def test_spiffe_id_string_representation() -> None:
    id = SpiffeId("spiffe://example.org/path")
    assert str(id) == "spiffe://example.org/path"


@pytest.mark.parametrize(
    "id_input, expected_str, expected_td",
    [
        (
            "SPIFFE://example.org/service",
            "spiffe://example.org/service",
            "example.org",
        ),
        (
            "spiffe://EXAMPLE.ORG/service",
            "spiffe://example.org/service",
            "example.org",
        ),
        (
            "SpIfFe://Example.Org/service",
            "spiffe://example.org/service",
            "example.org",
        ),
    ],
)
def test_spiffe_id_scheme_and_trust_domain_case_insensitive(
    id_input: str, expected_str: str, expected_td: str
) -> None:
    sid = SpiffeId(id_input)
    assert str(sid) == expected_str
    assert sid.trust_domain.name == expected_td


def test_spiffe_id_path_case_preserved() -> None:
    sid = SpiffeId("SPIFFE://example.org/Service/API")
    assert sid.path == "/Service/API"
    assert str(sid) == "spiffe://example.org/Service/API"


def test_spiffe_id_equivalent_inputs_equal() -> None:
    assert SpiffeId("spiffe://example.org/p") == SpiffeId("SPIFFE://EXAMPLE.ORG/p")
    assert SpiffeId("SPIFFE://EXAMPLE.ORG/p") == "spiffe://example.org/p"
    assert SpiffeId("SPIFFE://EXAMPLE.ORG/p") != "SPIFFE://EXAMPLE.ORG/p"
    assert SpiffeId("spiffe://example.org/Service") != SpiffeId("spiffe://example.org/service")


def test_spiffe_id_invalid_trust_domain_chars_after_normalization() -> None:
    with pytest.raises(SpiffeIdError):
        SpiffeId("SPIFFE://Example$.Org/path")
