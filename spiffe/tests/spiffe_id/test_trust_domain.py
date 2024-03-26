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

from spiffe.spiffe_id.spiffe_id import TrustDomain, TrustDomainError


@pytest.mark.parametrize(
    "input,expected",
    [
        ("example.org", "example.org"),
        ("spiffe://example.org/service", "example.org"),
        ("spiffe://example.org", "example.org"),
        ("domain.test", "domain.test"),
        ("a.b.c.d.e.f", "a.b.c.d.e.f"),
    ],
)
def test_valid_trust_domain(input, expected):
    td = TrustDomain(input)
    assert str(td) == expected


@pytest.mark.parametrize(
    "input,expected_error",
    [
        ("", "Invalid trust domain: cannot be empty"),
        (
            "http://example.org",
            "Invalid trust domain 'http://example.org': ID form does not start with 'spiffe://'",
        ),
        (
            "spiffe://example..org",
            "Invalid trust domain 'spiffe://example..org': cannot contain consecutive dots",
        ),
        (
            "spiffe://example-.org",
            "Invalid trust domain 'spiffe://example-.org': contains disallowed characters",
        ),
        (
            "spiffe://-example.org",
            "Invalid trust domain 'spiffe://-example.org': cannot start or end with '-' or '.'",
        ),
        (
            "spiffe://example.org?query",
            "Invalid trust domain 'spiffe://example.org?query': contains disallowed characters",
        ),
        (
            "spiffe://example.org#fragment",
            "Invalid trust domain 'spiffe://example.org#fragment': contains disallowed characters",
        ),
        (
            "example$org",
            "Invalid trust domain 'example$org': contains disallowed characters",
        ),
        (
            "UPPERCASE.org",
            "Invalid trust domain 'UPPERCASE.org': contains disallowed characters",
        ),
    ],
)
def test_invalid_trust_domain(input, expected_error):
    with pytest.raises(TrustDomainError) as exc:
        TrustDomain(input)
    assert str(exc.value) == expected_error


def test_trust_domain_equality():
    td1 = TrustDomain("example.org")
    td2 = TrustDomain("example.org")
    assert td1 == td2
    assert td1 == "example.org"


def test_trust_domain_inequality():
    td1 = TrustDomain("example.org")
    td2 = TrustDomain("example.com")
    assert td1 != td2
    assert td1 != "example.com"


def test_trust_domain_hash_equality():
    td1 = TrustDomain("example.org")
    td2 = TrustDomain("example.org")
    assert hash(td1) == hash(td2)


def test_trust_domain_as_spiffe_id():
    td = TrustDomain("example.org")
    spiffe_id = td.as_spiffe_id()
    assert str(spiffe_id) == "spiffe://example.org"


def test_trust_domain_string_representation():
    td = TrustDomain("example.org")
    assert str(td) == "example.org"
