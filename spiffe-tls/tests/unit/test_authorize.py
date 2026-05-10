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

import datetime
from typing import List

from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID

from spiffe.spiffe_id.spiffe_id import SpiffeId, TrustDomain
from spiffetls.tlsconfig.authorize import (
    authorize_any,
    authorize_id,
    authorize_member_of,
)


def test_authorize_any_with_one_spiffe_uri_san_succeeds() -> None:
    cert = _make_cert(uri_sans=["spiffe://example.org/service"], dns_sans=[])

    assert authorize_any()(cert)


def test_authorize_any_with_spiffe_uri_san_and_dns_san_succeeds() -> None:
    cert = _make_cert(
        uri_sans=["spiffe://example.org/service"],
        dns_sans=["service.example.org"],
    )

    assert authorize_any()(cert)


def test_authorize_any_with_zero_uri_sans_fails() -> None:
    cert = _make_cert(uri_sans=[], dns_sans=["service.example.org"])

    assert not authorize_any()(cert)


def test_authorize_any_with_multiple_uri_sans_fails() -> None:
    cert = _make_cert(
        uri_sans=["spiffe://example.org/service", "https://example.org/service"],
        dns_sans=[],
    )

    assert not authorize_any()(cert)


def test_authorize_any_with_non_spiffe_uri_san_fails() -> None:
    cert = _make_cert(uri_sans=["https://example.org/service"], dns_sans=[])

    assert not authorize_any()(cert)


def test_authorize_id_and_member_of_use_parsed_spiffe_uri_san() -> None:
    cert = _make_cert(
        uri_sans=["spiffe://example.org/service"],
        dns_sans=["service.example.org"],
    )

    assert authorize_id(SpiffeId("spiffe://example.org/service"))(cert)
    assert authorize_member_of(TrustDomain("example.org"))(cert)


def test_authorize_id_and_member_of_reject_multiple_uri_sans() -> None:
    cert = _make_cert(
        uri_sans=["spiffe://example.org/service", "https://example.org/service"],
        dns_sans=[],
    )

    assert not authorize_id(SpiffeId("spiffe://example.org/service"))(cert)
    assert not authorize_member_of(TrustDomain("example.org"))(cert)


def _make_cert(*, uri_sans: List[str], dns_sans: List[str]) -> crypto.X509:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "leaf"),
        ]
    )

    san_entries: List[x509.GeneralName] = []
    san_entries.extend(x509.UniformResourceIdentifier(uri) for uri in uri_sans)
    san_entries.extend(x509.DNSName(dns) for dns in dns_sans)

    now = datetime.datetime.now(datetime.timezone.utc)
    cert: Certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    return crypto.X509.from_cryptography(cert)
