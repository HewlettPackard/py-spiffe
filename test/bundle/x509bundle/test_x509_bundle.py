import pytest

import pem
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate

from pyspiffe.bundle.x509_bundle.exceptions import (
    X509BundleError,
    ParseX509BundleError,
    LoadX509BundleError,
)
from pyspiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from pyspiffe.spiffe_id.trust_domain import TrustDomain

_TEST_CERTS_PATH = 'test/bundle/x509bundle/certs/{}'
trust_domain = TrustDomain('domain.test')


def test_parse_raw_bundle_single_authority():
    bundle_bytes = read_bytes(_TEST_CERTS_PATH.format('cert.der'))

    x509_bundle = X509Bundle.parse_raw(trust_domain, bundle_bytes)

    assert x509_bundle.trust_domain == trust_domain
    assert len(x509_bundle.x509_authorities) == 1

    authority = x509_bundle.x509_authorities.pop()
    assert isinstance(authority, Certificate)
    assert 'CN=PEMUTILTEST1' == authority.subject.rfc4514_string()


def test_parse_raw_bundle_multiple_authorities():
    bundle_bytes = read_bytes(_TEST_CERTS_PATH.format('certs.der'))

    x509_bundle = X509Bundle.parse_raw(trust_domain, bundle_bytes)

    assert x509_bundle.trust_domain == trust_domain
    assert len(x509_bundle.x509_authorities) == 2

    expected_subjects = ['O=SPIRE,C=US', 'O=SPIFFE,C=US']
    authority1 = x509_bundle.x509_authorities.pop()
    assert isinstance(authority1, Certificate)
    assert authority1.subject.rfc4514_string() in expected_subjects

    authority2 = x509_bundle.x509_authorities.pop()
    assert isinstance(authority2, Certificate)
    assert authority2.subject.rfc4514_string() in expected_subjects


def test_parse_bundle_single_authority():
    bundle_bytes = read_bytes(_TEST_CERTS_PATH.format('cert.pem'))

    x509_bundle = X509Bundle.parse(trust_domain, bundle_bytes)

    assert x509_bundle.trust_domain == trust_domain
    assert len(x509_bundle.x509_authorities) == 1
    authority = x509_bundle.x509_authorities.pop()
    assert isinstance(authority, Certificate)
    assert 'CN=PEMUTILTEST1' == authority.subject.rfc4514_string()


def test_parse_bundle_multiple_authorities():
    bundle_bytes = read_bytes(_TEST_CERTS_PATH.format('certs.pem'))

    x509_bundle = X509Bundle.parse(trust_domain, bundle_bytes)

    assert x509_bundle.trust_domain == trust_domain
    assert len(x509_bundle.x509_authorities) == 2

    expected_subjects = ['CN=PEMUTILTEST1', 'CN=PEMUTILTEST2']
    authority1 = x509_bundle.x509_authorities.pop()
    assert isinstance(authority1, Certificate)
    assert authority1.subject.rfc4514_string() in expected_subjects

    authority2 = x509_bundle.x509_authorities.pop()
    assert isinstance(authority2, Certificate)
    assert authority2.subject.rfc4514_string() in expected_subjects


def test_parse_raw_trust_domain_is_emtpy():
    bundle_bytes = read_bytes(_TEST_CERTS_PATH.format('certs.der'))

    with pytest.raises(X509BundleError) as exception:
        X509Bundle.parse_raw(None, bundle_bytes)

    assert str(exception.value) == 'Trust domain cannot be empty.'


def test_parse_trust_domain_is_emtpy():
    bundle_bytes = read_bytes(_TEST_CERTS_PATH.format('certs.pem'))

    with pytest.raises(X509BundleError) as exception:
        X509Bundle.parse(None, bundle_bytes)

    assert str(exception.value) == 'Trust domain cannot be empty.'


def test_parse_bundle_from_empty():
    bundle_bytes = read_bytes(_TEST_CERTS_PATH.format('empty.pem'))

    with pytest.raises(ParseX509BundleError) as exception:
        X509Bundle.parse(trust_domain, bundle_bytes)

    assert (
        str(exception.value)
        == 'Error parsing X.509 bundle: Unable to load PEM X.509 certificate.'
    )


def test_parse_bundle_from_not_pem():
    bundle_bytes = read_bytes(_TEST_CERTS_PATH.format('not-pem'))

    with pytest.raises(ParseX509BundleError) as exception:
        X509Bundle.parse(trust_domain, bundle_bytes)

    assert (
        str(exception.value)
        == 'Error parsing X.509 bundle: Unable to load PEM X.509 certificate.'
    )


def test_load_bundle():
    bundle_path = _TEST_CERTS_PATH.format('certs.pem')

    x509_bundle = X509Bundle.load(trust_domain, bundle_path, serialization.Encoding.PEM)

    assert x509_bundle.trust_domain == trust_domain
    assert len(x509_bundle.x509_authorities) == 2

    expected_subjects = ['CN=PEMUTILTEST1', 'CN=PEMUTILTEST2']
    authority1 = x509_bundle.x509_authorities.pop()
    assert isinstance(authority1, Certificate)
    assert authority1.subject.rfc4514_string() in expected_subjects

    authority2 = x509_bundle.x509_authorities.pop()
    assert isinstance(authority2, Certificate)
    assert authority2.subject.rfc4514_string() in expected_subjects


def test_load_bundle_non_existent_file():
    with pytest.raises(LoadX509BundleError) as exception:
        X509Bundle.load(trust_domain, 'no-exists', serialization.Encoding.PEM)

    assert (
        str(exception.value)
        == 'Error loading X.509 bundle: Certs chain file file not found: no-exists.'
    )


def test_load_bundle_empty_trust_domain():
    bundle_path = _TEST_CERTS_PATH.format('certs.pem')
    with pytest.raises(Exception) as exception:
        X509Bundle.load(None, bundle_path, serialization.Encoding.PEM)

    assert str(exception.value) == 'Trust domain cannot be empty.'


def test_save_bundle_pem_encoded(tmpdir):
    bundle_bytes = read_bytes(_TEST_CERTS_PATH.format('certs.pem'))
    # create the X509Bundle to be saved
    x509_bundle = X509Bundle.parse(trust_domain, bundle_bytes)

    bundle_path = tmpdir.join('bundle.pem')
    X509Bundle.save(x509_bundle, bundle_path, serialization.Encoding.PEM)

    saved_bundle = X509Bundle.load(
        trust_domain, bundle_path, serialization.Encoding.PEM
    )

    assert saved_bundle.trust_domain == trust_domain
    assert len(saved_bundle.x509_authorities) == 2

    expected_subjects = ['CN=PEMUTILTEST1', 'CN=PEMUTILTEST2']
    authority1 = saved_bundle.x509_authorities.pop()
    assert isinstance(authority1, Certificate)
    assert authority1.subject.rfc4514_string() in expected_subjects

    authority2 = saved_bundle.x509_authorities.pop()
    assert isinstance(authority2, Certificate)
    assert authority2.subject.rfc4514_string() in expected_subjects


def test_save_bundle_der_encoded(tmpdir):
    bundle_bytes = read_bytes(_TEST_CERTS_PATH.format('certs.pem'))
    # create the X509Bundle to be saved
    x509_bundle = X509Bundle.parse(trust_domain, bundle_bytes)

    bundle_path = tmpdir.join('bundle.pem')
    X509Bundle.save(x509_bundle, bundle_path, serialization.Encoding.DER)

    saved_bundle = X509Bundle.load(
        trust_domain, bundle_path, serialization.Encoding.DER
    )

    assert saved_bundle.trust_domain == trust_domain
    assert len(saved_bundle.x509_authorities) == 2

    expected_subjects = ['CN=PEMUTILTEST1', 'CN=PEMUTILTEST2']
    authority1 = saved_bundle.x509_authorities.pop()
    assert isinstance(authority1, Certificate)
    assert authority1.subject.rfc4514_string() in expected_subjects

    authority2 = saved_bundle.x509_authorities.pop()
    assert isinstance(authority2, Certificate)
    assert authority2.subject.rfc4514_string() in expected_subjects


def test_save_non_supported_encoding(tmpdir):
    bundle_bytes = read_bytes(_TEST_CERTS_PATH.format('certs.pem'))
    # create the X509Bundle to be saved
    x509_bundle = X509Bundle.parse(trust_domain, bundle_bytes)

    bundle_path = tmpdir.join('bundle.pem')

    with pytest.raises(ValueError) as err:
        X509Bundle.save(x509_bundle, bundle_path, serialization.Encoding.Raw)

    assert (
        str(err.value)
        == 'Encoding not supported: Encoding.Raw. Expected \'PEM\' or \'DER\'.'
    )


def test_add_and_remove_authority():
    bundle = X509Bundle(trust_domain, None)
    pem_certs = pem.parse_file(_TEST_CERTS_PATH.format('certs.pem'))
    x509_cert_1 = x509.load_pem_x509_certificate(
        pem_certs[0].as_bytes(), default_backend()
    )
    x509_cert_2 = x509.load_pem_x509_certificate(
        pem_certs[1].as_bytes(), default_backend()
    )

    bundle.add_authority(x509_cert_1)
    bundle.add_authority(x509_cert_2)

    assert len(bundle.x509_authorities) == 2

    for a in bundle.x509_authorities:
        assert isinstance(a, Certificate)
        assert 'CN=PEMUTILTEST' in a.subject.rfc4514_string()

    bundle.remove_authority(x509_cert_1)
    assert len(bundle.x509_authorities) == 1
    bundle.remove_authority(x509_cert_2)
    assert len(bundle.x509_authorities) == 0


def read_bytes(path):
    with open(path, 'rb') as file:
        return file.read()
