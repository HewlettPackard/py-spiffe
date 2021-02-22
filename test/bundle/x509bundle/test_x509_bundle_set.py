from pyspiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from pyspiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from pyspiffe.spiffe_id.trust_domain import TrustDomain

_TEST_CERTS_PATH = 'test/bundle/x509bundle/certs/{}'
trust_domain_1 = TrustDomain('domain.test')
trust_domain_2 = TrustDomain('example.org')


def test_create_new_x509_bundle_set():
    bundle_bytes = read_bytes(_TEST_CERTS_PATH.format('cert.der'))

    bundle_1 = X509Bundle.parse_raw(trust_domain_1, bundle_bytes)
    bundle_2 = X509Bundle.parse_raw(trust_domain_2, bundle_bytes)

    bundles = {trust_domain_1: bundle_1, trust_domain_2: bundle_2}

    x509_bundle_set = X509BundleSet(bundles)

    assert len(x509_bundle_set._bundles) == 2

    found_bundle = x509_bundle_set.get_x509_bundle_for_trust_domain(trust_domain_1)
    assert found_bundle == bundle_1

    found_bundle = x509_bundle_set.get_x509_bundle_for_trust_domain(trust_domain_2)
    assert found_bundle == bundle_2

    found_bundle = x509_bundle_set.get_x509_bundle_for_trust_domain(
        TrustDomain('other.test')
    )
    assert found_bundle is None


def test_create_x509_bundle_set_from_list_of_bundles():
    bundle_bytes = read_bytes(_TEST_CERTS_PATH.format('certs.der'))

    bundle_1 = X509Bundle.parse_raw(trust_domain_1, bundle_bytes)
    bundle_2 = X509Bundle.parse_raw(trust_domain_2, bundle_bytes)

    bundles = [bundle_1, bundle_2]

    x509_bundle_set = X509BundleSet.of(bundles)

    assert len(x509_bundle_set._bundles) == 2

    found_bundle = x509_bundle_set.get_x509_bundle_for_trust_domain(trust_domain_1)
    assert found_bundle == bundle_1

    found_bundle = x509_bundle_set.get_x509_bundle_for_trust_domain(trust_domain_2)
    assert found_bundle == bundle_2

    found_bundle = x509_bundle_set.get_x509_bundle_for_trust_domain(
        TrustDomain('other.test')
    )
    assert found_bundle is None


def test_put_bundle():
    bundle_bytes = read_bytes(_TEST_CERTS_PATH.format('certs.der'))
    bundle_bytes_2 = read_bytes(_TEST_CERTS_PATH.format('certs.pem'))

    bundle_1 = X509Bundle.parse_raw(trust_domain_1, bundle_bytes)
    bundle_2 = X509Bundle.parse_raw(trust_domain_2, bundle_bytes)
    other_bundle = X509Bundle.parse(trust_domain_1, bundle_bytes_2)

    x509_bundle_set = X509BundleSet({})

    assert len(x509_bundle_set._bundles) == 0

    x509_bundle_set.put(bundle_1)
    assert len(x509_bundle_set._bundles) == 1

    found_bundle = x509_bundle_set.get_x509_bundle_for_trust_domain(trust_domain_1)
    assert found_bundle == bundle_1

    found_bundle = x509_bundle_set.get_x509_bundle_for_trust_domain(trust_domain_2)
    assert found_bundle is None

    x509_bundle_set.put(bundle_2)
    assert len(x509_bundle_set._bundles) == 2

    # putting other bundle for the trust domain 1
    x509_bundle_set.put(other_bundle)
    assert len(x509_bundle_set._bundles) == 2

    found_bundle = x509_bundle_set.get_x509_bundle_for_trust_domain(trust_domain_1)
    assert found_bundle == other_bundle


def read_bytes(path):
    with open(path, 'rb') as file:
        return file.read()
