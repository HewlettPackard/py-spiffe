from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from pyspiffe.bundle.jwt_bundle.jwt_bundle_set import JwtBundleSet
from pyspiffe.spiffe_id.trust_domain import TrustDomain

trust_domain_1 = TrustDomain('domain.test')
trust_domain_2 = TrustDomain('example.org')

# Default authorities to run test cases.
ec_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
authorities = {
    'kid1': ec_key,
    'kid2': rsa_key,
}


def test_create_jwt_bundle_set():
    jwt_bundle_1 = JwtBundle(trust_domain_1, authorities)
    jwt_bundle_2 = JwtBundle(trust_domain_2, authorities)

    fake_bundles = {trust_domain_1: jwt_bundle_1, trust_domain_2: jwt_bundle_2}

    jwt_bundle_set = JwtBundleSet(fake_bundles)

    # check that the bundle was copied
    assert jwt_bundle_set._bundles is not fake_bundles
    assert len(jwt_bundle_set._bundles) == len(fake_bundles.keys())
    assert list(jwt_bundle_set._bundles.keys())[0].name() == trust_domain_1.name()
    assert jwt_bundle_set._bundles[trust_domain_1] == jwt_bundle_1
    assert list(jwt_bundle_set._bundles.keys())[1].name() == trust_domain_2.name()
    assert jwt_bundle_set._bundles[trust_domain_2] == jwt_bundle_2


def test_create_jwt_bundle_set_no_bundle():
    jwt_bundle_set = JwtBundleSet(None)

    assert isinstance(jwt_bundle_set._bundles, dict)
    assert len(jwt_bundle_set._bundles) == 0


def test_put_bundle():
    jwt_bundle = JwtBundle(trust_domain_1, authorities)
    jwt_bundle_set = JwtBundleSet({trust_domain_1: jwt_bundle})

    assert len(jwt_bundle_set._bundles) == 1
    assert jwt_bundle_set._bundles[trust_domain_1] == jwt_bundle

    new_jwt_bundle = JwtBundle(trust_domain_2, authorities)
    jwt_bundle_set.put(new_jwt_bundle)

    assert len(jwt_bundle_set._bundles) == 2
    assert jwt_bundle_set._bundles[trust_domain_1] == jwt_bundle
    assert jwt_bundle_set._bundles[trust_domain_2] == new_jwt_bundle


def test_put_bundle_on_empty_set():
    jwt_bundle_set = JwtBundleSet({})

    assert len(jwt_bundle_set._bundles) == 0

    jwt_bundle = JwtBundle(trust_domain_1, authorities)

    jwt_bundle_set.put(jwt_bundle)

    assert len(jwt_bundle_set._bundles) == 1
    assert list(jwt_bundle_set._bundles.keys())[0].name() == trust_domain_1.name()


def test_put_replace_bundle_for_trust_domain():
    jwt_bundle = JwtBundle(trust_domain_1, authorities)
    jwt_bundle_set = JwtBundleSet({trust_domain_1: jwt_bundle})

    assert len(jwt_bundle_set._bundles) == 1
    assert jwt_bundle_set._bundles[trust_domain_1] == jwt_bundle

    new_jwt_bundle = JwtBundle(trust_domain_1, authorities)
    jwt_bundle_set.put(new_jwt_bundle)

    assert len(jwt_bundle_set._bundles) == 1
    assert jwt_bundle_set._bundles[trust_domain_1] == new_jwt_bundle


def test_get():
    jwt_bundle = JwtBundle(trust_domain_1, authorities)
    jwt_bundle_set = JwtBundleSet({trust_domain_1: jwt_bundle})

    res = jwt_bundle_set.get(trust_domain_1)

    assert res == jwt_bundle
    assert res.trust_domain() == jwt_bundle.trust_domain()


def test_get_non_existing_trust_domain():
    jwt_bundle = JwtBundle(trust_domain_1, authorities)
    jwt_bundle_set = JwtBundleSet({trust_domain_1: jwt_bundle})

    res = jwt_bundle_set.get(trust_domain_2)

    assert res is None


def test_get_empty_set():
    jwt_bundle_set = JwtBundleSet({})

    res = jwt_bundle_set.get(trust_domain_1)

    assert res is None
