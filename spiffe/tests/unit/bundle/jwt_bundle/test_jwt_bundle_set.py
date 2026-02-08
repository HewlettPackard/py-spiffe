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

from typing import Dict
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from spiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle, _PUBLIC_KEY_TYPES
from spiffe.bundle.jwt_bundle.jwt_bundle_set import JwtBundleSet
from spiffe.spiffe_id.spiffe_id import TrustDomain

trust_domain_1 = TrustDomain('domain.test')
trust_domain_2 = TrustDomain('example.org')

# Default authorities to run test cases.
ec_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
authorities: Dict[str, _PUBLIC_KEY_TYPES] = {
    'kid1': ec_key.public_key(),
    'kid2': rsa_key.public_key(),
}


def test_create_jwt_bundle_set() -> None:
    jwt_bundle_1 = JwtBundle(trust_domain_1, authorities)
    jwt_bundle_2 = JwtBundle(trust_domain_2, authorities)

    fake_bundles = {trust_domain_1: jwt_bundle_1, trust_domain_2: jwt_bundle_2}

    jwt_bundle_set = JwtBundleSet(fake_bundles)

    # check that the bundle was copied
    assert jwt_bundle_set._bundles is not fake_bundles
    assert len(jwt_bundle_set._bundles) == len(fake_bundles.keys())
    assert jwt_bundle_set.get_bundle_for_trust_domain(trust_domain_1) == jwt_bundle_1
    assert jwt_bundle_set.get_bundle_for_trust_domain(trust_domain_2) == jwt_bundle_2


def test_create_jwt_bundle_set_no_bundle() -> None:
    jwt_bundle_set = JwtBundleSet({})

    assert isinstance(jwt_bundle_set._bundles, dict)
    assert len(jwt_bundle_set._bundles) == 0


def test_put_bundle() -> None:
    jwt_bundle = JwtBundle(trust_domain_1, authorities)
    jwt_bundle_set = JwtBundleSet({trust_domain_1: jwt_bundle})

    assert len(jwt_bundle_set._bundles) == 1
    assert jwt_bundle_set._bundles[trust_domain_1.name] == jwt_bundle

    new_jwt_bundle = JwtBundle(trust_domain_2, authorities)
    jwt_bundle_set.put(new_jwt_bundle)

    assert len(jwt_bundle_set._bundles) == 2
    assert jwt_bundle_set._bundles[trust_domain_1.name] == jwt_bundle
    assert jwt_bundle_set._bundles[trust_domain_2.name] == new_jwt_bundle


def test_put_bundle_on_empty_set() -> None:
    jwt_bundle_set = JwtBundleSet({})

    assert len(jwt_bundle_set._bundles) == 0

    jwt_bundle = JwtBundle(trust_domain_1, authorities)

    jwt_bundle_set.put(jwt_bundle)

    assert len(jwt_bundle_set._bundles) == 1
    assert list(jwt_bundle_set._bundles.keys())[0] == trust_domain_1.name


def test_put_replace_bundle_for_trust_domain() -> None:
    jwt_bundle = JwtBundle(trust_domain_1, authorities)
    jwt_bundle_set = JwtBundleSet({trust_domain_1: jwt_bundle})

    assert len(jwt_bundle_set._bundles) == 1
    assert jwt_bundle_set._bundles[trust_domain_1.name] == jwt_bundle

    new_jwt_bundle = JwtBundle(trust_domain_1, authorities)
    jwt_bundle_set.put(new_jwt_bundle)

    assert len(jwt_bundle_set._bundles) == 1
    assert jwt_bundle_set._bundles[trust_domain_1.name] == new_jwt_bundle


def test_get() -> None:
    jwt_bundle = JwtBundle(trust_domain_1, authorities)
    jwt_bundle_set = JwtBundleSet({trust_domain_1: jwt_bundle})

    res = jwt_bundle_set.get_bundle_for_trust_domain(trust_domain_1)

    assert res is not None
    assert res == jwt_bundle
    assert res.trust_domain == jwt_bundle.trust_domain


def test_get_non_existing_trust_domain() -> None:
    jwt_bundle = JwtBundle(trust_domain_1, authorities)
    jwt_bundle_set = JwtBundleSet({trust_domain_1: jwt_bundle})

    res = jwt_bundle_set.get_bundle_for_trust_domain(trust_domain_2)

    assert res is None


def test_get_empty_set() -> None:
    jwt_bundle_set = JwtBundleSet({})

    res = jwt_bundle_set.get_bundle_for_trust_domain(trust_domain_1)

    assert res is None
