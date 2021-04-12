import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from pyspiffe.spiffe_id.trust_domain import TrustDomain
from pyspiffe.bundle.jwt_bundle.exceptions import JwtBundleError
from pyspiffe.exceptions import ArgumentError

# Default trust domain to run test cases.
trust_domain = TrustDomain("spiffe://any.domain")

# Default authorities to run test cases.
ec_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
authorities = {
    'kid1': ec_key,
    'kid2': rsa_key,
}


def test_create_jwt_bundle():
    jwt_bundle = JwtBundle(trust_domain, authorities)

    assert jwt_bundle.trust_domain() == trust_domain
    assert len(jwt_bundle.jwt_authorities().keys()) == len(authorities.keys())


def test_create_jwt_bundle_no_trust_domain():
    with pytest.raises(JwtBundleError) as exc_info:
        JwtBundle(None, authorities)

    assert str(exc_info.value) == 'Trust domain cannot be empty.'


def test_create_jwt_bundle_no_authorities():
    jwt_bundle = JwtBundle(trust_domain, None)

    assert jwt_bundle.trust_domain() == trust_domain
    assert isinstance(jwt_bundle.jwt_authorities(), dict)
    assert len(jwt_bundle.jwt_authorities().keys()) == 0


"""
    get_jwt_authority
"""


def test_get_jwt_authority_valid_input():
    jwt_bundle = JwtBundle(trust_domain, authorities)

    authority_key = jwt_bundle.get_jwt_authority('kid2')

    assert rsa_key == authority_key


def test_get_jwt_authority_invalid_key_id_not_found():
    jwt_bundle = JwtBundle(trust_domain, authorities)

    response = jwt_bundle.get_jwt_authority('p0')

    assert response is None


def test_get_jwt_authority_invalid_input():
    jwt_bundle = JwtBundle(trust_domain, authorities)

    with pytest.raises(ArgumentError) as exception:
        jwt_bundle.get_jwt_authority('')

    assert str(exception.value) == 'key_id cannot be empty.'


def test_get_jwt_authority_empty_authority_dict():
    invalid_authorities = None
    jwt_bundle = JwtBundle(trust_domain, invalid_authorities)

    response = jwt_bundle.get_jwt_authority(key_id='p1')

    assert response is None
