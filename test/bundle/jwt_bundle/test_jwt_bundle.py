import pytest
from pyspiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from pyspiffe.spiffe_id.trust_domain import TrustDomain
from pyspiffe.bundle.jwt_bundle.exceptions import AuthorityNotFoundError

"""
    findJwtAuthority
"""


def test_valid_input_findJwtAuthority():
    p1 = "PublicKey1"
    p2 = "PublicKey2"
    p3 = "PublicKey3"
    authorities = {
        'kid1': p1,
        'kid2': p2,
        'kid3': p3,
    }
    trust_domain = TrustDomain("spiffe://any.domain")
    jwt_bundle = JwtBundle(trust_domain, authorities)
    authority_key = jwt_bundle.find_jwt_authority('kid2')

    assert p2 == authority_key


def test_invalid_key_id_not_found_findJwtAuthority():
    trust_domain = TrustDomain("spiffe://any.domain")
    authority = {
        'kid1': 'p1',
        'kid2': 'p2',
        'kid3': 'p3',
    }
    jwt_bundle = JwtBundle(trust_domain, authority)
    with pytest.raises(AuthorityNotFoundError) as exception:
        jwt_bundle.find_jwt_authority('p0')

    assert str(exception.value) == 'Key (p0) not found in authorities.'


def test_invalid_input_findJwtAuthority():
    trust_domain = TrustDomain("spiffe://any.domain")
    authority = {
        'kid1': 'p1',
        'kid2': 'p2',
        'kid3': 'p3',
    }
    jwt_bundle = JwtBundle(trust_domain, authority)
    with pytest.raises(ValueError) as exception:
        jwt_bundle.find_jwt_authority(key_id=None)

    assert str(exception.value) == 'key_id cannot be empty.'


def test_authority_none_creation():
    trust_domain = TrustDomain("spiffe://any.domain")
    authority = None
    jwt_bundle = JwtBundle(trust_domain, authority)
    with pytest.raises(AuthorityNotFoundError) as exception:
        jwt_bundle.find_jwt_authority(key_id='p1')

    assert str(exception.value) == 'Key (p1) not found in authorities.'
