import pytest

from pyspiffe.spiffe_id.trust_domain import TrustDomain
from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.exceptions import ArgumentError


@pytest.mark.parametrize(
    'trust_domain,path_segments,expected_spiffe_id',
    [
        (
            TrustDomain('example.org'),
            ['path', 'element'],
            'spiffe://example.org/path/element',
        ),
        (
            TrustDomain('example.org'),
            ['/path', '/element'],
            'spiffe://example.org/path/element',
        ),
        # path case should be preserved
        (
            TrustDomain('domain.test'),
            ['   pAth1  ', '   pATH2  '],
            'spiffe://domain.test/pAth1/pATH2',
        ),
        (
            TrustDomain('domain.test'),
            '   pAth1/pATH2  ',
            'spiffe://domain.test/pAth1/pATH2',
        ),
        (
            TrustDomain('domain.test'),
            ['   pAth1/pATH2  '],
            'spiffe://domain.test/pAth1/pATH2',
        ),
    ],
)
def test_of_trust_domain_and_segments(trust_domain, path_segments, expected_spiffe_id):
    result = SpiffeId.of(trust_domain, path_segments)
    assert str(result) == expected_spiffe_id


@pytest.mark.parametrize(
    'spiffe_id_str,expected_trust_domain,expected_path',
    [
        ('spiffe://example.org', TrustDomain('example.org'), ''),
        (
            'spiffe://example.org/path1/path2',
            TrustDomain('example.org'),
            '/path1/path2',
        ),
        # only path case should be preserved
        (
            'SPIFFE://EXAMPLE.oRg/pAth1/pATH2',
            TrustDomain('example.org'),
            '/pAth1/pATH2',
        ),
        (
            '    spiffe://EXAMPLE.oRg/PATH1/PATH2   ',
            TrustDomain('example.org'),
            '/PATH1/PATH2',
        ),
        (
            'spiffe://domain.test/pa@th/element:',
            TrustDomain('domain.test'),
            '/pa@th/element:',
        ),
        (
            "spiffe://domain.test/p!a$t&h'/(e)l*e+m,e;n=t",
            TrustDomain('domain.test'),
            "/p!a$t&h'/(e)l*e+m,e;n=t",
        ),
    ],
)
def test_parse_spiffe_id_valid_uri(spiffe_id_str, expected_trust_domain, expected_path):
    spiffe_id = SpiffeId.parse(spiffe_id_str)
    assert spiffe_id.trust_domain() == expected_trust_domain
    assert spiffe_id.path() == expected_path


@pytest.mark.parametrize(
    'spiffe_id_str,expected',
    [
        ('', 'SPIFFE ID cannot be empty.'),
        (None, 'SPIFFE ID cannot be empty.'),
        ('192.168.2.2:6688', "'192.168.2.2:6688' is not a valid 'URI'."),
        (
            'http://domain.test/path/element',
            'SPIFFE ID: invalid scheme: expected spiffe.',
        ),
        ('spiffe:///path/element', 'SPIFFE ID: trust domain cannot be empty.'),
        (
            'spiffe://domain.test/path/element?query=1',
            'SPIFFE ID: query is not allowed.',
        ),
        (
            'spiffe://domain.test/path/element#fragment-1',
            'SPIFFE ID: fragment is not allowed.',
        ),
        ('spiffe://domain.test:8080/path/element', 'SPIFFE ID: port is not allowed.'),
        (
            'spiffe://user:password@test.org/path/element',
            'SPIFFE ID: userinfo is not allowed.',
        ),
        ('spiffe:path/element', 'SPIFFE ID: trust domain cannot be empty.'),
        ('spiffe:/path/element', 'SPIFFE ID: trust domain cannot be empty.'),
        (
            'spiffe://domain.test/path/elem%5uent',
            "'spiffe://domain.test/path/elem%5uent' is not a valid 'URI'.",
        ),
    ],
)
def test_parse_spiffe_id_from_invalid_uri_string(spiffe_id_str, expected):
    with pytest.raises(ArgumentError) as exception:
        SpiffeId.parse(spiffe_id_str)

    assert str(exception.value) == expected


def test_equal_spiffe_id():
    trust_domain = TrustDomain('domain.test')
    spiffeid_1 = SpiffeId.of(trust_domain, 'path1')  # path1 is normalized as /path1
    spiffeid_2 = SpiffeId.of(trust_domain, '/path1')
    assert spiffeid_1 == spiffeid_2


def test_equal_spiffe_id_with_multiple_paths():
    trust_domain = TrustDomain('example.org')
    spiffeid_1 = SpiffeId.of(trust_domain, ['PATH1', 'PATH2'])
    spiffeid_2 = SpiffeId.of(trust_domain, ['/PATH1', '/PATH2'])
    assert spiffeid_1 == spiffeid_2


def test_not_equal_spiffe_ids():
    trust_domain = TrustDomain('domain.test')
    spiffeid_1 = SpiffeId.of(trust_domain, 'path1')
    spiffeid_2 = SpiffeId.of(trust_domain, 'path2')
    assert spiffeid_1 != spiffeid_2


def test_not_equal_when_different_objects():
    trust_domain = TrustDomain('domain.test')
    spiffeid_1 = SpiffeId.of(trust_domain, 'path1')
    assert spiffeid_1 != trust_domain


def test_trust_domain_none():
    with pytest.raises(ArgumentError) as exception:
        SpiffeId.of(None, 'path')

    assert str(exception.value) == 'SPIFFE ID: trust domain cannot be empty.'


def test_of_empty_trust_domain():
    with pytest.raises(ArgumentError) as exception:
        SpiffeId.of('', 'path')

    assert (
        str(exception.value)
        == 'SPIFFE ID: trust_domain argument must be a TrustDomain instance.'
    )


def test_exceeds_maximum_length():
    path = 'a' * 2028

    with pytest.raises(ArgumentError) as exception:
        SpiffeId.parse('spiffe://example.org/{}'.format(path))

    assert str(exception.value) == 'SPIFFE ID: maximum length is 2048 bytes.'


def test_maximum_length():
    path = 'a' * 2027
    spiffe_id = SpiffeId.parse('spiffe://example.org/{}'.format(path))

    assert spiffe_id.trust_domain() == TrustDomain('example.org')
    assert spiffe_id.path() == '/' + path


def test_is_member_of():
    spiffe_id = SpiffeId.parse('spiffe://domain.test/path/element')
    trust_domain = TrustDomain('domain.test')
    assert spiffe_id.is_member_of(trust_domain)


def test_is_not_member_of():
    spiffe_id = SpiffeId.parse('spiffe://domain.test/path/element')
    trust_domain = TrustDomain('other.test')
    assert not spiffe_id.is_member_of(trust_domain)


def test_str_when_no_path():
    spiffe_id = SpiffeId.parse('spiffe://domain.test')
    assert str(spiffe_id) == 'spiffe://domain.test'
