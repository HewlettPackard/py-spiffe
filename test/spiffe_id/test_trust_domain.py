import pytest

from pyspiffe.spiffe_id.trust_domain import TrustDomain


@pytest.mark.parametrize(
    'test_input,expected',
    [
        ('domain.test', 'domain.test'),
        (' doMain.tesT  ', 'domain.test'),
        ('spiffe://domAin.Test', 'domain.test'),
        ('spiffe://domain.test/path/element', 'domain.test'),
        ('spiffe://domain.test/spiffe://domain.test/path/element', 'domain.test'),
        ('spiffe://domain.test/spiffe://domain.test:80/path/element', 'domain.test'),
    ],
)
def test_valid_trust_domain(test_input, expected):
    result = TrustDomain(test_input).name()
    assert result == expected


@pytest.mark.parametrize(
    'test_input,expected',
    [
        ('', 'Trust domain cannot be empty.'),
        (None, 'Trust domain cannot be empty.'),
        ('http://domain.test', 'Trust domain: invalid scheme: expected spiffe.'),
        ('://domain.test', 'Trust domain: invalid scheme: expected spiffe.'),
        ('spiffe:///path/element', 'Trust domain cannot be empty.'),
        ('/path/element', 'Trust domain cannot be empty.'),
        ('spiffe://domain.test:80', 'Trust domain: port is not allowed.'),
    ],
)
def test_invalid_trust_domain(test_input, expected):
    with pytest.raises(ValueError) as exception:
        TrustDomain(test_input)

    assert str(exception.value) == expected


def test_get_name():
    trust_domain = TrustDomain('example.org')
    assert trust_domain.name() == 'example.org'


def test_to_string():
    trust_domain = TrustDomain('domain.test')
    assert str(trust_domain) == 'domain.test'


def test_compare_multiple_equal_trust_domains():
    trust_domain1 = TrustDomain('domain.test')
    trust_domain2 = TrustDomain('domain.test')
    assert trust_domain1 == trust_domain2


def test_compare_different_trust_domains():
    trust_domain1 = TrustDomain('domain.test')
    trust_domain2 = TrustDomain('other.test')
    assert not trust_domain1 == trust_domain2


def test_not_equal_when_different_objects():
    trust_domain = TrustDomain('domain.test')
    td_list = list([trust_domain])
    assert trust_domain != td_list


def test_exceeds_maximum_length():
    name = "a" * 256

    with pytest.raises(ValueError) as exception:
        TrustDomain("{}".format(name))

    assert str(exception.value) == 'Trust domain cannot be longer than 255 bytes.'


def test_maximum_length():
    name = "a" * 255
    trust_domain = TrustDomain('{}'.format(name))

    assert trust_domain.name() == name


def test_as_str_id():
    trust_domain = TrustDomain('example.org')
    assert trust_domain.as_str_id() == 'spiffe://example.org'
