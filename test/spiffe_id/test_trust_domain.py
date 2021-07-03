import pytest

from pyspiffe.exceptions import ArgumentError
from pyspiffe.spiffe_id.spiffe_id import TrustDomain
from test.spiffe_id.test_spiffe_id import TD_CHARS


@pytest.mark.parametrize(
    'test_input,expected',
    [
        ('trustdomain', 'trustdomain'),
        ('trustdomain.test', 'trustdomain.test'),
        ('spiffe://domain.test/path/element', 'domain.test'),
    ],
)
def test_valid_trust_domain(test_input, expected):
    result = TrustDomain.parse(test_input)
    assert result.name() == expected


@pytest.mark.parametrize(
    'test_input,expected',
    [
        ('', 'Trust domain is missing.'),
        (None, 'Trust domain is missing.'),
        ('http://domain.test', 'Scheme is missing or invalid.'),
        ('://domain.test', 'Scheme is missing or invalid.'),
        ('spiffe:///path/element', 'Trust domain is missing.'),
        (
            '/path/element',
            'Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores.',
        ),
        (
            'spiffe://domain.test:80',
            'Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores.',
        ),
        (
            'user:pass@domain.test',
            'Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores.',
        ),
        (
            'Domain.Test',
            'Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores.',
        ),
    ],
)
def test_invalid_trust_domain(test_input, expected):
    with pytest.raises(ArgumentError) as exception:
        TrustDomain.parse(test_input)

    assert str(exception.value) == expected


def test_parse_with_all_chars():
    # Go all the way through 255, which ensures we reject UTF-8 appropriately
    for i in range(0, 255):
        c = chr(i)
        td = "trustdomain" + c
        if c in TD_CHARS:
            trust_domain = TrustDomain.parse(td)
            assert trust_domain.name() == td
        else:
            with pytest.raises(ArgumentError) as exception:
                TrustDomain.parse(td)
            assert (
                str(exception.value)
                == 'Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores.'
            )


def test_to_string():
    trust_domain = TrustDomain.parse('domain.test')
    assert str(trust_domain) == 'domain.test'


def test_compare_multiple_equal_trust_domains():
    trust_domain1 = TrustDomain.parse('domain.test')
    trust_domain2 = TrustDomain.parse('domain.test')
    assert trust_domain1 == trust_domain2


def test_compare_different_trust_domains():
    trust_domain1 = TrustDomain.parse('domain.test')
    trust_domain2 = TrustDomain.parse('other.test')
    assert not trust_domain1 == trust_domain2


def test_not_equal_when_different_objects():
    trust_domain = TrustDomain.parse('domain.test')
    td_list = list([trust_domain])
    assert trust_domain != td_list


def test_as_str_id():
    trust_domain = TrustDomain.parse('example.org')
    assert trust_domain.as_str_id() == 'spiffe://example.org'
