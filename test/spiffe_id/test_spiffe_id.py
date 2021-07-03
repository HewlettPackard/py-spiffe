import pytest

from pyspiffe.exceptions import SpiffeIdError, ArgumentError
from pyspiffe.spiffe_id.spiffe_id import SpiffeId, TrustDomain

TD_CHARS = {
    'a',
    'b',
    'c',
    'd',
    'e',
    'f',
    'g',
    'h',
    'i',
    'j',
    'k',
    'l',
    'm',
    'n',
    'o',
    'p',
    'q',
    'r',
    's',
    't',
    'u',
    'v',
    'w',
    'x',
    'y',
    'z',
    '0',
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    '.',
    '-',
    '_',
}

PATH_CHARS = {
    'a',
    'b',
    'c',
    'd',
    'e',
    'f',
    'g',
    'h',
    'i',
    'j',
    'k',
    'l',
    'm',
    'n',
    'o',
    'p',
    'q',
    'r',
    's',
    't',
    'u',
    'v',
    'w',
    'x',
    'y',
    'z',
    'A',
    'B',
    'C',
    'D',
    'E',
    'F',
    'G',
    'H',
    'I',
    'J',
    'K',
    'L',
    'M',
    'N',
    'O',
    'P',
    'Q',
    'R',
    'S',
    'T',
    'U',
    'V',
    'W',
    'X',
    'Y',
    'Z',
    '0',
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    '.',
    '-',
    '_',
}


@pytest.mark.parametrize(
    'trust_domain,path_segments,expected_spiffe_id',
    [
        (
            TrustDomain.parse('example.org'),
            ['/path', '/element'],
            'spiffe://example.org/path/element',
        ),
        (
            TrustDomain.parse('example.org'),
            ['/path', '/element'],
            'spiffe://example.org/path/element',
        ),
        (
            TrustDomain.parse('domain.test'),
            ['/pAth1', '/pATH2'],
            'spiffe://domain.test/pAth1/pATH2',
        ),
        (
            TrustDomain.parse('domain.test'),
            '/pAth1/pATH2',
            'spiffe://domain.test/pAth1/pATH2',
        ),
    ],
)
def test_of_trust_domain_and_segments(trust_domain, path_segments, expected_spiffe_id):
    result = SpiffeId.of(trust_domain, path_segments)
    assert str(result) == expected_spiffe_id


@pytest.mark.parametrize(
    'trust_domain,path_segments,expected_error',
    [
        (
            TrustDomain.parse('example.org'),
            '/',
            'Path cannot have a trailing slash.',
        ),
        (
            TrustDomain.parse('example.org'),
            '//',
            'Path cannot contain empty segments.',
        ),
        (
            TrustDomain.parse('example.org'),
            '/ /',
            'Path segment characters are limited to letters, numbers, dots, dashes, and underscores.',
        ),
        (
            TrustDomain.parse('example.org'),
            '/./',
            'Path cannot contain dot segments.',
        ),
        (
            TrustDomain.parse('example.org'),
            ['/../'],
            'Path cannot contain dot segments.',
        ),
    ],
)
def test_of_trust_domain_and_invalid_segments(
    trust_domain, path_segments, expected_error
):
    with pytest.raises(SpiffeIdError) as exception:
        SpiffeId.of(trust_domain, path_segments)
    assert str(exception.value) == expected_error


@pytest.mark.parametrize(
    'spiffe_id_str,expected_trust_domain,expected_path',
    [
        ('spiffe://example.org', TrustDomain.parse('example.org'), ''),
        (
            'spiffe://example.org/path1/path2',
            TrustDomain.parse('example.org'),
            '/path1/path2',
        ),
    ],
)
def test_parse_spiffe_id_valid(spiffe_id_str, expected_trust_domain, expected_path):
    spiffe_id = SpiffeId.parse(spiffe_id_str)
    assert spiffe_id.trust_domain() == expected_trust_domain
    assert spiffe_id.path() == expected_path


@pytest.mark.parametrize(
    'spiffe_id_str,expected',
    [
        ('', 'SPIFFE ID cannot be empty.'),
        (None, 'SPIFFE ID cannot be empty.'),
        ('192.168.2.2:6688', 'Scheme is missing or invalid.'),
        (
            'http://domain.test/path/element',
            'Scheme is missing or invalid.',
        ),
        ('spiffe:///path/element', 'Trust domain is missing.'),
        (
            'spiffe://domain.test/path/element?query=1',
            'Path segment characters are limited to letters, numbers, dots, dashes, and underscores.',
        ),
        (
            'spiffe://domain.test/path/element#fragment-1',
            'Path segment characters are limited to letters, numbers, dots, dashes, and underscores.',
        ),
        (
            'spiffe://domain.test:8080/path/element',
            'Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores.',
        ),
        (
            'spiffe://user:password@test.org/path/element',
            'Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores.',
        ),
        ('spiffe:path/element', 'Scheme is missing or invalid.'),
        ('spiffe:/path/element', 'Scheme is missing or invalid.'),
        (
            'spiffe://domain.test/path/elem%5uent',
            'Path segment characters are limited to letters, numbers, dots, dashes, and underscores.',
        ),
        ('spiffe://trustdomain/', 'Path cannot have a trailing slash.'),
        ('spiffe://trustdomain/path/other/', 'Path cannot have a trailing slash.'),
        ('spiffe://trustdomain//', 'Path cannot contain empty segments.'),
        ('spiffe://trustdomain/./', 'Path cannot contain dot segments.'),
        ('spiffe://trustdomain/../', 'Path cannot contain dot segments.'),
        (
            'spiffe://trustdomain/ /',
            'Path segment characters are limited to letters, numbers, dots, dashes, and underscores.',
        ),
    ],
)
def test_parse_spiffe_id_from_invalid(spiffe_id_str, expected):
    with pytest.raises(ArgumentError) as exception:
        SpiffeId.parse(spiffe_id_str)

    assert str(exception.value) == expected


def test_equal_spiffe_id():
    trust_domain = TrustDomain.parse('trustdomain')
    spiffeid_1 = SpiffeId.of(trust_domain, '/path1')
    spiffeid_2 = SpiffeId.of(trust_domain, '/path1')
    assert spiffeid_1 == spiffeid_2


def test_equal_spiffe_id_with_multiple_paths():
    trust_domain = TrustDomain.parse('trustdomain')
    spiffeid_1 = SpiffeId.of(trust_domain, ['/PATH1', '/PATH2'])
    spiffeid_2 = SpiffeId.of(trust_domain, ['/PATH1', '/PATH2'])
    assert spiffeid_1 == spiffeid_2


def test_not_equal_spiffe_ids():
    trust_domain = TrustDomain.parse('trustdomain')
    spiffeid_1 = SpiffeId.of(trust_domain, '/path1')
    spiffeid_2 = SpiffeId.of(trust_domain, '/path2')
    assert spiffeid_1 != spiffeid_2


def test_trust_domain_none():
    with pytest.raises(ArgumentError) as exception:
        SpiffeId.of(None, '/path')

    assert str(exception.value) == 'Trust domain is missing.'


def test_of_empty_trust_domain():
    with pytest.raises(ArgumentError) as exception:
        SpiffeId.of('', '/path')

    assert str(exception.value) == 'Trust domain is missing.'


def test_is_member_of():
    spiffe_id = SpiffeId.parse('spiffe://domain.test/path/element')
    trust_domain = TrustDomain.parse('domain.test')
    assert spiffe_id.is_member_of(trust_domain)


def test_is_not_member_of():
    spiffe_id = SpiffeId.parse('spiffe://domain.test/path/element')
    trust_domain = TrustDomain.parse('other.test')
    assert not spiffe_id.is_member_of(trust_domain)


def test_str_when_no_path():
    spiffe_id = SpiffeId.parse('spiffe://domain.test')
    assert str(spiffe_id) == 'spiffe://domain.test'


def test_parse_with_all_chars():
    # Go all the way through 255, which ensures we reject UTF-8 appropriately
    for i in range(0, 255):
        c = chr(i)

        # Don't test '/' since it is the delimiter between path segments
        if c == '/':
            continue

        path = '/path' + c

        if c in PATH_CHARS:
            spiffe_id = SpiffeId.parse('spiffe://trustdomain' + path)
            assert str(spiffe_id) == 'spiffe://trustdomain' + path
        else:
            with pytest.raises(SpiffeIdError) as exception:
                SpiffeId.parse('spiffe://trustdomain' + path)
            assert (
                str(exception.value)
                == 'Path segment characters are limited to letters, numbers, dots, dashes, and underscores.'
            )

        td = 'spiffe://trustdomain' + c
        if c in TD_CHARS:
            spiffe_id = SpiffeId.parse(td)
            assert str(spiffe_id) == td
        else:
            with pytest.raises(SpiffeIdError) as exception:
                SpiffeId.parse(td)
            assert (
                str(exception.value)
                == 'Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores.'
            )


def test_of_with_all_chars():
    # Go all the way through 255, which ensures we reject UTF-8 appropriately
    for i in range(0, 255):
        c = chr(i)

        # Don't test '/' since it is the delimiter between path segments
        if c == '/':
            continue

        path1 = '/Path1' + c
        path2 = '/Path2' + c
        trust_domain = TrustDomain.parse('trustdomain')

        if c in PATH_CHARS:
            spiffe_id = SpiffeId.of(trust_domain, [path1, path2])
            assert str(spiffe_id) == 'spiffe://trustdomain' + path1 + path2
        else:
            with pytest.raises(SpiffeIdError) as exception:
                SpiffeId.of('spiffe://trustdomain', [path1, path2])
            assert (
                str(exception.value)
                == 'Path segment characters are limited to letters, numbers, dots, dashes, and underscores.'
            )
