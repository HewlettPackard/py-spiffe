import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate

from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.svid.exceptions import (
    InvalidLeafCertificateError,
    InvalidIntermediateCertificateError,
    ParseCertificateError,
    ParsePrivateKeyError,
    LoadCertificateError,
    LoadPrivateKeyError,
)
from pyspiffe.svid.x509_svid import X509Svid, _extract_spiffe_id
from cryptography.hazmat.primitives.asymmetric import ec, rsa

_TEST_CERTS_PATH = 'test/svid/x509svid/certs/{}'


def test_parse_raw_chain_and_ec_key():
    chain_bytes = read_bytes('1-chain.der')
    key_bytes = read_bytes('1-key.der')

    x509_svid = X509Svid.parse_raw(chain_bytes, key_bytes)

    expected_spiffe_id = SpiffeId.parse('spiffe://example.org/service')
    assert x509_svid.spiffe_id() == expected_spiffe_id
    assert len(x509_svid.cert_chain()) == 2
    assert isinstance(x509_svid.leaf(), Certificate)
    assert isinstance(x509_svid.private_key(), ec.EllipticCurvePrivateKey)
    assert _extract_spiffe_id(x509_svid.leaf()) == expected_spiffe_id


def test_parse_chain_and_ec_key():
    chain_bytes = read_bytes('2-chain.pem')
    key_bytes = read_bytes('2-key.pem')

    x509_svid = X509Svid.parse(chain_bytes, key_bytes)

    expected_spiffe_id = SpiffeId.parse('spiffe://example.org/service')
    assert x509_svid.spiffe_id() == SpiffeId.parse('spiffe://example.org/service')
    assert len(x509_svid.cert_chain()) == 2
    assert isinstance(x509_svid.leaf(), Certificate)
    assert isinstance(x509_svid.cert_chain()[1], Certificate)
    assert isinstance(x509_svid.private_key(), ec.EllipticCurvePrivateKey)
    assert _extract_spiffe_id(x509_svid.leaf()) == expected_spiffe_id


def test_parse_leaf_only_and_rsa_key():
    chain_bytes = read_bytes('3-good-leaf-only.pem')
    key_bytes = read_bytes('3-key-pkcs8-rsa.pem')

    x509_svid = X509Svid.parse(chain_bytes, key_bytes)

    expected_spiffe_id = SpiffeId.parse('spiffe://example.org/workload-1')
    assert x509_svid.spiffe_id() == expected_spiffe_id
    assert len(x509_svid.cert_chain()) == 1
    assert isinstance(x509_svid.leaf(), Certificate)
    assert isinstance(x509_svid.private_key(), rsa.RSAPrivateKey)
    assert _extract_spiffe_id(x509_svid.leaf()) == expected_spiffe_id


def test_parse_raw_missing_certificate():
    chain_bytes = read_bytes('1-key.der')
    key_bytes = read_bytes('1-key.der')

    with pytest.raises(ParseCertificateError) as exception:
        X509Svid.parse_raw(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Error parsing certificate: Unable to parse DER X.509 certificate.'
    )


def test_parse_missing_certificate():
    chain_bytes = read_bytes('2-key.pem')
    key_bytes = read_bytes('2-key.pem')

    with pytest.raises(ParseCertificateError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Error parsing certificate: Unable to parse PEM X.509 certificate.'
    )


def test_parse_raw_missing_key():
    chain_bytes = read_bytes('1-chain.der')
    key_bytes = read_bytes('1-chain.der')

    with pytest.raises(ParsePrivateKeyError) as exception:
        X509Svid.parse_raw(chain_bytes, key_bytes)

    assert str(exception.value) == (
        'Error parsing private key: Could not deserialize key data. The data may be in an incorrect format '
        'or it may be encrypted with an unsupported algorithm.'
    )


def test_parse_missing_key():
    chain_bytes = read_bytes('2-chain.pem')
    key_bytes = read_bytes('2-chain.pem')

    with pytest.raises(ParsePrivateKeyError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert str(exception.value) == (
        'Error parsing private key: Could not deserialize key data. The data may be in an incorrect format '
        'or it may be encrypted with an unsupported algorithm.'
    )


def test_parse_raw_corrupted_certificate():
    chain_bytes = read_bytes('corrupted')
    key_bytes = read_bytes('1-key.der')

    with pytest.raises(ParseCertificateError) as exception:
        X509Svid.parse_raw(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Error parsing certificate: Unable to parse DER X.509 certificate.'
    )


def test_parse_corrupted_certificate():
    chain_bytes = read_bytes('corrupted')
    key_bytes = read_bytes('2-key.pem')

    with pytest.raises(ParseCertificateError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Error parsing certificate: Unable to parse PEM X.509 certificate.'
    )


def test_parse_raw_corrupted_private_key():
    chain_bytes = read_bytes('1-chain.der')
    key_bytes = read_bytes('corrupted')

    with pytest.raises(ParsePrivateKeyError) as exception:
        X509Svid.parse_raw(chain_bytes, key_bytes)

    assert str(exception.value) == (
        'Error parsing private key: Could not deserialize key data. The data may be in an incorrect format '
        'or it may be encrypted with an unsupported algorithm.'
    )


def test_parse_corrupted_private_key():
    chain_bytes = read_bytes('2-chain.pem')
    key_bytes = read_bytes('corrupted')

    with pytest.raises(ParsePrivateKeyError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert str(exception.value) == (
        'Error parsing private key: Could not deserialize key data. The data may be in an incorrect format '
        'or it may be encrypted with an unsupported algorithm.'
    )


def test_parse_invalid_spiffe_id():
    chain_bytes = read_bytes('wrong-empty-spiffe-id.pem')
    key_bytes = read_bytes('2-key.pem')

    with pytest.raises(InvalidLeafCertificateError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Invalid leaf certificate: Certificate does not contain a SPIFFE ID in the URI SAN.'
    )


def test_parse_leaf_ca_true():
    chain_bytes = read_bytes('wrong-leaf-ca-true.pem')
    key_bytes = read_bytes('2-key.pem')

    with pytest.raises(InvalidLeafCertificateError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Invalid leaf certificate: Leaf certificate must not have CA flag set to true.'
    )


def test_parse_no_digital_signature():
    chain_bytes = read_bytes('wrong-leaf-no-digital-signature.pem')
    key_bytes = read_bytes('2-key.pem')

    with pytest.raises(InvalidLeafCertificateError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Invalid leaf certificate: Leaf certificate must have \'digitalSignature\' as key usage.'
    )


def test_parse_key_cert_sign():
    chain_bytes = read_bytes('wrong-leaf-cert-sign.pem')
    key_bytes = read_bytes('2-key.pem')

    with pytest.raises(InvalidLeafCertificateError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Invalid leaf certificate: Leaf certificate must not have \'keyCertSign\' as key usage.'
    )


def test_parse_crl_sign():
    chain_bytes = read_bytes('wrong-leaf-crl-sign.pem')
    key_bytes = read_bytes('2-key.pem')

    with pytest.raises(InvalidLeafCertificateError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Invalid leaf certificate: Leaf certificate must not have \'cRLSign\' as key usage.'
    )


def test_parse_intermediate_no_ca():
    chain_bytes = read_bytes('wrong-intermediate-no-ca.pem')
    key_bytes = read_bytes('2-key.pem')

    with pytest.raises(InvalidIntermediateCertificateError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Invalid intermediate certificate: Signing certificate must have CA flag set to true.'
    )


def test_parse_intermediate_no_key_cert_sign():
    chain_bytes = read_bytes('wrong-intermediate-no-key-cert-sign.pem')
    key_bytes = read_bytes('2-key.pem')

    with pytest.raises(InvalidIntermediateCertificateError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Invalid intermediate certificate: Signing certificate must have \'keyCertSign\' as key usage.'
    )


def test_load_from_pem_files():
    chain_path = _TEST_CERTS_PATH.format('2-chain.pem')
    key_path = _TEST_CERTS_PATH.format('2-key.pem')

    x509_svid = X509Svid.load(chain_path, key_path, serialization.Encoding.PEM)

    expected_spiffe_id = SpiffeId.parse('spiffe://example.org/service')
    assert x509_svid.spiffe_id() == expected_spiffe_id
    assert len(x509_svid.cert_chain()) == 2
    assert isinstance(x509_svid.leaf(), Certificate)
    assert isinstance(x509_svid.cert_chain()[1], Certificate)
    assert isinstance(x509_svid.private_key(), ec.EllipticCurvePrivateKey)
    assert _extract_spiffe_id(x509_svid.leaf()) == expected_spiffe_id


def test_load_from_der_files():
    chain_path = _TEST_CERTS_PATH.format('1-chain.der')
    key_path = _TEST_CERTS_PATH.format('1-key.der')

    x509_svid = X509Svid.load(chain_path, key_path, serialization.Encoding.DER)

    expected_spiffe_id = SpiffeId.parse('spiffe://example.org/service')
    assert x509_svid.spiffe_id() == expected_spiffe_id
    assert len(x509_svid.cert_chain()) == 2
    assert isinstance(x509_svid.leaf(), Certificate)
    assert isinstance(x509_svid.cert_chain()[1], Certificate)
    assert isinstance(x509_svid.private_key(), ec.EllipticCurvePrivateKey)
    assert _extract_spiffe_id(x509_svid.leaf()) == expected_spiffe_id


def test_load_non_existent_cert_file():
    chain_path = 'no-exists'
    key_path = '2-key.pem'

    with pytest.raises(LoadCertificateError) as exception:
        X509Svid.load(chain_path, key_path, serialization.Encoding.PEM)

    assert (
        str(exception.value)
        == 'Error loading certificate from file: Certificates file not found: no-exists.'
    )


def test_load_non_existent_key_bytes():
    chain_path = _TEST_CERTS_PATH.format('2-chain.pem')
    key_path = 'no-exists'

    with pytest.raises(LoadPrivateKeyError) as exception:
        X509Svid.load(chain_path, key_path, serialization.Encoding.PEM)

    assert (
        str(exception.value)
        == 'Error loading private key from file: Private key file not found: no-exists.'
    )


def test_save_chain_and_ec_key_as_pem(tmpdir):
    chain_bytes = read_bytes('2-chain.pem')
    key_bytes = read_bytes('2-key.pem')

    # create the X509Svid to be saved
    x509_svid = X509Svid.parse(chain_bytes, key_bytes)
    # temp files to store the certs and private_key

    chain_pem_file = tmpdir.join('chain.pem')
    key_pem_file = tmpdir.join('key.pem')

    X509Svid.save(x509_svid, chain_pem_file, key_pem_file, serialization.Encoding.PEM)

    # now load the saved svid, and check that everything was stored correctly
    saved_svid = X509Svid.load(chain_pem_file, key_pem_file, serialization.Encoding.PEM)
    expected_spiffe_id = SpiffeId.parse('spiffe://example.org/service')
    assert saved_svid.spiffe_id() == expected_spiffe_id
    assert len(saved_svid.cert_chain()) == 2
    assert isinstance(saved_svid.leaf(), Certificate)
    assert isinstance(x509_svid.cert_chain()[1], Certificate)
    assert isinstance(saved_svid.private_key(), ec.EllipticCurvePrivateKey)
    assert _extract_spiffe_id(saved_svid.leaf()) == expected_spiffe_id


def test_save_chain_and_rsa_key_as_der(tmpdir):
    chain_bytes = read_bytes('3-good-leaf-only.pem')
    key_bytes = read_bytes('3-key-pkcs8-rsa.pem')

    # create the X509Svid to be saved
    x509_svid = X509Svid.parse(chain_bytes, key_bytes)

    # temp files to store the certs and private_key
    chain_der_file = tmpdir.join('chain.der')
    key_der_file = tmpdir.join('key.der')

    X509Svid.save(x509_svid, chain_der_file, key_der_file, serialization.Encoding.DER)

    # now load the saved svid, and check that everything was stored correctly
    saved_svid = X509Svid.load(chain_der_file, key_der_file, serialization.Encoding.DER)
    expected_spiffe_id = SpiffeId.parse('spiffe://example.org/workload-1')
    assert saved_svid.spiffe_id() == expected_spiffe_id
    assert len(saved_svid.cert_chain()) == 1
    assert isinstance(saved_svid.leaf(), Certificate)
    assert isinstance(saved_svid.private_key(), rsa.RSAPrivateKey)
    assert _extract_spiffe_id(saved_svid.leaf()) == expected_spiffe_id


def test_save_non_supported_encoding():
    chain_bytes = read_bytes('3-good-leaf-only.pem')
    key_bytes = read_bytes('3-key-pkcs8-rsa.pem')

    # create the X509Svid to be saved
    x509_svid = X509Svid.parse(chain_bytes, key_bytes)

    with pytest.raises(ValueError) as err:
        X509Svid.save(x509_svid, 'chain_file', 'key_file', serialization.Encoding.Raw)

    assert (
        str(err.value)
        == 'Encoding not supported: Encoding.Raw. Expected \'PEM\' or \'DER\'.'
    )


def test_load_non_supported_encoding():
    chain_path = _TEST_CERTS_PATH.format('2-chain.pem')
    key_path = _TEST_CERTS_PATH.format('2-key.pem')
    with pytest.raises(ValueError) as err:
        X509Svid.load(chain_path, key_path, serialization.Encoding.OpenSSH)

    assert (
        str(err.value)
        == 'Encoding not supported: Encoding.OpenSSH. Expected \'PEM\' or \'DER\'.'
    )


def test_get_chain_returns_a_copy():
    chain_bytes = read_bytes('1-chain.der')
    key_bytes = read_bytes('1-key.der')

    x509_svid = X509Svid.parse_raw(chain_bytes, key_bytes)

    assert x509_svid.cert_chain() is not x509_svid._cert_chain


def read_bytes(filename):
    path = _TEST_CERTS_PATH.format(filename)
    with open(path, 'rb') as file:
        return file.read()
