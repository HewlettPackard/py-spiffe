import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import Certificate

from pyspiffe.spiffe_id.spiffe_id import SpiffeId
from pyspiffe.utils.certificate_utils import (
    parse_pem_certificates,
    parse_der_certificates,
    load_certificates_bytes_from_file,
    write_certificates_to_file,
    serialize_certificate,
    load_private_key_from_file,
    write_private_key_to_file,
    parse_der_private_key,
    parse_pem_private_key,
)
from pyspiffe.utils.exceptions import (
    X509CertificateError,
    ParseCertificateError,
    LoadCertificateError,
    StoreCertificateError,
    StorePrivateKeyError,
    ParsePrivateKeyError,
    LoadPrivateKeyError,
)

_EXPECTED_SPIFFE_ID = SpiffeId.parse('spiffe://example.org/service')
_TEST_CERTS_PATH = 'test/svid/x509svid/certs/{}'


def test_parse_der_certificates():
    certs_bytes = _read_bytes('1-chain.der')

    certs = parse_der_certificates(certs_bytes)

    assert len(certs) == 2
    assert isinstance(certs[0], Certificate)
    assert isinstance(certs[1], Certificate)
    assert _extract_spiffe_id(certs[0]) == _EXPECTED_SPIFFE_ID


def test_parse_pem_certificates():
    certs_bytes = _read_bytes('2-chain.pem')

    certs = parse_pem_certificates(certs_bytes)

    assert len(certs) == 2
    assert isinstance(certs[0], Certificate)
    assert isinstance(certs[1], Certificate)
    assert _extract_spiffe_id(certs[0]) == _EXPECTED_SPIFFE_ID


def test_parse_der_corrupted_certificate():
    certs_bytes = _read_bytes('corrupted')

    with pytest.raises(ParseCertificateError) as exception:
        parse_der_certificates(certs_bytes)

    assert str(exception.value) == 'Unable to parse DER X.509 certificate.'


def test_parse_pem_corrupted_certificate():
    certs_bytes = _read_bytes('corrupted')

    with pytest.raises(ParseCertificateError) as exception:
        parse_pem_certificates(certs_bytes)

    assert str(exception.value) == 'Unable to parse PEM X.509 certificate.'


def test_load_certificates_bytes_from_pem_file():
    certs_file_path = _TEST_CERTS_PATH.format('2-chain.pem')

    certs_bytes = load_certificates_bytes_from_file(certs_file_path)
    certs = parse_pem_certificates(certs_bytes)

    assert len(certs) == 2
    assert isinstance(certs[0], Certificate)
    assert isinstance(certs[1], Certificate)
    assert _extract_spiffe_id(certs[0]) == _EXPECTED_SPIFFE_ID


def test_load_certificates_bytes_from_der_file():
    certs_file_path = _TEST_CERTS_PATH.format('1-chain.der')

    certs_bytes = load_certificates_bytes_from_file(certs_file_path)
    certs = parse_der_certificates(certs_bytes)

    assert len(certs) == 2
    assert isinstance(certs[0], Certificate)
    assert isinstance(certs[1], Certificate)
    assert _extract_spiffe_id(certs[0]) == _EXPECTED_SPIFFE_ID


def test_load_certificates_bytes_from_file_raise_file_not_found():
    with pytest.raises(LoadCertificateError) as exception:
        load_certificates_bytes_from_file('path_not_found')

    assert (
        str(exception.value)
        == 'Error loading certificate from file: Certificates file not found: path_not_found.'
    )


def test_load_certificates_bytes_from_file_raise_exception(mocker):
    mocker.patch('builtins.open', side_effect=Exception('Error msg'), autospec=True)

    with pytest.raises(LoadCertificateError) as exception:
        load_certificates_bytes_from_file('path')

    assert (
        str(exception.value)
        == 'Error loading certificate from file: Certificates file could not be read: Error msg.'
    )


def test_write_certificates_to_file_as_pem(tmpdir):
    certs_file_path = _TEST_CERTS_PATH.format('1-chain.der')
    certs_bytes = load_certificates_bytes_from_file(certs_file_path)
    certs = parse_der_certificates(certs_bytes)

    # temp files to store the certs and private_key
    cert_dest_file = tmpdir.join('cert.pem')

    write_certificates_to_file(cert_dest_file, serialization.Encoding.PEM, certs)

    certs_bytes = load_certificates_bytes_from_file(cert_dest_file)
    saved_cert = parse_pem_certificates(certs_bytes)[0]

    assert isinstance(saved_cert, Certificate)
    assert _extract_spiffe_id(saved_cert) == _EXPECTED_SPIFFE_ID


def test_write_certificates_to_file_raise_error(mocker):
    mocker.patch('builtins.open', autospec=True)
    mock_cert = mocker.Mock()
    mock_cert.public_bytes.side_effect = Exception('Fake Error')
    des_file = mocker.Mock()

    with pytest.raises(StoreCertificateError) as exc_info:
        write_certificates_to_file(des_file, serialization.Encoding.PEM, [mock_cert])

    assert (
        str(exc_info.value)
        == 'Error saving certificate to file: Error writing X.509 SVID to file: Could not get bytes from object: Fake Error.'
    )


def test_extract_der_bytes_from_certificate():
    certs_bytes = _read_bytes('1-chain.der')
    cert = parse_der_certificates(certs_bytes)[0]

    cert_bytes = serialize_certificate(cert, serialization.Encoding.DER)

    cert = parse_der_certificates(cert_bytes)[0]

    assert isinstance(cert, Certificate)
    assert _extract_spiffe_id(cert) == _EXPECTED_SPIFFE_ID


def test_extract_pem_bytes_from_certificate():
    certs_bytes = _read_bytes('2-chain.pem')
    cert = parse_pem_certificates(certs_bytes)[0]

    cert_bytes = serialize_certificate(cert, serialization.Encoding.PEM)
    cert = parse_pem_certificates(cert_bytes)[0]

    assert isinstance(cert, Certificate)
    assert _extract_spiffe_id(cert) == _EXPECTED_SPIFFE_ID


def test_serialize_certificate(mocker):
    mock_cert = mocker.Mock()
    fake_bytes = b'some_bytes'
    mock_cert.public_bytes.return_value = fake_bytes

    res = serialize_certificate(mock_cert, serialization.Encoding.PEM)

    assert res == fake_bytes


def test_serialize_certificate_raise_error(mocker):
    mock_cert = mocker.Mock()
    mock_cert.public_bytes.side_effect = Exception('Fake Error')

    with pytest.raises(X509CertificateError) as exc_info:
        serialize_certificate(mock_cert, serialization.Encoding.PEM)

    assert str(exc_info.value) == 'Could not get bytes from object: Fake Error.'


def test_load_private_key_from_file(tmpdir):
    key_bytes = _read_bytes('1-key.der')
    private_key = parse_der_private_key(key_bytes)

    # temp file to store the private_key
    key_dest_file = tmpdir.join('key.der')

    write_private_key_to_file(key_dest_file, serialization.Encoding.DER, private_key)

    key_bytes = load_private_key_from_file(key_dest_file)
    saved_key = parse_der_private_key(key_bytes)

    assert isinstance(saved_key, ec.EllipticCurvePrivateKey)


def test_load_private_key_from_file_raise_error_file_not_found(mocker):
    mocker.patch('builtins.open', side_effect=FileNotFoundError(), autospec=True)

    with pytest.raises(LoadPrivateKeyError) as exc_info:
        load_private_key_from_file('key_path')

    assert (
        str(exc_info.value)
        == 'Error loading private key from file: Private key file not found: key_path.'
    )


def test_load_private_key_from_file_raise_error(mocker):
    mocker.patch('builtins.open', side_effect=Exception('Fake Error'), autospec=True)

    with pytest.raises(LoadPrivateKeyError) as exc_info:
        load_private_key_from_file('key_path')

    assert (
        str(exc_info.value)
        == 'Error loading private key from file: Private key file could not be read: Fake Error.'
    )


def test_write_private_key_to_file(tmpdir):
    key_bytes = _read_bytes('1-key.der')
    private_key = parse_der_private_key(key_bytes)

    # temp file to store the private_key
    key_dest_file = tmpdir.join('key.der')

    write_private_key_to_file(key_dest_file, serialization.Encoding.DER, private_key)

    key_bytes = load_private_key_from_file(key_dest_file)
    saved_key = parse_der_private_key(key_bytes)

    assert isinstance(saved_key, ec.EllipticCurvePrivateKey)


def test_write_private_key_to_file_raise_error(mocker):
    mocker.patch('builtins.open', side_effect=Exception('Fake Error'), autospec=True)
    mock_private_key = mocker.Mock()

    with pytest.raises(StorePrivateKeyError) as exc_info:
        write_private_key_to_file(
            'private_key_path',
            serialization.Encoding.PEM,
            mock_private_key,
        )

    assert (
        str(exc_info.value)
        == 'Error saving private key to file: Could not write private key bytes to file: Fake Error.'
    )


def test_write_private_key_to_file_raise_error_cannot_extract_bytes(mocker):
    mocker.patch('builtins.open', autospec=True)
    mock_private_key = mocker.Mock()
    mock_private_key.private_bytes.side_effect = Exception('Fake Error')

    with pytest.raises(StorePrivateKeyError) as exc_info:
        write_private_key_to_file(
            'private_key_path',
            serialization.Encoding.PEM,
            mock_private_key,
        )

    assert (
        str(exc_info.value)
        == 'Error saving private key to file: Could not write private key bytes to file: Could not extract private key bytes from object: Fake Error.'
    )


def test_parse_der_private_key():
    key_bytes = _read_bytes('1-key.der')
    private_key = parse_der_private_key(key_bytes)

    assert isinstance(private_key, ec.EllipticCurvePrivateKey)


def test_parse_der_private_key_raise_error():
    key_bytes = b'some bytes'

    with pytest.raises(ParsePrivateKeyError) as exc_info:
        parse_der_private_key(key_bytes)

    assert str(exc_info.value).startswith('Error parsing private key:')


def test_parse_pem_private_key():
    key_bytes = _read_bytes('2-key.pem')
    private_key = parse_pem_private_key(key_bytes)

    assert isinstance(private_key, ec.EllipticCurvePrivateKey)


def test_parse_pem_private_key_raise_error():
    key_bytes = b'some bytes'

    with pytest.raises(ParsePrivateKeyError) as exc_info:
        parse_pem_private_key(key_bytes)

    assert str(exc_info.value).startswith('Error parsing private key:')


def _read_bytes(filename):
    path = _TEST_CERTS_PATH.format(filename)
    with open(path, 'rb') as file:
        return file.read()


def _extract_spiffe_id(cert: Certificate) -> SpiffeId:
    ext = cert.extensions.get_extension_for_oid(
        x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    sans = ext.value.get_values_for_type(x509.UniformResourceIdentifier)
    return SpiffeId.parse(sans[0])
