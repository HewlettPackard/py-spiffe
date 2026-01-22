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

import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate

from spiffe.spiffe_id.spiffe_id import SpiffeId
from spiffe.errors import ArgumentError
from spiffe.svid.errors import (
    InvalidLeafCertificateError,
    InvalidIntermediateCertificateError,
)
from spiffe.utils.errors import (
    LoadCertificateError,
    LoadPrivateKeyError,
    StoreCertificateError,
    StorePrivateKeyError,
    ParseCertificateError,
    ParsePrivateKeyError,
)
from spiffe.svid.x509_svid import X509Svid, _extract_spiffe_id
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from testutils.certs import TEST_CERTS_DIR


@pytest.fixture
def clean_files():
    files_to_clean = []

    yield files_to_clean

    # Cleanup code
    for file_path in files_to_clean:
        if os.path.exists(file_path):
            os.remove(file_path)


def test_create_x509_svid(mocker):
    fake_spiffe_id = mocker.Mock()
    fake_cert_chain = [mocker.Mock()]
    fake_private_key = mocker.Mock()

    res = X509Svid(
        spiffe_id=fake_spiffe_id,
        cert_chain=fake_cert_chain,
        private_key=fake_private_key,
    )

    assert res.spiffe_id == fake_spiffe_id
    assert len(res.cert_chain) == len(fake_cert_chain)
    assert res.private_key == fake_private_key


def test_create_x509_svid_no_spiffe_id(mocker):
    with pytest.raises(ArgumentError) as exc_info:
        X509Svid(spiffe_id=None, cert_chain=[mocker.Mock()], private_key=mocker.Mock())

    assert str(exc_info.value) == 'spiffe_id cannot be None'


def test_create_x509_svid_no_cert_chain(mocker):
    with pytest.raises(ArgumentError) as exc_info:
        X509Svid(spiffe_id=mocker.Mock(), cert_chain=[], private_key=mocker.Mock())

    assert str(exc_info.value) == 'cert_chain cannot be empty'


def test_create_x509_svid_no_private_key(mocker):
    with pytest.raises(ArgumentError) as exc_info:
        X509Svid(spiffe_id=mocker.Mock(), cert_chain=[mocker.Mock()], private_key=None)

    assert str(exc_info.value) == 'private_key cannot be None'


def test_parse_raw_chain_and_ec_key():
    chain_bytes = read_bytes('1-chain.der')
    key_bytes = read_bytes('1-key.der')

    x509_svid = X509Svid.parse_raw(chain_bytes, key_bytes)

    expected_spiffe_id = SpiffeId('spiffe://example.org/service')
    assert x509_svid.spiffe_id == expected_spiffe_id
    assert len(x509_svid.cert_chain) == 2
    assert isinstance(x509_svid.leaf, Certificate)
    assert isinstance(x509_svid.private_key, ec.EllipticCurvePrivateKey)
    assert _extract_spiffe_id(x509_svid.leaf) == expected_spiffe_id


def test_parse_chain_and_ec_key():
    chain_bytes = read_bytes('2-chain.pem')
    key_bytes = read_bytes('2-key.pem')

    x509_svid = X509Svid.parse(chain_bytes, key_bytes)

    expected_spiffe_id = SpiffeId('spiffe://example.org/service')
    assert x509_svid.spiffe_id == SpiffeId('spiffe://example.org/service')
    assert len(x509_svid.cert_chain) == 2
    assert isinstance(x509_svid.leaf, Certificate)
    assert isinstance(x509_svid.cert_chain[1], Certificate)
    assert isinstance(x509_svid.private_key, ec.EllipticCurvePrivateKey)
    assert _extract_spiffe_id(x509_svid.leaf) == expected_spiffe_id


def test_parse_leaf_only_and_rsa_key():
    chain_bytes = read_bytes('3-good-leaf-only.pem')
    key_bytes = read_bytes('3-key-pkcs8-rsa.pem')

    x509_svid = X509Svid.parse(chain_bytes, key_bytes)

    expected_spiffe_id = SpiffeId('spiffe://example.org/workload-1')
    assert x509_svid.spiffe_id == expected_spiffe_id
    assert len(x509_svid.cert_chain) == 1
    assert isinstance(x509_svid.leaf, Certificate)
    assert isinstance(x509_svid.private_key, rsa.RSAPrivateKey)
    assert _extract_spiffe_id(x509_svid.leaf) == expected_spiffe_id


def test_parse_raw_missing_certificate():
    chain_bytes = read_bytes('1-key.der')
    key_bytes = read_bytes('1-key.der')

    with pytest.raises(ParseCertificateError) as exception:
        X509Svid.parse_raw(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Error parsing certificate: Unable to parse DER X.509 certificate'
    )


def test_parse_missing_certificate():
    chain_bytes = read_bytes('2-key.pem')
    key_bytes = read_bytes('2-key.pem')

    with pytest.raises(ParseCertificateError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Error parsing certificate: Unable to parse PEM X.509 certificate'
    )


def test_parse_raw_missing_key():
    chain_bytes = read_bytes('1-chain.der')
    key_bytes = read_bytes('1-chain.der')

    with pytest.raises(ParsePrivateKeyError) as exception:
        X509Svid.parse_raw(chain_bytes, key_bytes)

    assert exception is not None
    assert "Could not deserialize key data" in str(exception.value)
    assert "ASN.1 parsing error" in str(exception.value)


def test_parse_missing_key():
    chain_bytes = read_bytes('2-chain.pem')
    key_bytes = read_bytes('2-chain.pem')

    with pytest.raises(ParsePrivateKeyError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert exception is not None
    assert "Error parsing private key" in str(exception.value)


def test_parse_raw_corrupted_certificate():
    chain_bytes = read_bytes('corrupted')
    key_bytes = read_bytes('1-key.der')

    with pytest.raises(ParseCertificateError) as exception:
        X509Svid.parse_raw(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Error parsing certificate: Unable to parse DER X.509 certificate'
    )


def test_parse_corrupted_certificate():
    chain_bytes = read_bytes('corrupted')
    key_bytes = read_bytes('2-key.pem')

    with pytest.raises(ParseCertificateError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Error parsing certificate: Unable to parse PEM X.509 certificate'
    )


def test_parse_raw_corrupted_private_key():
    chain_bytes = read_bytes('1-chain.der')
    key_bytes = read_bytes('corrupted')

    with pytest.raises(ParsePrivateKeyError) as exception:
        X509Svid.parse_raw(chain_bytes, key_bytes)

    assert exception is not None
    assert "Could not deserialize key data" in str(exception.value)
    assert "ASN.1 parsing error" in str(exception.value)


def test_parse_corrupted_private_key():
    chain_bytes = read_bytes('2-chain.pem')
    key_bytes = read_bytes('corrupted')

    with pytest.raises(ParsePrivateKeyError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert exception is not None
    assert "Unable to load PEM file" in str(exception.value)


def test_parse_invalid_spiffe_id():
    chain_bytes = read_bytes('wrong-empty-spiffe-id.pem')
    key_bytes = read_bytes('2-key.pem')

    with pytest.raises(InvalidLeafCertificateError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Invalid leaf certificate: Certificate does not contain a SPIFFE ID in the URI SAN'
    )


def test_parse_leaf_ca_true():
    chain_bytes = read_bytes('wrong-leaf-ca-true.pem')
    key_bytes = read_bytes('2-key.pem')

    with pytest.raises(InvalidLeafCertificateError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Invalid leaf certificate: Leaf certificate must not have CA flag set to true'
    )


def test_parse_no_digital_signature():
    chain_bytes = read_bytes('wrong-leaf-no-digital-signature.pem')
    key_bytes = read_bytes('2-key.pem')

    with pytest.raises(InvalidLeafCertificateError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Invalid leaf certificate: Leaf certificate must have \'digitalSignature\' as key usage'
    )


def test_parse_key_cert_sign():
    chain_bytes = read_bytes('wrong-leaf-cert-sign.pem')
    key_bytes = read_bytes('2-key.pem')

    with pytest.raises(InvalidLeafCertificateError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Invalid leaf certificate: Leaf certificate must not have \'keyCertSign\' as key usage'
    )


def test_parse_crl_sign():
    chain_bytes = read_bytes('wrong-leaf-crl-sign.pem')
    key_bytes = read_bytes('2-key.pem')

    with pytest.raises(InvalidLeafCertificateError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Invalid leaf certificate: Leaf certificate must not have \'cRLSign\' as key usage'
    )


def test_parse_intermediate_no_ca():
    chain_bytes = read_bytes('wrong-intermediate-no-ca.pem')
    key_bytes = read_bytes('2-key.pem')

    with pytest.raises(InvalidIntermediateCertificateError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Invalid intermediate certificate: Signing certificate must have CA flag set to true'
    )


def test_parse_intermediate_no_key_cert_sign():
    chain_bytes = read_bytes('wrong-intermediate-no-key-cert-sign.pem')
    key_bytes = read_bytes('2-key.pem')

    with pytest.raises(InvalidIntermediateCertificateError) as exception:
        X509Svid.parse(chain_bytes, key_bytes)

    assert (
        str(exception.value)
        == 'Invalid intermediate certificate: Signing certificate must have \'keyCertSign\' as key usage'
    )


def test_load_from_pem_files():
    chain_path = TEST_CERTS_DIR / '2-chain.pem'
    key_path = TEST_CERTS_DIR / '2-key.pem'

    x509_svid = X509Svid.load(str(chain_path), str(key_path), serialization.Encoding.PEM)

    expected_spiffe_id = SpiffeId('spiffe://example.org/service')
    assert x509_svid.spiffe_id == expected_spiffe_id
    assert len(x509_svid.cert_chain) == 2
    assert isinstance(x509_svid.leaf, Certificate)
    assert isinstance(x509_svid.cert_chain[1], Certificate)
    assert isinstance(x509_svid.private_key, ec.EllipticCurvePrivateKey)
    assert _extract_spiffe_id(x509_svid.leaf) == expected_spiffe_id


def test_extract_spiffe_id_missing_san_extension(mocker):
    """Regression test: Missing SubjectAlternativeName extension should raise InvalidLeafCertificateError."""
    from cryptography import x509

    mock_cert = mocker.Mock()
    mock_extensions = mocker.Mock()
    mock_extensions.get_extension_for_oid.side_effect = x509.ExtensionNotFound(
        "SubjectAlternativeName extension not found",
        x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
    )
    mock_cert.extensions = mock_extensions

    with pytest.raises(InvalidLeafCertificateError) as exception:
        _extract_spiffe_id(mock_cert)

    assert 'SubjectAlternativeName extension' in str(exception.value)


def test_validate_leaf_missing_basic_constraints_extension(mocker):
    """Regression test: Missing BasicConstraints extension in leaf should raise InvalidLeafCertificateError."""
    from cryptography import x509

    mock_cert = mocker.Mock()
    mock_extensions = mocker.Mock()
    mock_extensions.get_extension_for_oid.side_effect = x509.ExtensionNotFound(
        "BasicConstraints extension not found", x509.ExtensionOID.BASIC_CONSTRAINTS
    )
    mock_cert.extensions = mock_extensions

    from spiffe.svid.x509_svid import _validate_leaf_certificate

    with pytest.raises(InvalidLeafCertificateError) as exception:
        _validate_leaf_certificate(mock_cert)

    assert 'BasicConstraints extension' in str(exception.value)


def test_validate_leaf_missing_key_usage_extension(mocker):
    """Regression test: Missing KeyUsage extension in leaf should raise InvalidLeafCertificateError."""
    from cryptography import x509
    from spiffe.svid.x509_svid import _validate_leaf_certificate

    mock_cert = mocker.Mock()
    mock_extensions = mocker.Mock()

    # First call (BasicConstraints) succeeds, second call (KeyUsage) fails
    basic_constraints = mocker.Mock()
    basic_constraints.value = mocker.Mock()
    basic_constraints.value.ca = False

    def get_extension_side_effect(oid):
        if oid == x509.ExtensionOID.BASIC_CONSTRAINTS:
            return basic_constraints
        elif oid == x509.ExtensionOID.KEY_USAGE:
            raise x509.ExtensionNotFound("KeyUsage extension not found", oid)

    mock_extensions.get_extension_for_oid.side_effect = get_extension_side_effect
    mock_cert.extensions = mock_extensions

    with pytest.raises(InvalidLeafCertificateError) as exception:
        _validate_leaf_certificate(mock_cert)

    assert 'KeyUsage extension' in str(exception.value)


def test_validate_intermediate_missing_basic_constraints_extension(mocker):
    """Regression test: Missing BasicConstraints extension in intermediate should raise InvalidIntermediateCertificateError."""
    from cryptography import x509
    from spiffe.svid.x509_svid import _validate_intermediate_certificate

    mock_cert = mocker.Mock()
    mock_extensions = mocker.Mock()
    mock_extensions.get_extension_for_oid.side_effect = x509.ExtensionNotFound(
        "BasicConstraints extension not found", x509.ExtensionOID.BASIC_CONSTRAINTS
    )
    mock_cert.extensions = mock_extensions

    with pytest.raises(InvalidIntermediateCertificateError) as exception:
        _validate_intermediate_certificate(mock_cert)

    assert 'BasicConstraints extension' in str(exception.value)


def test_validate_intermediate_missing_key_usage_extension(mocker):
    """Regression test: Missing KeyUsage extension in intermediate should raise InvalidIntermediateCertificateError."""
    from cryptography import x509
    from spiffe.svid.x509_svid import _validate_intermediate_certificate

    mock_cert = mocker.Mock()
    mock_extensions = mocker.Mock()

    # First call (BasicConstraints) succeeds, second call (KeyUsage) fails
    basic_constraints = mocker.Mock()
    basic_constraints.value = mocker.Mock()
    basic_constraints.value.ca = True

    def get_extension_side_effect(oid):
        if oid == x509.ExtensionOID.BASIC_CONSTRAINTS:
            return basic_constraints
        elif oid == x509.ExtensionOID.KEY_USAGE:
            raise x509.ExtensionNotFound("KeyUsage extension not found", oid)

    mock_extensions.get_extension_for_oid.side_effect = get_extension_side_effect
    mock_cert.extensions = mock_extensions

    with pytest.raises(InvalidIntermediateCertificateError) as exception:
        _validate_intermediate_certificate(mock_cert)

    assert 'KeyUsage extension' in str(exception.value)


def test_load_from_der_files():
    chain_path = TEST_CERTS_DIR / '1-chain.der'
    key_path = TEST_CERTS_DIR / '1-key.der'

    x509_svid = X509Svid.load(str(chain_path), str(key_path), serialization.Encoding.DER)

    expected_spiffe_id = SpiffeId('spiffe://example.org/service')
    assert x509_svid.spiffe_id == expected_spiffe_id
    assert len(x509_svid.cert_chain) == 2
    assert isinstance(x509_svid.leaf, Certificate)
    assert isinstance(x509_svid.cert_chain[1], Certificate)
    assert isinstance(x509_svid.private_key, ec.EllipticCurvePrivateKey)
    assert _extract_spiffe_id(x509_svid.leaf) == expected_spiffe_id


def test_load_non_existent_cert_file():
    chain_path = 'no-exists'
    key_path = '2-key.pem'

    with pytest.raises(LoadCertificateError) as exception:
        X509Svid.load(chain_path, key_path, serialization.Encoding.PEM)

    assert (
        str(exception.value)
        == 'Error loading certificate from file: File not found: no-exists'
    )


def test_load_non_existent_key_bytes():
    chain_path = TEST_CERTS_DIR / '2-chain.pem'
    key_path = 'no-exists'

    with pytest.raises(LoadPrivateKeyError) as exception:
        X509Svid.load(str(chain_path), key_path, serialization.Encoding.PEM)

    assert (
        str(exception.value)
        == 'Error loading private key from file: File not found: no-exists'
    )


def test_load_cannot_read_key_bytes(mocker):
    mocker.patch(
        'spiffe.svid.x509_svid.load_certificates_bytes_from_file',
        return_value=b'bytes',
        autospec=True,
    )
    mocker.patch('builtins.open', side_effect=Exception('Error msg'), autospec=True)

    with pytest.raises(LoadPrivateKeyError) as err:
        X509Svid.load('chain_path', 'key-no-exists', serialization.Encoding.PEM)

    assert 'Error loading private key from file: File could not be read: Error msg' == str(
        err.value
    )


def test_save_chain_and_ec_key_as_pem(tmpdir, clean_files):
    chain_bytes = read_bytes('2-chain.pem')
    key_bytes = read_bytes('2-key.pem')

    # create the X509Svid to be saved
    x509_svid = X509Svid.parse(chain_bytes, key_bytes)
    # temp files to store the certs and private_key

    chain_pem_file = tmpdir.join('chain.pem')
    key_pem_file = tmpdir.join('key.pem')

    # Add files to the cleanup list
    clean_files.extend([chain_pem_file, key_pem_file])

    x509_svid.save(chain_pem_file, key_pem_file, serialization.Encoding.PEM)

    # now load the saved svid, and check that everything was stored correctly
    saved_svid = X509Svid.load(chain_pem_file, key_pem_file, serialization.Encoding.PEM)
    expected_spiffe_id = SpiffeId('spiffe://example.org/service')
    assert saved_svid.spiffe_id == expected_spiffe_id
    assert len(saved_svid.cert_chain) == 2
    assert isinstance(saved_svid.leaf, Certificate)
    assert isinstance(x509_svid.cert_chain[1], Certificate)
    assert isinstance(saved_svid.private_key, ec.EllipticCurvePrivateKey)
    assert _extract_spiffe_id(saved_svid.leaf) == expected_spiffe_id


def test_save_chain_and_rsa_key_as_der(tmpdir, clean_files):
    chain_bytes = read_bytes('3-good-leaf-only.pem')
    key_bytes = read_bytes('3-key-pkcs8-rsa.pem')

    # create the X509Svid to be saved
    x509_svid = X509Svid.parse(chain_bytes, key_bytes)

    # temp files to store the certs and private_key
    chain_file = tmpdir.join('chain.der')
    key_file = tmpdir.join('key.der')

    # Add files to the cleanup list
    clean_files.extend([chain_file, key_file])

    x509_svid.save(chain_file, key_file, serialization.Encoding.DER)

    # now load the saved svid, and check that everything was stored correctly
    saved_svid = X509Svid.load(chain_file, key_file, serialization.Encoding.DER)
    expected_spiffe_id = SpiffeId('spiffe://example.org/workload-1')
    assert saved_svid.spiffe_id == expected_spiffe_id
    assert len(saved_svid.cert_chain) == 1
    assert isinstance(saved_svid.leaf, Certificate)
    assert isinstance(saved_svid.private_key, rsa.RSAPrivateKey)
    assert _extract_spiffe_id(saved_svid.leaf) == expected_spiffe_id


def test_save_non_supported_encoding(tmpdir, clean_files):
    chain_bytes = read_bytes('3-good-leaf-only.pem')
    key_bytes = read_bytes('3-key-pkcs8-rsa.pem')

    # create the X509Svid to be saved
    x509_svid = X509Svid.parse(chain_bytes, key_bytes)

    chain_file = tmpdir.join('chain_file')
    key_file = tmpdir.join('key_file')

    # Add files to the cleanup list
    clean_files.extend([chain_file, key_file])

    with pytest.raises(ArgumentError) as err:
        x509_svid.save(chain_file, key_file, serialization.Encoding.Raw)

    assert (
        str(err.value) == 'Encoding not supported: Encoding.Raw. Expected \'PEM\' or \'DER\''
    )


def test_save_error_writing_x509_svid_to_file(mocker, tmpdir, clean_files):
    chain_bytes = read_bytes('3-good-leaf-only.pem')
    key_bytes = read_bytes('3-key-pkcs8-rsa.pem')

    # create the X509Svid to be saved
    x509_svid = X509Svid.parse(chain_bytes, key_bytes)

    chain_file = tmpdir.join('chain_file')
    key_file = tmpdir.join('key_file')

    # Add files to the cleanup list
    clean_files.extend([chain_file, key_file])

    mocker.patch('builtins.open', side_effect=Exception('Error msg'), autospec=True)
    with pytest.raises(StoreCertificateError) as exception:
        x509_svid.save(chain_file, key_file, serialization.Encoding.PEM)

    assert str(exception.value) == 'Error saving certificate to file: Error msg'


def test_save_error_extracting_private_key(mocker, tmpdir, clean_files):
    chain_bytes = read_bytes('3-good-leaf-only.pem')
    key_bytes = read_bytes('3-key-pkcs8-rsa.pem')

    # create the X509Svid to be saved
    x509_svid = X509Svid.parse(chain_bytes, key_bytes)

    mock_private_key = mocker.Mock()
    mock_private_key.private_bytes.side_effect = Exception('Error msg')
    x509_svid._private_key = mock_private_key

    chain_file = tmpdir.join('chain_file')
    key_file = tmpdir.join('key_file')

    # Add files to the cleanup list
    clean_files.extend([chain_file, key_file])

    with pytest.raises(StorePrivateKeyError) as exception:
        x509_svid.save(chain_file, key_file, serialization.Encoding.PEM)

    assert (
        str(exception.value)
        == 'Error saving private key to file: Could not serialize private key from '
        'bytes: Error msg'
    )


def test_load_non_supported_encoding():
    chain_path = TEST_CERTS_DIR / '2-chain.pem'
    key_path = TEST_CERTS_DIR / '2-key.pem'
    with pytest.raises(ArgumentError) as err:
        X509Svid.load(str(chain_path), str(key_path), serialization.Encoding.OpenSSH)

    assert (
        str(err.value) == "Encoding not supported: Encoding.OpenSSH. Expected 'PEM' or 'DER'"
    )


def test_get_chain_returns_a_copy():
    chain_bytes = read_bytes('1-chain.der')
    key_bytes = read_bytes('1-key.der')

    x509_svid = X509Svid.parse_raw(chain_bytes, key_bytes)

    assert x509_svid.cert_chain is not x509_svid._cert_chain


def read_bytes(filename):
    path = TEST_CERTS_DIR / filename
    with open(path, 'rb') as file:
        return file.read()
