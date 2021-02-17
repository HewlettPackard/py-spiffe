"""
This module manages X.509 SVID objects.
"""

import os

import pem
from typing import List, Union
from typing.io import BinaryIO

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ed448, rsa, ec, dsa
from cryptography.x509 import Certificate

from pyspiffe.spiffe_id.spiffe_id import SpiffeId

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from pyasn1.codec.der.decoder import decode

from pyspiffe.svid.exceptions import (
    InvalidLeafCertificateError,
    InvalidIntermediateCertificateError,
    ParseCertificateError,
    ParsePrivateKeyError,
    X509SvidError,
    StoreCertificateError,
    StorePrivateKeyError,
    LoadCertificateError,
    LoadPrivateKeyError,
)

_CERTS_FILE_MODE = 0o644
_PRIVATE_KEY_FILE_MODE = 0o600

_PRIVATE_KEY_TYPES = Union[
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
    rsa.RSAPrivateKey,
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
]


class X509Svid(object):
    """
    Represents a SPIFFE X.509-SVID

    Contains a SpiffeId, a private key and a chain of X.509 certificates.
    """

    def __init__(
        self,
        spiffe_id: SpiffeId,
        cert_chain: List[Certificate],
        private_key: _PRIVATE_KEY_TYPES,
    ) -> None:
        """Creates a X509Svid instance.

        Args:
            spiffe_id: a SpiffeId instance.
            cert_chain: a list representing a chain of X.509 Certificate
            private_key: a Private Key object
        """

        self.spiffe_id = spiffe_id
        self.cert_chain = cert_chain
        self.private_key = private_key

    def leaf(self) -> Certificate:
        """Returns the Leaf X.509 certificate of the chain."""
        return self.cert_chain[0]

    @classmethod
    def parse_raw(
        cls, certs_chain_bytes: bytes, private_key_bytes: bytes
    ) -> 'X509Svid':
        """Parses the X509-SVID from certificate chain and private key bytes.
        The certificate chain must be ASN.1 DER (concatenated with no intermediate padding if there are more than
        one certificate). The private key must be a PKCS#8 ASN.1 DER.

        It is assumed that the leaf certificate is always the first certificate in the parsed chain.

        Args:
            certs_chain_bytes: chain of X.509 certificates in ASN.1 DER format
            private_key_bytes: private key as PKCS#8 ASN.1 DER

        Returns:
            an instance of a 'X509Svid' containing the chain of certificates, the private key, and the SPIFFE ID of the
            leaf certificate in the chain

        Raises:
            ParseCertificateError: in case the chain of certificates cannot be parsed from the cert_chain_bytes

            ParsePrivateKeyError: in case the private key cannot be parsed from the private_key_bytes

            InvalidLeafCertificateError: in case the leaf certificate does not have a SPIFFE ID in the URI SAN,
                                         in case the leaf certificate is CA,
                                         in case the leaf certificate has 'keyCertSign' as key usage,
                                         in case the leaf certificate does not have 'digitalSignature' as key usage,
                                         in case the leaf certificate does not have 'cRLSign' as key usage

            InvalidIntermediateCertificateError: in case one of the intermediate certificates is not CA,
                                                 in case one of the intermediate certificates does not have 'keyCertSign' as key usage
        """

        chain = cls.process_der_chain(certs_chain_bytes)
        cls.validate_chain(chain)

        private_key = cls.parse_der_private_key(private_key_bytes)
        spiffe_id = cls.extract_spiffe_id(chain[0])

        return X509Svid(spiffe_id, chain, private_key)

    @classmethod
    def parse(cls, certs_chain_bytes: bytes, private_key_bytes: bytes) -> 'X509Svid':
        """Parses the X.509 SVID from PEM blocks containing certificate chain and key
        bytes. The private key must be a PKCS#8 PEM block.

        It is assumed that the leaf certificate is always the first certificate in the parsed chain.

        Args:
            certs_chain_bytes: chain of X.509 certificates in PEM format
            private_key_bytes: private key as PKCS#8 PEM block

        Returns:
            an instance of a 'X509Svid' containing the chain of certificates, the private key, and the SPIFFE ID of the
            leaf certificate in the chain

        Raises:
            ParseCertificateError: in case the chain of certificates cannot be parsed from the cert_chain_bytes

            ParsePrivateKeyError: in case the private key cannot be parsed from the private_key_bytes

            InvalidLeafCertificateError: in case the leaf certificate does not have a SPIFFE ID in the URI SAN,
                                         in case the leaf certificate is CA,
                                         in case the leaf certificate has 'keyCertSign' as key usage,
                                         in case the leaf certificate does not have 'digitalSignature' as key usage,
                                         in case the leaf certificate does not have 'cRLSign' as key usage

            InvalidIntermediateCertificateError: in case one of the intermediate certificates is not CA,
                                                 in case one of the intermediate certificates does not have 'keyCertSign' as key usage
        """

        chain = cls.parse_pem(certs_chain_bytes)

        cls.validate_chain(chain)

        private_key = cls.parse_pem_private_key(private_key_bytes)
        spiffe_id = cls.extract_spiffe_id(chain[0])

        return X509Svid(spiffe_id, chain, private_key)

    @classmethod
    def load(
        cls,
        certs_chain_path: str,
        private_key_path: str,
        encoding: serialization.Encoding,
    ) -> 'X509Svid':
        """Loads the X.509 SVID from PEM or DER encoded files on disk.

        The private key should be without encryption.

        Args:
            certs_chain_path (str): path to the file containing one or more X.509 certificates as PEM blocks
            private_key_path (str): path the file containing a private key as PKCS#8 PEM block
            encoding (serialization.Encoding): the encoding used to serialize the certs and private key, can be
                                            serialization.Encoding.PEM or serialization.Encoding.DER

        Returns:
            an instance of a 'X509Svid' containing the chain of certificates, the private key, and the SPIFFE ID of the
            leaf certificate in the chain

        Raises:
            ValueError: in case the encoding is not either PEM or DER (from serialization.Encoding)

            X509SvidError: in case the file path in certs_chain_path or in private_key_path does not exists or cannot be open

            ParseCertificateError: in case the chain of certificates cannot be parsed from the bytes read from certs_chain_path

            ParsePrivateKeyError: in case the private key cannot be parsed from the bytes read from private_key_path

            InvalidLeafCertificateError: in case the leaf certificate does not have a SPIFFE ID in the URI SAN,
                                         in case the leaf certificate is CA,
                                         in case the leaf certificate has 'keyCertSign' as key usage,
                                         in case the leaf certificate does not have 'digitalSignature' as key usage,
                                         in case the leaf certificate does not have 'cRLSign' as key usage

            InvalidIntermediateCertificateError: in case one of the intermediate certificates is not CA,
                                                 in case one of the intermediate certificates does not have 'keyCertSign' as key usage
        """

        chain_bytes = cls.load_certs_bytes(certs_chain_path)
        key_bytes = cls.load_private_key_bytes(private_key_path)
        if encoding == serialization.Encoding.PEM:
            return cls.parse(chain_bytes, key_bytes)
        elif encoding == serialization.Encoding.DER:
            return cls.parse_raw(chain_bytes, key_bytes)
        else:
            raise ValueError(
                'Encoding not supported: {}. Expected \'PEM\' or \'DER\''.format(
                    encoding
                )
            )

    @classmethod
    def save(
        cls,
        x509_svid: 'X509Svid',
        certs_chain_path: str,
        private_key_path: str,
        encoding: serialization.Encoding,
    ) -> None:
        """Saves the X.509 SVID certs chain and private key in PEM or DER encoded files on disk.

        The private key is stored without encryption, but the file is set with filemode = '0600' (only owner has read/write permission)

        Args:
            x509_svid: the 'X509Svid' that has the certs_chain and private_key to be saved on disk

            certs_chain_path (str): path to the file containing one or more X.509 certificates as PEM blocks
                                    The certs_chain file is configured with a filemode = '0644'

            private_key_path (str): path the file containing a PKCS#8 PEM block
                                    The private_key file is configured with a filemode = '0600'

            encoding (serialization.Encoding): the encoding used to serialize the certs and private key, can be
                                            serialization.Encoding.PEM or serialization.Encoding.DER

        Raises:
            ValueError: in case the encoding is not either PEM or DER (from serialization.Encoding)

            X509SvidError: in the case the file path in certs_chain_path or in private_key_path cannot be open to write

            X509SvidError: in case the certs chain or the private key in the X509Svid cannot be converted to bytes
        """

        if not (encoding is encoding.PEM or encoding is encoding.DER):
            raise ValueError(
                'Encoding not supported: {}. Expected \'PEM\' or \'DER\''.format(
                    encoding
                )
            )

        cls.write_certs_to_file(certs_chain_path, encoding, x509_svid)

        private_key_bytes = cls.extract_private_key_bytes(
            encoding, x509_svid.private_key
        )
        cls.write_private_key_to_file(private_key_path, private_key_bytes)

    @staticmethod
    def load_private_key_bytes(private_key_path: str) -> bytes:
        try:
            with open(private_key_path, 'rb') as key_file:
                return key_file.read()
        except FileNotFoundError:
            raise LoadPrivateKeyError(
                'Private key file not found: {}'.format(private_key_path)
            )
        except Exception as err:
            raise LoadPrivateKeyError(
                'Private key file could not be read: {}'.format(str(err))
            )

    @staticmethod
    def load_certs_bytes(certs_chain_path: str) -> bytes:
        try:
            with open(certs_chain_path, 'rb') as chain_file:
                return chain_file.read()
        except FileNotFoundError:
            raise LoadCertificateError(
                'Certs chain file file not found: {}'.format(certs_chain_path)
            )
        except Exception as err:
            raise LoadCertificateError(
                'Certs chain file could not be read: {}'.format(str(err))
            )

    @classmethod
    def write_private_key_to_file(
        cls, private_key_path: str, private_key_bytes: bytes
    ) -> None:
        try:
            with open(private_key_path, 'wb') as private_key_file:
                os.chmod(private_key_file.name, _PRIVATE_KEY_FILE_MODE)
                private_key_file.write(private_key_bytes)
        except Exception as err:
            raise StorePrivateKeyError(
                'Could not write private key bytes to file: {}'.format(str(err))
            )

    @staticmethod
    def extract_private_key_bytes(
        encoding: serialization.Encoding, private_key: _PRIVATE_KEY_TYPES
    ) -> bytes:
        try:
            return private_key.private_bytes(
                encoding,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        except Exception as err:
            raise X509SvidError(
                'Could extract private key bytes from object: {}'.format(str(err))
            )

    @classmethod
    def write_certs_to_file(
        cls,
        certs_chain_path: str,
        encoding: serialization.Encoding,
        x509_svid: 'X509Svid',
    ) -> None:
        try:
            with open(certs_chain_path, 'wb') as chain_file:
                os.chmod(chain_file.name, _CERTS_FILE_MODE)
                for cert in x509_svid.cert_chain:
                    cls.write_cert_to_file(cert, chain_file, encoding)
        except Exception as err:
            raise StoreCertificateError(
                'Error opening certs chain file: {}'.format(str(err))
            )

    @classmethod
    def write_cert_to_file(
        cls, cert: Certificate, chain_file: BinaryIO, encoding: serialization.Encoding
    ) -> None:
        try:
            chain_bytes = cls.extract_chain_bytes(cert, encoding)
            chain_file.write(chain_bytes)
        except Exception as err:
            raise StoreCertificateError(
                'Error writing certs chain to file: {}'.format(str(err))
            )

    @staticmethod
    def extract_chain_bytes(
        cert: Certificate, encoding: serialization.Encoding
    ) -> bytes:
        try:
            chain_bytes = cert.public_bytes(encoding)
        except Exception as err:
            raise X509SvidError(
                'Could not get certs chain key bytes from object: {}'.format(str(err))
            )

        return chain_bytes

    @staticmethod
    def parse_der_private_key(private_key_bytes: bytes) -> _PRIVATE_KEY_TYPES:
        try:
            return load_der_private_key(private_key_bytes, None, None)
        except Exception as err:
            raise ParsePrivateKeyError(str(err))

    @staticmethod
    def parse_pem_private_key(private_key_bytes: bytes) -> _PRIVATE_KEY_TYPES:
        try:
            return load_pem_private_key(private_key_bytes, None, None)
        except Exception as err:
            raise ParsePrivateKeyError(str(err))

    @staticmethod
    def process_der_chain(certs_chain_bytes: bytes) -> List[Certificate]:
        chain = []
        try:
            leaf = x509.load_der_x509_certificate(certs_chain_bytes, default_backend())
            chain.append(leaf)
            _, remaining_data = decode(certs_chain_bytes)
            while len(remaining_data) > 0:
                cert = x509.load_der_x509_certificate(remaining_data, default_backend())
                chain.append(cert)
                _, remaining_data = decode(remaining_data)
        except Exception as err:
            raise ParseCertificateError(str(err))

        return chain

    @staticmethod
    def parse_pem(pem_bytes: bytes) -> List[Certificate]:
        result = []
        parsed_certs = pem.parse(pem_bytes)
        for cert in parsed_certs:
            try:
                x509_cert = x509.load_pem_x509_certificate(
                    cert.as_bytes(), default_backend()
                )
                result.append(x509_cert)
            except Exception:
                raise ParseCertificateError('Unable to load certificate')

        if len(result) < 1:
            raise ParseCertificateError('Unable to load certificate')
        return result

    @staticmethod
    def extract_spiffe_id(cert: Certificate) -> SpiffeId:
        ext = cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        sans = ext.value.get_values_for_type(x509.UniformResourceIdentifier)
        if len(sans) == 0:
            raise InvalidLeafCertificateError(
                'Certificate does not contain a SPIFFE ID in the URI SAN.'
            )
        return SpiffeId.parse(sans[0])

    @classmethod
    def validate_chain(cls, cert_chain: List[Certificate]) -> None:
        leaf = cert_chain[0]
        cls.validate_leaf_certificate(leaf)

        for cert in cert_chain[1:]:
            cls.validate_intermediate_certificate(cert)

    @staticmethod
    def validate_leaf_certificate(leaf: Certificate) -> None:
        basic_constraints = leaf.extensions.get_extension_for_oid(
            x509.ExtensionOID.BASIC_CONSTRAINTS
        )
        if basic_constraints.value.ca:
            raise InvalidLeafCertificateError(
                'Leaf certificate must not have CA flag set to true.'
            )
        key_usage = leaf.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
        if not key_usage.value.digital_signature:
            raise InvalidLeafCertificateError(
                'Leaf certificate must have \'digitalSignature\' as key usage.'
            )
        if key_usage.value.key_cert_sign:
            raise InvalidLeafCertificateError(
                'Leaf certificate must not have \'keyCertSign\' as key usage.'
            )
        if key_usage.value.crl_sign:
            raise InvalidLeafCertificateError(
                'Leaf certificate must not have \'cRLSign\' as key usage.'
            )

    @staticmethod
    def validate_intermediate_certificate(cert: Certificate) -> None:
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.BASIC_CONSTRAINTS
        )
        if not basic_constraints.value.ca:
            raise InvalidIntermediateCertificateError(
                'Signing certificate must have CA flag set to true.'
            )
        key_usage = cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
        if not key_usage.value.key_cert_sign:
            raise InvalidIntermediateCertificateError(
                'Signing certificate must have \'keyCertSign\' as key usage.'
            )
