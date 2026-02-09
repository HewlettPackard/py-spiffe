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

---

Portions of this code are adapted from urllib3's contrib/pyopenssl.py module
with modifications to support SPIFFE X.509 SVIDs with automatic refresh.

MIT License

Copyright (c) 2008-2020 Andrey Petrov and contributors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from __future__ import annotations

import logging
import ssl
from socket import socket as socket_cls
from socket import timeout
from typing import TYPE_CHECKING, Literal, MutableSequence, TypeAlias, overload

import OpenSSL.SSL
from cryptography import x509
from OpenSSL import SSL, crypto

from spiffe.workloadapi.x509_source import X509Source
from spiffetls.context import create_ssl_context
from spiffetls import util

if TYPE_CHECKING:
    from OpenSSL.crypto import X509

try:
    from cryptography.x509 import UnsupportedExtension  # type: ignore[attr-defined]
except ImportError:
    # UnsupportedExtension is gone in cryptography >= 2.1.0
    class UnsupportedExtension(Exception):  # type: ignore[no-redef]
        pass


_stdlib_to_openssl_verify = {
    ssl.CERT_NONE: OpenSSL.SSL.VERIFY_NONE,
    ssl.CERT_OPTIONAL: OpenSSL.SSL.VERIFY_PEER,
    ssl.CERT_REQUIRED: OpenSSL.SSL.VERIFY_PEER + OpenSSL.SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
}
_openssl_to_stdlib_verify = {v: k for k, v in _stdlib_to_openssl_verify.items()}

# The SSLvX values are the most likely to be missing in the future
# but we check them all just to be sure.
_OP_NO_SSLv2_OR_SSLv3: int = getattr(OpenSSL.SSL, "OP_NO_SSLv2", 0) | getattr(
    OpenSSL.SSL, "OP_NO_SSLv3", 0
)
_OP_NO_TLSv1: int = getattr(OpenSSL.SSL, "OP_NO_TLSv1", 0)
_OP_NO_TLSv1_1: int = getattr(OpenSSL.SSL, "OP_NO_TLSv1_1", 0)
_OP_NO_TLSv1_2: int = getattr(OpenSSL.SSL, "OP_NO_TLSv1_2", 0)
_OP_NO_TLSv1_3: int = getattr(OpenSSL.SSL, "OP_NO_TLSv1_3", 0)

_openssl_to_ssl_minimum_version: dict[int, int] = {
    ssl.TLSVersion.MINIMUM_SUPPORTED: _OP_NO_SSLv2_OR_SSLv3,
    ssl.TLSVersion.TLSv1: _OP_NO_SSLv2_OR_SSLv3,
    ssl.TLSVersion.TLSv1_1: _OP_NO_SSLv2_OR_SSLv3 | _OP_NO_TLSv1,
    ssl.TLSVersion.TLSv1_2: _OP_NO_SSLv2_OR_SSLv3 | _OP_NO_TLSv1 | _OP_NO_TLSv1_1,
    ssl.TLSVersion.TLSv1_3: (
        _OP_NO_SSLv2_OR_SSLv3 | _OP_NO_TLSv1 | _OP_NO_TLSv1_1 | _OP_NO_TLSv1_2
    ),
    ssl.TLSVersion.MAXIMUM_SUPPORTED: (
        _OP_NO_SSLv2_OR_SSLv3 | _OP_NO_TLSv1 | _OP_NO_TLSv1_1 | _OP_NO_TLSv1_2
    ),
}
_openssl_to_ssl_maximum_version: dict[int, int] = {
    ssl.TLSVersion.MINIMUM_SUPPORTED: (
        _OP_NO_SSLv2_OR_SSLv3 | _OP_NO_TLSv1 | _OP_NO_TLSv1_1 | _OP_NO_TLSv1_2 | _OP_NO_TLSv1_3
    ),
    ssl.TLSVersion.TLSv1: (
        _OP_NO_SSLv2_OR_SSLv3 | _OP_NO_TLSv1_1 | _OP_NO_TLSv1_2 | _OP_NO_TLSv1_3
    ),
    ssl.TLSVersion.TLSv1_1: _OP_NO_SSLv2_OR_SSLv3 | _OP_NO_TLSv1_2 | _OP_NO_TLSv1_3,
    ssl.TLSVersion.TLSv1_2: _OP_NO_SSLv2_OR_SSLv3 | _OP_NO_TLSv1_3,
    ssl.TLSVersion.TLSv1_3: _OP_NO_SSLv2_OR_SSLv3,
    ssl.TLSVersion.MAXIMUM_SUPPORTED: _OP_NO_SSLv2_OR_SSLv3,
}

_PeerCertTuple: TypeAlias = tuple[tuple[str, str], ...]
_PeerCertTupleTuple: TypeAlias = tuple[_PeerCertTuple, ...]
_PeerCertRetDictType: TypeAlias = dict[str, str | _PeerCertTupleTuple | _PeerCertTuple]
_PeerCertRetType: TypeAlias = _PeerCertRetDictType | bytes | None

# OpenSSL will only write 16K at a time
SSL_WRITE_BLOCKSIZE = 16384

_logger: logging.Logger = logging.getLogger(__name__)


def _dnsname_to_stdlib(name: str) -> str | None:
    """Converts a dNSName SubjectAlternativeName field to the standard library form.

    Cryptography produces a dNSName as a unicode string that was idna-decoded
    from ASCII bytes. We need to idna-encode that string to get it back, and
    then on Python 3 we also need to convert to unicode via UTF-8 (the stdlib
    uses PyUnicode_FromStringAndSize on it, which decodes via UTF-8).

    Args:
        name: The DNS name to convert.

    Returns:
        The converted name, or None if the name cannot be idna-encoded.
    """

    def idna_encode(name: str) -> bytes | None:
        """Borrowed from the Python Cryptography Project.

        Encodes a DNS name using IDNA encoding, handling wildcards correctly.
        """
        import idna

        try:
            for prefix in ["*.", "."]:
                if name.startswith(prefix):
                    name = name[len(prefix) :]
                    return prefix.encode("ascii") + idna.encode(name)
            return idna.encode(name)
        except idna.core.IDNAError:
            return None

    # Don't send IPv6 addresses through the IDNA encoder.
    if ":" in name:
        return name

    encoded_name = idna_encode(name)
    if encoded_name is None:
        return None
    return encoded_name.decode("utf-8")


def get_subj_alt_name(peer_cert: X509) -> list[tuple[str, str]]:
    """Given a PyOpenSSL certificate, provides all the subject alternative names.

    Args:
        peer_cert: The PyOpenSSL certificate to extract SANs from.

    Returns:
        A list of tuples containing (type, value) pairs for each SAN.
    """
    cert = peer_cert.to_cryptography()

    # We want to find the SAN extension. Ask Cryptography to locate it (it's
    # faster than looping in Python)
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        # No such extension, return the empty list.
        return []
    except (
        x509.DuplicateExtension,
        UnsupportedExtension,
        x509.UnsupportedGeneralNameType,
        UnicodeError,
    ) as e:
        # A problem has been found with the quality of the certificate. Assume
        # no SAN field is present.
        _logger.warning(
            "A problem was encountered with the certificate that prevented "
            "extraction of the SubjectAlternativeName field. This can "
            "affect certificate validation. The error was %s",
            e,
        )
        return []

    # We want to return dNSName and iPAddress fields. We need to cast the IPs
    # back to strings because the match_hostname function wants them as
    # strings.
    # Sadly the DNS names need to be idna encoded and then, on Python 3, UTF-8
    # decoded. This is pretty frustrating, but that's what the standard library
    # does with certificates, and so we need to attempt to do the same.
    # We also want to skip over names which cannot be idna encoded.
    names = [
        ("DNS", name)
        for name in map(_dnsname_to_stdlib, ext.get_values_for_type(x509.DNSName))
        if name is not None
    ]
    names.extend(("IP Address", str(name)) for name in ext.get_values_for_type(x509.IPAddress))

    return names


class WrappedSocket:
    """API-compatibility wrapper for Python OpenSSL's Connection class.

    This class wraps an OpenSSL Connection to provide an interface compatible
    with Python's standard library socket interface.
    """

    def __init__(
        self,
        connection: OpenSSL.SSL.Connection,
        socket: socket_cls,
        suppress_ragged_eofs: bool = True,
    ) -> None:
        """Initialize a wrapped socket.

        Args:
            connection: The OpenSSL Connection to wrap.
            socket: The underlying socket.
            suppress_ragged_eofs: Whether to suppress ragged EOF errors.
        """
        self.connection = connection
        self.socket = socket
        self.suppress_ragged_eofs = suppress_ragged_eofs
        self._io_refs = 0
        self._closed = False

    def fileno(self) -> int:
        """Return the socket's file descriptor."""
        return self.socket.fileno()

    def _decref_socketios(self) -> None:
        """Decrement socket IO reference count."""
        if self._io_refs > 0:
            self._io_refs -= 1
        if self._closed:
            self.close()

    def recv(self, bufsiz: int = 1024, flags: int | None = None) -> bytes:
        """Receive data from the socket.

        Args:
            bufsiz: Maximum amount of data to be received at once.
            flags: Optional socket flags.

        Returns:
            The received data.

        Raises:
            OSError: If a system call error occurs.
            ssl.SSLError: If an SSL error occurs.
            timeout: If a timeout occurs.
        """
        try:
            data = self.connection.recv(bufsiz, flags)
        except OpenSSL.SSL.SysCallError as e:
            if self.suppress_ragged_eofs and e.args == (-1, "Unexpected EOF"):
                return b""
            else:
                raise OSError(e.args[0], str(e)) from e
        except OpenSSL.SSL.ZeroReturnError:
            if self.connection.get_shutdown() == OpenSSL.SSL.RECEIVED_SHUTDOWN:
                return b""
            else:
                raise
        except OpenSSL.SSL.WantReadError as e:
            if not util.wait_for_read(self.socket, self.socket.gettimeout()):
                raise timeout("The read operation timed out") from e
            else:
                return self.recv(bufsiz, flags)
        # TLS 1.3 post-handshake authentication
        except OpenSSL.SSL.Error as e:
            raise ssl.SSLError(f"read error: {e!r}") from e
        else:
            return data

    def recv_into(
        self,
        buffer: MutableSequence[int],
        nbytes: int | None = None,
        flags: int | None = None,
    ) -> int:
        """Receive data from the socket into a buffer.

        Args:
            buffer: Writable buffer where bytes will be copied.
            nbytes: Optional maximum number of bytes to receive.
            flags: Optional socket flags.

        Returns:
            The number of bytes received.

        Raises:
            OSError: If a system call error occurs.
            ssl.SSLError: If an SSL error occurs.
            timeout: If a timeout occurs.
        """
        try:
            return self.connection.recv_into(buffer, nbytes, flags)
        except OpenSSL.SSL.SysCallError as e:
            if self.suppress_ragged_eofs and e.args == (-1, "Unexpected EOF"):
                return 0
            else:
                raise OSError(e.args[0], str(e)) from e
        except OpenSSL.SSL.ZeroReturnError:
            if self.connection.get_shutdown() == OpenSSL.SSL.RECEIVED_SHUTDOWN:
                return 0
            else:
                raise
        except OpenSSL.SSL.WantReadError as e:
            if not util.wait_for_read(self.socket, self.socket.gettimeout()):
                raise timeout("The read operation timed out") from e
            else:
                return self.recv_into(buffer, nbytes, flags)
        # TLS 1.3 post-handshake authentication
        except OpenSSL.SSL.Error as e:
            raise ssl.SSLError(f"read error: {e!r}") from e

    def settimeout(self, timeout: float) -> None:
        """Set the timeout on the socket.

        Args:
            timeout: The timeout value in seconds.
        """
        return self.socket.settimeout(timeout)

    def _send_until_done(self, data: bytes) -> int:
        """Send data until complete or timeout.

        Args:
            data: The data to send.

        Returns:
            The number of bytes sent.

        Raises:
            OSError: If a system call error occurs.
            timeout: If a timeout occurs.
        """
        while True:
            try:
                return self.connection.send(data)
            except OpenSSL.SSL.WantWriteError as e:
                if not util.wait_for_write(self.socket, self.socket.gettimeout()):
                    raise timeout() from e
                continue
            except OpenSSL.SSL.SysCallError as e:
                raise OSError(e.args[0], str(e)) from e

    def sendall(self, data: bytes) -> None:
        """Send all data to the socket.

        Args:
            data: The data to send.
        """
        total_sent = 0
        while total_sent < len(data):
            sent = self._send_until_done(data[total_sent : total_sent + SSL_WRITE_BLOCKSIZE])
            total_sent += sent

    def send(self, data: bytes, flags: int = 0) -> int:
        """Send data to the socket.

        Args:
            data: The data to send.
            flags: Optional flags for the send operation.

        Returns:
            The number of bytes sent.
        """
        return self.connection.send(data, flags)

    def shutdown(self, how: int) -> None:
        """Shutdown the socket connection.

        Args:
            how: How to shutdown the connection.

        Raises:
            ssl.SSLError: If an SSL error occurs during shutdown.
        """
        try:
            self.connection.shutdown()
        except OpenSSL.SSL.Error as e:
            raise ssl.SSLError(f"shutdown error: {e!r}") from e

    def close(self) -> None:
        """Close the socket."""
        self._closed = True
        if self._io_refs <= 0:
            self._real_close()

    def _real_close(self) -> None:
        """Actually close the underlying connection."""
        try:
            return self.connection.close()  # type: ignore[no-any-return]
        except OpenSSL.SSL.Error:
            return

    @overload
    def getpeercert(
        self, binary_form: Literal[False] = False
    ) -> _PeerCertRetDictType | None: ...

    @overload
    def getpeercert(self, binary_form: Literal[True]) -> bytes | None: ...

    @overload
    def getpeercert(self, binary_form: bool) -> _PeerCertRetType: ...

    def getpeercert(self, binary_form: bool = False) -> _PeerCertRetType:
        """Get the peer's certificate.

        Args:
            binary_form: If True, return the certificate in binary (DER) form.

        Returns:
            The peer certificate in the requested format, or None if no cert.
        """
        x509 = self.connection.get_peer_certificate()

        if not x509:
            return None

        if binary_form:
            return crypto.dump_certificate(crypto.FILETYPE_ASN1, x509)

        return {
            "subject": ((("commonName", x509.get_subject().CN),),),
            "subjectAltName": tuple(get_subj_alt_name(x509)),
        }

    def version(self) -> str:
        """Get the TLS protocol version.

        Returns:
            The TLS version string.
        """
        return self.connection.get_protocol_version_name()

    def selected_alpn_protocol(self) -> str | None:
        """Get the selected ALPN protocol.

        Returns:
            The selected ALPN protocol, or None if none was negotiated.
        """
        alpn_proto = self.connection.get_alpn_proto_negotiated()
        return alpn_proto.decode() if alpn_proto else None

    def accept(self) -> tuple[WrappedSocket, tuple[str, int]]:
        """Accept a new connection.

        Returns:
            A tuple of (wrapped socket, address).
        """
        client_socket, address = self.socket.accept()
        cnx = OpenSSL.SSL.Connection(self.connection.get_context(), client_socket)
        cnx.set_accept_state()

        return WrappedSocket(cnx, client_socket), address


WrappedSocket.makefile = socket_cls.makefile  # type: ignore[attr-defined]


class SpiffeSSLContext:
    """SSL context that supports automatic refresh of SPIFFE X.509 SVIDs.

    This class provides an interface compatible with Python's standard library
    ssl.SSLContext while automatically refreshing certificates from an X509Source
    as they rotate.

    Example:
        >>> from spiffe import X509Source
        >>> from spiffetls import SpiffeSSLContext
        >>> import httpx
        >>>
        >>> x509_source = X509Source()
        >>> ctx = SpiffeSSLContext(x509_source, use_system_trusted_cas=True)
        >>> client = httpx.Client(verify=ctx)
    """

    def __init__(
        self,
        x509_source: X509Source,
        use_system_trusted_cas: bool = False,
        protocol: int = SSL.TLS_CLIENT_METHOD,
    ) -> None:
        """Initialize a SpiffeSSLContext.

        Args:
            x509_source: The X509Source providing SPIFFE certificates.
            use_system_trusted_cas: Whether to also trust system CA certificates.
            protocol: The SSL/TLS protocol method to use.
        """
        self.protocol = protocol
        self._ctx = create_ssl_context(
            protocol,
            x509_source,
            None,
            SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
            use_system_trusted_cas,
        )
        self._options = 0
        self.check_hostname = False
        self._minimum_version: int = ssl.TLSVersion.MINIMUM_SUPPORTED
        self._maximum_version: int = ssl.TLSVersion.MAXIMUM_SUPPORTED
        self._verify_flags: int = ssl.VERIFY_X509_TRUSTED_FIRST

    @property
    def __class__(self) -> type:
        """Return ssl.SSLContext as the class for compatibility with type checks."""
        return ssl.SSLContext

    @__class__.setter
    def __class__(self, value: type) -> None:
        raise TypeError(f"__class__ assignment is not supported for {type(self).__name__}")

    @property
    def options(self) -> int:
        """Get the SSL options bitmask."""
        return self._options

    @options.setter
    def options(self, value: int) -> None:
        """Set the SSL options bitmask.

        Args:
            value: The options bitmask.
        """
        self._options = value
        self._set_ctx_options()

    @property
    def verify_flags(self) -> int:
        """Get the certificate verification flags."""
        return self._verify_flags

    @verify_flags.setter
    def verify_flags(self, value: int) -> None:
        """Set the certificate verification flags.

        Args:
            value: The verification flags.
        """
        self._verify_flags = value
        cert_store = self._ctx.get_cert_store()
        if cert_store is None:
            raise RuntimeError("OpenSSL certificate store is unavailable")
        cert_store.set_flags(self._verify_flags)

    @property
    def verify_mode(self) -> int:
        """Get the certificate verification mode."""
        return _openssl_to_stdlib_verify[self._ctx.get_verify_mode()]

    @verify_mode.setter
    def verify_mode(self, value: ssl.VerifyMode) -> None:
        """Set the certificate verification mode.

        Args:
            value: The verification mode.
        """
        self._ctx.set_verify(_stdlib_to_openssl_verify[value], _verify_callback)

    def set_default_verify_paths(self) -> None:
        """Set default verification paths (no-op for SPIFFE contexts)."""
        pass

    def set_ciphers(self, ciphers: bytes | str) -> None:
        """Set the available ciphers for the SSL connection.

        Args:
            ciphers: The cipher list string.
        """
        if isinstance(ciphers, str):
            ciphers = ciphers.encode("utf-8")
        self._ctx.set_cipher_list(ciphers)

    def load_verify_locations(
        self,
        cafile: str | None = None,
        capath: str | None = None,
        cadata: bytes | None = None,
    ) -> None:
        """Load verification locations (no-op for SPIFFE contexts).

        Args:
            cafile: Path to CA certificate file (unused).
            capath: Path to CA certificate directory (unused).
            cadata: CA certificate data (unused).
        """
        pass

    def load_cert_chain(
        self,
        certfile: str,
        keyfile: str | None = None,
        password: str | None = None,
    ) -> None:
        """Load certificate chain (no-op for SPIFFE contexts).

        Args:
            certfile: Path to certificate file (unused).
            keyfile: Path to key file (unused).
            password: Password for encrypted key (unused).
        """
        pass

    def set_alpn_protocols(self, protocols: list[bytes | str]) -> None:
        """Set ALPN protocols to advertise during handshake.

        Args:
            protocols: List of ALPN protocol identifiers.
        """
        protocols_bytes = [util.to_bytes(p, "ascii") for p in protocols]
        return self._ctx.set_alpn_protos(protocols_bytes)

    def wrap_socket(
        self,
        sock: socket_cls,
        server_side: bool = False,
        do_handshake_on_connect: bool = True,
        suppress_ragged_eofs: bool = True,
        server_hostname: bytes | str | None = None,
    ) -> WrappedSocket:
        """Wrap a socket with SSL/TLS.

        Args:
            sock: The socket to wrap.
            server_side: Whether this is a server-side socket.
            do_handshake_on_connect: Whether to perform the handshake immediately.
            suppress_ragged_eofs: Whether to suppress ragged EOF errors.
            server_hostname: The expected server hostname for SNI.

        Returns:
            A WrappedSocket instance.

        Raises:
            ssl.SSLError: If the handshake fails.
            timeout: If the handshake times out.
        """
        cnx = OpenSSL.SSL.Connection(self._ctx, sock)

        # If server_hostname is an IP, don't use it for SNI, per RFC6066 Section 3
        if server_hostname and not util.is_ipaddress(server_hostname):
            if isinstance(server_hostname, str):
                server_hostname = server_hostname.encode("utf-8")
            cnx.set_tlsext_host_name(server_hostname)

        if server_side:
            cnx.set_accept_state()
        else:
            cnx.set_connect_state()

        if do_handshake_on_connect and not server_side:
            while True:
                try:
                    cnx.do_handshake()
                except OpenSSL.SSL.WantReadError as e:
                    if not util.wait_for_read(sock, sock.gettimeout()):
                        raise timeout("select timed out") from e
                    continue
                except OpenSSL.SSL.Error as e:
                    raise ssl.SSLError(f"bad handshake: {e!r}") from e
                break

        return WrappedSocket(cnx, sock)

    def _set_ctx_options(self) -> None:
        """Set OpenSSL context options based on minimum/maximum TLS versions."""
        self._ctx.set_options(
            self._options
            | _openssl_to_ssl_minimum_version[self._minimum_version]
            | _openssl_to_ssl_maximum_version[self._maximum_version]
        )

    @property
    def minimum_version(self) -> int:
        """Get the minimum TLS version."""
        return self._minimum_version

    @minimum_version.setter
    def minimum_version(self, minimum_version: int) -> None:
        """Set the minimum TLS version.

        Args:
            minimum_version: The minimum TLS version to support.
        """
        self._minimum_version = minimum_version
        self._set_ctx_options()

    @property
    def maximum_version(self) -> int:
        """Get the maximum TLS version."""
        return self._maximum_version

    @maximum_version.setter
    def maximum_version(self, maximum_version: int) -> None:
        """Set the maximum TLS version.

        Args:
            maximum_version: The maximum TLS version to support.
        """
        self._maximum_version = maximum_version
        self._set_ctx_options()


def _verify_callback(
    cnx: OpenSSL.SSL.Connection,
    x509: X509,
    err_no: int,
    err_depth: int,
    return_code: int,
) -> bool:
    """Verification callback for OpenSSL.

    Args:
        cnx: The SSL connection.
        x509: The certificate being verified.
        err_no: The error number.
        err_depth: The depth in the certificate chain.
        return_code: The return code from OpenSSL.

    Returns:
        True if the certificate is valid, False otherwise.
    """
    return err_no == 0
