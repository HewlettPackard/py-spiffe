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

Portions of this code are adapted from urllib3's util package.

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

import re
import select
import socket
from functools import partial

__all__ = ["wait_for_read", "wait_for_write", "to_bytes", "is_ipaddress"]


def _have_working_poll() -> bool:
    """Check if select.poll is available and working.

    Returns:
        True if poll() is available and working, False otherwise.
    """
    try:
        poll_obj = select.poll()
        poll_obj.poll(0)
    except (AttributeError, OSError):
        return False
    else:
        return True


def select_wait_for_socket(
    sock: socket.socket,
    read: bool = False,
    write: bool = False,
    timeout: float | None = None,
) -> bool:
    """Wait for a socket to be ready using select.select.

    Args:
        sock: The socket to wait for.
        read: Whether to wait for read readiness.
        write: Whether to wait for write readiness.
        timeout: Optional timeout in seconds.

    Returns:
        True if the socket is ready, False if timeout expired.

    Raises:
        RuntimeError: If neither read nor write is specified.
    """
    if not read and not write:
        raise RuntimeError("must specify at least one of read=True, write=True")
    rcheck = []
    wcheck = []
    if read:
        rcheck.append(sock)
    if write:
        wcheck.append(sock)
    # When doing a non-blocking connect, most systems signal success by
    # marking the socket writable. Windows, though, signals success by marked
    # it as "exceptional". We paper over the difference by checking the write
    # sockets for both conditions. (The stdlib selectors module does the same
    # thing.)
    fn = partial(select.select, rcheck, wcheck, wcheck)
    rready, wready, xready = fn(timeout)
    return bool(rready or wready or xready)


def poll_wait_for_socket(
    sock: socket.socket,
    read: bool = False,
    write: bool = False,
    timeout: float | None = None,
) -> bool:
    """Wait for a socket to be ready using select.poll.

    Args:
        sock: The socket to wait for.
        read: Whether to wait for read readiness.
        write: Whether to wait for write readiness.
        timeout: Optional timeout in seconds.

    Returns:
        True if the socket is ready, False if timeout expired.

    Raises:
        RuntimeError: If neither read nor write is specified.
    """
    if not read and not write:
        raise RuntimeError("must specify at least one of read=True, write=True")
    mask = 0
    if read:
        mask |= select.POLLIN
    if write:
        mask |= select.POLLOUT
    poll_obj = select.poll()
    poll_obj.register(sock, mask)

    # For some reason, poll() takes timeout in milliseconds
    def do_poll(t: float | None) -> list[tuple[int, int]]:
        if t is not None:
            t *= 1000
        return poll_obj.poll(t)

    return bool(do_poll(timeout))


def wait_for_socket(
    sock: socket.socket,
    read: bool = False,
    write: bool = False,
    timeout: float | None = None,
) -> bool:
    """Wait for a socket to be ready for I/O.

    Automatically selects between poll() and select() based on availability.

    Args:
        sock: The socket to wait for.
        read: Whether to wait for read readiness.
        write: Whether to wait for write readiness.
        timeout: Optional timeout in seconds.

    Returns:
        True if the socket is ready, False if timeout expired.
    """
    # We delay choosing which implementation to use until the first time we're
    # called. We could do it at import time, but then we might make the wrong
    # decision if someone goes wild with monkeypatching select.poll after
    # we're imported.
    global wait_for_socket
    if _have_working_poll():
        wait_for_socket = poll_wait_for_socket
    elif hasattr(select, "select"):
        wait_for_socket = select_wait_for_socket
    return wait_for_socket(sock, read, write, timeout)


def wait_for_read(sock: socket.socket, timeout: float | None = None) -> bool:
    """Wait for reading to be available on a given socket.

    Args:
        sock: The socket to wait for.
        timeout: Optional timeout in seconds.

    Returns:
        True if the socket is readable, False if the timeout expired.
    """
    return wait_for_socket(sock, read=True, timeout=timeout)


def wait_for_write(sock: socket.socket, timeout: float | None = None) -> bool:
    """Wait for writing to be available on a given socket.

    Args:
        sock: The socket to wait for.
        timeout: Optional timeout in seconds.

    Returns:
        True if the socket is writable, False if the timeout expired.
    """
    return wait_for_socket(sock, write=True, timeout=timeout)


def to_bytes(
    x: str | bytes, encoding: str | None = None, errors: str | None = None
) -> bytes:
    """Convert a string to bytes.

    Args:
        x: The string or bytes to convert.
        encoding: The encoding to use (defaults to utf-8).
        errors: How to handle encoding errors (defaults to strict).

    Returns:
        The bytes representation.

    Raises:
        TypeError: If x is neither str nor bytes.
    """
    if isinstance(x, bytes):
        return x
    elif not isinstance(x, str):
        raise TypeError(f"not expecting type {type(x).__name__}")
    if encoding or errors:
        return x.encode(encoding or "utf-8", errors=errors or "strict")
    return x.encode()


_IPV4_PAT = r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"

_HEX_PAT = "[0-9A-Fa-f]{1,4}"
_LS32_PAT = "(?:{hex}:{hex}|{ipv4})".format(hex=_HEX_PAT, ipv4=_IPV4_PAT)
_subs = {"hex": _HEX_PAT, "ls32": _LS32_PAT}
_variations = [
    #                            6( h16 ":" ) ls32
    "(?:%(hex)s:){6}%(ls32)s",
    #                       "::" 5( h16 ":" ) ls32
    "::(?:%(hex)s:){5}%(ls32)s",
    # [               h16 ] "::" 4( h16 ":" ) ls32
    "(?:%(hex)s)?::(?:%(hex)s:){4}%(ls32)s",
    # [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
    "(?:(?:%(hex)s:)?%(hex)s)?::(?:%(hex)s:){3}%(ls32)s",
    # [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
    "(?:(?:%(hex)s:){0,2}%(hex)s)?::(?:%(hex)s:){2}%(ls32)s",
    # [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
    "(?:(?:%(hex)s:){0,3}%(hex)s)?::%(hex)s:%(ls32)s",
    # [ *4( h16 ":" ) h16 ] "::"              ls32
    "(?:(?:%(hex)s:){0,4}%(hex)s)?::%(ls32)s",
    # [ *5( h16 ":" ) h16 ] "::"              h16
    "(?:(?:%(hex)s:){0,5}%(hex)s)?::%(hex)s",
    # [ *6( h16 ":" ) h16 ] "::"
    "(?:(?:%(hex)s:){0,6}%(hex)s)?::",
]

_IPV6_PAT = "(?:" + "|".join([x % _subs for x in _variations]) + ")"
_UNRESERVED_PAT = r"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._\-~"
_ZONE_ID_PAT = "(?:%25|%)(?:[" + _UNRESERVED_PAT + "]|%[a-fA-F0-9]{2})+"
_IPV6_ADDRZ_PAT = r"\[" + _IPV6_PAT + r"(?:" + _ZONE_ID_PAT + r")?\]"
_IPV4_RE = re.compile("^" + _IPV4_PAT + "$")
_BRACELESS_IPV6_ADDRZ_RE = re.compile("^" + _IPV6_ADDRZ_PAT[2:-2] + "$")


def is_ipaddress(hostname: str | bytes) -> bool:
    """Detect whether the hostname given is an IPv4 or IPv6 address.

    Also detects IPv6 addresses with Zone IDs.

    Args:
        hostname: Hostname to examine.

    Returns:
        True if the hostname is an IP address, False otherwise.
    """
    if isinstance(hostname, bytes):
        # IDN A-label bytes are ASCII compatible.
        hostname = hostname.decode("ascii")
    return bool(_IPV4_RE.match(hostname) or _BRACELESS_IPV6_ADDRZ_RE.match(hostname))
