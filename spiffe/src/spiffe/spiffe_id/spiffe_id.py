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

import re

from spiffe.errors import PySpiffeError

"""
This module manages SpiffeId and TrustDomain objects.
"""

SCHEME_PREFIX = "spiffe://"


class SpiffeIdError(PySpiffeError):
    """Custom exception for SpiffeId related errors."""

    def __init__(self, detail: str, input_value: str = "") -> None:
        """
        Initializes a SpiffeIdError with a detailed error message.

        Args:
            detail (str): A description of the error.
            input_value (str, optional): The input value that caused the error. Defaults to an empty string.
        """
        if input_value:
            message = f"Invalid SPIFFE ID '{input_value}': {detail}"
        else:
            message = f"Invalid SPIFFE ID: {detail}"
        super().__init__(message)


class TrustDomainError(PySpiffeError):
    """Custom exception for TrustDomain related errors."""

    def __init__(self, detail: str, input_value: str = "") -> None:
        """
        Initializes a SpiffeIdError with a detailed error message.

        Args:
            detail (str): A description of the error.
            input_value (str, optional): The input value that caused the error. Defaults to an empty string.
        """
        if input_value:
            message = f"Invalid trust domain '{input_value}': {detail}"
        else:
            message = f"Invalid trust domain: {detail}"
        super().__init__(message)


class TrustDomain:
    """
    Represents the name of a SPIFFE Trust Domain.

    The TrustDomain can be initialized with a name or a full SPIFFE ID, from
    which the trust domain part is extracted.

    Examples:
        >>> td = TrustDomain("example.org")
        >>> print(td)
        example.org

        >>> td = TrustDomain("spiffe://example.org/service")
        >>> print(td)
        example.org
    """

    def __init__(self, id_or_name: str):
        self._name = extract_and_validate_trust_domain(id_or_name)

    @property
    def name(self) -> str:
        return self._name

    def as_spiffe_id(self) -> str:
        return f"{SCHEME_PREFIX}{self._name}"

    def __str__(self) -> str:
        return self._name

    def __eq__(self, other) -> bool:
        if isinstance(other, TrustDomain):
            return self._name == other._name
        elif isinstance(other, str):
            return self._name == other
        return False

    def __hash__(self) -> int:
        return hash(self._name)


class SpiffeId:
    """
    Represents a SPIFFE Identifier according to the SPIFFE standard.

    A SPIFFE ID is composed of a scheme ('spiffe'), a trust domain, and a path.
    It uniquely identifies a workload within a trust domain. The path is
    optional and is used to identify specific entities within the trust domain.

    Examples:
        Creating a SpiffeId with a path:
            >>> id = SpiffeId('spiffe://example.org/service')
            >>> print(id)
            spiffe://example.org/service

        Creating a SpiffeId without a path:
            >>> id = SpiffeId('spiffe://example.org')
            >>> print(id)
            spiffe://example.org
    """

    def __init__(self, id: str):
        if not id:
            raise SpiffeIdError("cannot be empty")

        if not id.startswith(SCHEME_PREFIX):
            raise SpiffeIdError("does not start with 'spiffe://'", id)

        rest = id[len(SCHEME_PREFIX) :]
        path_idx = rest.find("/")
        if path_idx == -1:
            # No path found; entire `rest` is the trust domain
            trust_domain_name = rest
            path = ""
        else:
            trust_domain_name = rest[:path_idx]
            path = rest[path_idx:]  # Include the leading '/' in the path

        try:
            self._trust_domain = TrustDomain(trust_domain_name)
        except TrustDomainError as err:
            raise SpiffeIdError(str(err), id)

        if path:
            try:
                self._validate_path(path)
            except ValueError as err:
                raise SpiffeIdError(str(err), id)
        self._path = path

    def __str__(self) -> str:
        return f"{SCHEME_PREFIX}{self._trust_domain}{self._path}"

    def __eq__(self, other) -> bool:
        if isinstance(other, SpiffeId):
            return (self._trust_domain, self._path) == (
                other._trust_domain,
                other._path,
            )
        elif isinstance(other, str):
            return str(self) == other
        return False

    def __hash__(self) -> int:
        return hash((self._trust_domain, self._path))

    @property
    def trust_domain(self) -> TrustDomain:
        return self._trust_domain

    @staticmethod
    def _validate_path(path: str):
        if not path.startswith("/"):
            raise ValueError("path must start with '/'")

        segments = path.split("/")
        for segment in segments[
            1:
        ]:  # Skip the first segment since it's empty due to the leading '/'
            if not segment:
                raise ValueError("path cannot contain empty segments")
            if segment in [".", ".."]:
                raise ValueError("path segments '.' and '..' are not allowed")
            if not re.match(r"^[a-zA-Z0-9._-]+$", segment):
                raise ValueError("invalid character in path segment")


def extract_and_validate_trust_domain(id_or_name: str) -> str:
    if ":/" in id_or_name:
        if not id_or_name.startswith(SCHEME_PREFIX):
            raise TrustDomainError("ID form does not start with 'spiffe://'", id_or_name)
        trust_domain = id_or_name[len(SCHEME_PREFIX) :].split("/", 1)[0]
    else:
        trust_domain = id_or_name

    # Validate trust domain
    if not trust_domain:
        raise TrustDomainError("cannot be empty")

    if trust_domain[0] in ['-', '.'] or trust_domain[-1] in ['-', '.']:
        raise TrustDomainError("cannot start or end with '-' or '.'", id_or_name)

    if '..' in trust_domain:
        raise TrustDomainError("cannot contain consecutive dots", id_or_name)

    if not re.match(
        r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$',
        trust_domain,
    ):
        raise TrustDomainError("contains disallowed characters", id_or_name)

    return trust_domain
