# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The ``SecretBackend`` contract a plugin-provided backend instance implements.

Unlike notification transports, secret backends are *leaf* components: the host does not
inject any services or context into them. A backend is self-contained — it receives its own
resolved configuration at construction time (via the registered factory) and talks directly
to the underlying secret store (Vault, etc.).

Beyond the required ``SecretBackend`` methods, a backend may implement optional capability
protocols (``ListableSecretBackend``, ``VersionedSecretBackend``). The host feature-detects
them on the backend *instance* with ``hasattr``/``isinstance``; the registration contract
and ``SDK_ABI_VERSION`` are untouched by them, so an old host simply never calls the extra
methods and a new host degrades cleanly on a backend without them.
"""

from __future__ import annotations

import builtins
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class SecretBackend(Protocol):
    """A concrete secret backend instance, as built by a plugin's ``BackendFactory``."""

    def read(self, path: str) -> Mapping[str, Any] | None:
        """Read the secret stored at ``path``; return ``None`` if it does not exist."""

    def write(self, path: str, data: Mapping[str, Any]) -> None:
        """Write ``data`` to the secret stored at ``path``."""

    def delete(self, path: str) -> None:
        """Delete the secret stored at ``path``; deleting a missing secret is not an error."""

    def test(self) -> None:
        """Verify connectivity/authentication against the backend; raise on failure."""


@runtime_checkable
class ListableSecretBackend(SecretBackend, Protocol):
    """A backend that can additionally enumerate its contents for browsing.

    Implementing this protocol is optional; the host feature-detects it (``hasattr``/
    ``isinstance``) and offers backend browsing only when present.
    """

    # builtins.list because the method name shadows the builtin in class scope.
    def list(self, path: str = "") -> builtins.list[str]:
        """List the names of the immediate children under ``path``.

        Container entries (which can be listed further) end with ``"/"``; leaf entries
        (readable secret paths) do not. An unknown or empty ``path`` returns ``[]``.
        """


@dataclass(frozen=True)
class SecretVersion:
    """One version of a secret, as listed by :meth:`VersionedSecretBackend.versions`."""

    version: int
    #: The backend's own creation timestamp text (RFC 3339 for Vault), or ``None`` when
    #: the backend records none.
    created_at: str | None
    #: Soft-deleted: reads no longer return the data, but the version still exists.
    deleted: bool
    #: Destroyed: the data is gone for good; only the version number remains.
    destroyed: bool


@dataclass(frozen=True)
class VersionedSecret:
    """Secret data together with the version it was read at."""

    data: Mapping[str, Any]
    version: int
    created_at: str | None
    #: ``True`` when the version exists but its data is deleted or destroyed; ``data`` is
    #: then empty. A caller writing "only if nothing changed since I read" still passes
    #: ``version`` as ``expected_version``: a deleted version still occupies the path.
    deleted: bool = False


class VersionConflictError(Exception):
    """``write_checked`` found a current version other than ``expected_version``.

    The write was not applied. The host identifies this failure by the class *name*
    (it never imports the SDK at runtime), so a subclass keeps it in its MRO.
    """

    def __init__(self, path: str, expected_version: int) -> None:
        self.path = path
        self.expected_version = expected_version
        super().__init__(
            f"Secret at {path!r} is no longer at version {expected_version}; "
            "it changed since it was read"
        )


@runtime_checkable
class VersionedSecretBackend(SecretBackend, Protocol):
    """A backend that keeps versions of each secret and supports check-and-set writes.

    Implementing this protocol is optional; the host feature-detects it (``hasattr``/
    ``isinstance``) and falls back to plain ``read``/``write`` otherwise.
    """

    def read_versioned(self, path: str) -> VersionedSecret | None:
        """Read the latest version at ``path`` together with its version number.

        A latest version whose data is deleted or destroyed is returned with empty
        ``data`` and ``deleted=True`` rather than as ``None``, because the path is
        still occupied. Return ``None`` only when nothing was ever stored at ``path``.
        """

    def read_version(self, path: str, version: int) -> VersionedSecret | None:
        """Read one specific version at ``path``; ``None`` if the path does not exist."""

    def versions(self, path: str) -> builtins.list[SecretVersion]:
        """List every version at ``path``, oldest first; ``[]`` for an unknown path."""

    def write_checked(self, path: str, data: Mapping[str, Any], *, expected_version: int) -> int:
        """Write ``data`` only if the current version at ``path`` is ``expected_version``.

        ``expected_version=0`` means "only if nothing is stored there yet". Returns the
        version number just written. Raises :class:`VersionConflictError` when the
        current version differs; the backend then wrote nothing.
        """
