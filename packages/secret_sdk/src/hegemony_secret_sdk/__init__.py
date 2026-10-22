# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Public SDK for Hegemony secret backend plugins.

Dependency-light (pydantic only). Out-of-tree plugin wheels depend on this package and
never import Hegemony app internals. A plugin exposes a ``register(registry)`` callable
under the ``hegemony.secret_backends`` entry-point group.

Secret backends are leaf components: the host does not inject services or context into
them (unlike notification transports). A backend factory receives only an already-resolved
configuration dict and returns a :class:`SecretBackend` instance.
"""

from __future__ import annotations

from ._version import SDK_ABI_VERSION, __version__
from .backend import DataKeyWrappingSecretBackend, ListableSecretBackend, SecretBackend
from .registry import BackendFactory, SecretBackendRegistry

#: The entry-point group out-of-tree secret backend plugins register under.
SECRET_BACKEND_ENTRY_POINT_GROUP = "hegemony.secret_backends"

__all__ = [
    "SECRET_BACKEND_ENTRY_POINT_GROUP",
    "SDK_ABI_VERSION",
    "BackendFactory",
    "DataKeyWrappingSecretBackend",
    "ListableSecretBackend",
    "SecretBackend",
    "SecretBackendRegistry",
    "__version__",
]
