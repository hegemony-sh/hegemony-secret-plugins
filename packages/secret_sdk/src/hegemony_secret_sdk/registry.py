# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The registry facade contract a plugin's ``register(registry)`` callable receives.

The core platform supplies a concrete object satisfying this Protocol. Plugins program
against the Protocol only, never against the platform's registry internals.

A plugin registers one or more backend *types* via :meth:`SecretBackendRegistry.register_backend_type`.
Each registration contributes a ``factory`` that builds a :class:`~hegemony_secret_sdk.backend.SecretBackend`
instance from an already-resolved configuration dict — secret backends are leaf components, so
the factory performs no secret resolution of its own and the host injects no services or context.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel

from .backend import SecretBackend

# Builds a concrete SecretBackend instance from an already-resolved configuration dict.
BackendFactory = Callable[[dict[str, Any]], SecretBackend]


@runtime_checkable
class SecretBackendRegistry(Protocol):
    """Registration surface passed to ``register(registry)`` plugin callables."""

    #: The platform's plugin registration ABI version (see ``SDK_ABI_VERSION``).
    api_version: int

    def register_backend_type(
        self,
        *,
        backend_type: str,
        display_name: str,
        description: str,
        factory: BackendFactory,
        config_model: type[BaseModel] | None = None,
        config_schema: dict[str, Any] | None = None,
        default_config: dict[str, Any] | None = None,
        hidden: bool = False,
    ) -> None:
        """Register a secret backend type with its config factory.

        ``config_model`` and ``config_schema`` are both optional and independent; a
        plugin may supply either, both, or neither. Neither takes precedence over the
        other — the host may use ``config_model`` for validation/parsing and
        ``config_schema`` for UI rendering, so provide whichever (or both) your
        plugin needs.

        ``hidden`` types stay registered and resolvable (existing configurations
        referencing them keep working) but are omitted from create-time type pickers —
        use it for legacy type-string aliases. Passing ``hidden`` requires a host built
        with hidden-type support; on an older host the keyword raises ``TypeError`` and
        the plugin fails to load.
        """
