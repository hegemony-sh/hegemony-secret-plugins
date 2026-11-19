# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Hegemony Vaultwarden secret backend plugin.

Registers the ``vaultwarden`` backend type under the ``hegemony.secret_backends``
entry-point group. It reads and writes the items of one organization on a
`Vaultwarden <https://github.com/dani-garcia/vaultwarden>`_ server (or a self-hosted
Bitwarden server, which speaks the same client API), resolving
``"<collection>/<item>"`` reference paths to a mapping of item field names to values.

Bitwarden Secrets Manager is a different product with a different API, which
Vaultwarden does not implement; this plugin does not talk to it.
"""

from __future__ import annotations

from typing import Any

from hegemony_secret_sdk import SecretBackendRegistry

from .backend import (
    DEFAULT_CACHE_TTL_SECONDS,
    DEFAULT_TIMEOUT_SECONDS,
    VaultwardenBackend,
    VaultwardenConfig,
)

# Fields holding raw auth material. The host UI renders these with the secret/variable
# picker rather than a plain text input, and refuses plaintext values for them.
_SECRET_REF_FIELD = {"type": "string", "x_secret_ref": True}

_CONFIG_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["server_url", "client_id", "client_secret", "master_password", "organization"],
    "properties": {
        "server_url": {
            "type": "string",
            "title": "Server URL",
            "description": "Base address of the Vaultwarden server, e.g. https://vault.example.com",
        },
        "client_id": {
            "type": "string",
            "title": "API key client_id",
            "description": (
                "Personal API key id of a dedicated service user, e.g. user.<id> "
                "(web vault: Settings → Security → Keys → View API key)."
            ),
        },
        "client_secret": {
            **_SECRET_REF_FIELD,
            "title": "API key client_secret",
        },
        "master_password": {
            **_SECRET_REF_FIELD,
            "title": "Master password",
            "description": (
                "Master password of the service user. The server stores only encrypted "
                "data; the password is needed to decrypt it and is never sent to the server."
            ),
        },
        "organization": {
            "type": "string",
            "title": "Organization",
            "description": "Name or id of the organization whose collections hold the secrets.",
        },
        "cache_ttl_seconds": {
            "type": "integer",
            "title": "Cache lifetime (seconds)",
            "description": (
                "How long reads reuse a downloaded copy of the vault. Every refresh "
                "downloads the whole vault; 0 refreshes on every read."
            ),
            "default": DEFAULT_CACHE_TTL_SECONDS,
            "minimum": 0,
        },
        "timeout": {
            "type": "integer",
            "title": "Request timeout (seconds)",
            "description": (
                "Per-request timeout. Without one, an unresponsive server pins the "
                "calling worker thread indefinitely."
            ),
            "default": DEFAULT_TIMEOUT_SECONDS,
            "minimum": 1,
        },
        "ca_cert_file": {
            "type": "string",
            "title": "CA certificate file",
            "description": "Optional path to a CA certificate bundle for TLS verification.",
        },
        "verify_ssl": {
            "type": "boolean",
            "title": "Verify SSL",
            "default": True,
        },
        "allow_insecure_http": {
            "type": "boolean",
            "title": "Allow plain HTTP",
            "description": (
                "Accept an http:// address. Off by default: plain HTTP sends the API "
                "key and the access token across the network in cleartext. Turn it on "
                "only for a dev server or a network you fully trust."
            ),
            "default": False,
        },
    },
}


def build_vaultwarden_backend(config: dict[str, Any]) -> VaultwardenBackend:
    """Build a :class:`VaultwardenBackend` from an already-resolved config dict."""
    return VaultwardenBackend(VaultwardenConfig.from_dict(config))


def register(registry: SecretBackendRegistry) -> None:
    """Entry point for the ``hegemony.secret_backends`` group."""
    registry.register_backend_type(
        backend_type="vaultwarden",
        display_name="Vaultwarden",
        description=(
            "Vaultwarden (or self-hosted Bitwarden) password vault: the items of one "
            "organization, addressed as <collection>/<item>."
        ),
        factory=build_vaultwarden_backend,
        config_schema=_CONFIG_SCHEMA,
    )


__all__ = [
    "VaultwardenBackend",
    "VaultwardenConfig",
    "build_vaultwarden_backend",
    "register",
]
