# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Hegemony 1Password secret backend plugin.

Registers two backend types under the ``hegemony.secret_backends`` entry-point
group: ``onepassword_connect`` (authenticates against a self-hosted 1Password
Connect server) and ``onepassword_service_account`` (authenticates with a 1Password
Service Account token via the official ``onepassword-sdk``). Both resolve
``"<vault>/<item>"`` reference paths to a mapping of item field names to values.
"""

from __future__ import annotations

from typing import Any

from hegemony_secret_sdk import SecretBackendRegistry

from .connect_client import OnePasswordConnectBackend, OnePasswordConnectConfig
from .service_account_client import (
    OnePasswordServiceAccountBackend,
    OnePasswordServiceAccountConfig,
)

# Fields holding raw auth material (token/credential values). The host UI renders
# these with the secret/variable picker rather than a plain text input.
_SECRET_REF_FIELD = {"type": "string", "x_secret_ref": True}

_CONNECT_CONFIG_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["connect_host", "connect_token"],
    "properties": {
        "connect_host": {
            "type": "string",
            "title": "1Password Connect host",
            "description": "1Password Connect server address, e.g. https://connect.example.com",
        },
        "connect_token": {
            **_SECRET_REF_FIELD,
            "title": "Connect API token",
        },
    },
}

_SERVICE_ACCOUNT_CONFIG_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["service_account_token"],
    "properties": {
        "service_account_token": {
            **_SECRET_REF_FIELD,
            "title": "Service account token",
            "description": "1Password Service Account token, e.g. ops_...",
        },
        "integration_name": {
            "type": "string",
            "title": "Integration name",
            "default": "Hegemony",
        },
    },
}


def build_onepassword_connect_backend(config: dict[str, Any]) -> OnePasswordConnectBackend:
    """Build an :class:`OnePasswordConnectBackend` from an already-resolved config dict."""
    return OnePasswordConnectBackend(OnePasswordConnectConfig.from_dict(config))


def build_onepassword_service_account_backend(
    config: dict[str, Any],
) -> OnePasswordServiceAccountBackend:
    """Build an :class:`OnePasswordServiceAccountBackend` from a resolved config dict."""
    return OnePasswordServiceAccountBackend(OnePasswordServiceAccountConfig.from_dict(config))


def register(registry: SecretBackendRegistry) -> None:
    """Entry point for the ``hegemony.secret_backends`` group."""
    registry.register_backend_type(
        backend_type="onepassword_connect",
        display_name="1Password (Connect server)",
        description="1Password secrets backend authenticating against a self-hosted Connect server.",
        factory=build_onepassword_connect_backend,
        config_schema=_CONNECT_CONFIG_SCHEMA,
    )
    registry.register_backend_type(
        backend_type="onepassword_service_account",
        display_name="1Password (Service Account)",
        description="1Password secrets backend authenticating with a Service Account token.",
        factory=build_onepassword_service_account_backend,
        config_schema=_SERVICE_ACCOUNT_CONFIG_SCHEMA,
    )


__all__ = [
    "build_onepassword_connect_backend",
    "build_onepassword_service_account_backend",
    "register",
]
