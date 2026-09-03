# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Hegemony HashiCorp Vault / OpenBao secret backend plugin.

Registers KV v2 backends under the ``hegemony.secret_backends`` entry-point group. Three
type strings are registered:

- ``vault`` — the preferred generic HashiCorp Vault type.
- ``vault_kv2`` — a hidden legacy alias of it, kept so existing backend rows keep resolving.
- ``openbao`` — OpenBao, the Linux Foundation fork of Vault.

All three build the same KV v2 :class:`VaultSecretsBackend`. OpenBao keeps Vault's HTTP
API — the ``X-Vault-Token`` header, the KV v2 paths and the AppRole login are unchanged —
so one client serves both. The separate type string exists so the host UI names the
product honestly, and so the two can diverge later without migrating existing rows.
"""

from __future__ import annotations

from typing import Any

from hegemony_secret_sdk import SecretBackendRegistry

from .vault_client import DEFAULT_TIMEOUT_SECONDS, VaultBackendConfig, VaultSecretsBackend

# Fields holding raw auth material (token or credential *values*). The host UI renders
# these with the secret/variable picker, and the host also *requires* them to be
# placeholder expressions rather than plaintext — see ``sensitive_config_fields`` in the
# host's secret_backend_validation, which unions this marker into its policy.
#
# Paths to credential files are deliberately NOT marked. A filesystem path is not secret
# material, and marking it would make a literal path (the only useful value for these
# fields) fail the no-plaintext check outright.
_SECRET_REF_FIELD = {"type": "string", "x_secret_ref": True}


def _config_schema(product: str, address_example: str) -> dict[str, Any]:
    """Build the KV v2 backend config schema, labelled for ``product``.

    Property *names* are identical across products, and deliberately so: the host keys its
    per-component override handling (``x_component``/``x_fallback_of``) and its
    sensitive-field policy (``x_secret_ref``) off these names. Only the human-facing titles
    and descriptions vary between Vault and OpenBao.
    """
    return {
        "type": "object",
        "required": ["address"],
        "properties": {
            "address": {
                "type": "string",
                "title": f"{product} address",
                "description": f"{product} server address, e.g. {address_example}",
            },
            "kv_mount": {
                "type": "string",
                "title": "KV v2 mount point",
                "default": "hegemony",
            },
            "path_prefix": {
                "type": "string",
                "title": "Path prefix",
                "description": "Optional prefix applied to all secret paths.",
            },
            "namespace": {
                "type": "string",
                "title": "Namespace",
                "description": (
                    "Optional namespace to scope every request to. Namespaces are an "
                    "OpenBao feature and a Vault Enterprise feature; leave empty otherwise."
                ),
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
            "token": {
                **_SECRET_REF_FIELD,
                "title": f"{product} token",
                "description": (
                    f"Static {product} token (dev mode). Takes precedence over AppRole."
                ),
            },
            "role_id": {
                **_SECRET_REF_FIELD,
                "title": "AppRole role ID",
            },
            "secret_id": {
                **_SECRET_REF_FIELD,
                "title": "AppRole secret ID",
            },
            # Path fields, not credential fields — see the note on _SECRET_REF_FIELD.
            # Prefer these over the value fields when credentials are rotated in place:
            # the client re-reads them on every login, so a rotated file is picked up
            # without rebuilding the backend.
            "role_id_file": {
                "type": "string",
                "title": "AppRole role ID file",
                "description": "Path to a file containing the AppRole role ID.",
            },
            "secret_id_file": {
                "type": "string",
                "title": "AppRole secret ID file",
                "description": "Path to a file containing the AppRole secret ID.",
            },
            # x_component tells the host which process applies an override onto its
            # x_fallback_of base field before calling the factory; the factory itself only
            # ever sees role_id/secret_id and role_id_file/secret_id_file.
            "api_role_id": {
                **_SECRET_REF_FIELD,
                "title": "AppRole role ID (API override)",
                "description": (
                    "Overrides role_id for the API component only. Set this when the API and "
                    f"worker authenticate to {product} with different AppRoles."
                ),
                "x_fallback_of": "role_id",
                "x_component": "api",
            },
            "api_secret_id": {
                **_SECRET_REF_FIELD,
                "title": "AppRole secret ID (API override)",
                "description": (
                    "Overrides secret_id for the API component only. Set this when the API and "
                    f"worker authenticate to {product} with different AppRoles."
                ),
                "x_fallback_of": "secret_id",
                "x_component": "api",
            },
            "worker_role_id": {
                **_SECRET_REF_FIELD,
                "title": "AppRole role ID (worker override)",
                "description": (
                    "Overrides role_id for the worker component only. Set this when the API and "
                    f"worker authenticate to {product} with different AppRoles."
                ),
                "x_fallback_of": "role_id",
                "x_component": "worker",
            },
            "worker_secret_id": {
                **_SECRET_REF_FIELD,
                "title": "AppRole secret ID (worker override)",
                "description": (
                    "Overrides secret_id for the worker component only. Set this when the API and "
                    f"worker authenticate to {product} with different AppRoles."
                ),
                "x_fallback_of": "secret_id",
                "x_component": "worker",
            },
            # The file-path equivalents of the four overrides above. These are what a
            # deployment that rotates AppRole credentials should use: each component reads
            # its own file, and the client re-reads it on every login.
            "api_role_id_file": {
                "type": "string",
                "title": "AppRole role ID file (API override)",
                "description": (
                    "Overrides role_id_file for the API component only. Use with "
                    "worker_role_id_file when the API and worker hold separate AppRoles."
                ),
                "x_fallback_of": "role_id_file",
                "x_component": "api",
            },
            "api_secret_id_file": {
                "type": "string",
                "title": "AppRole secret ID file (API override)",
                "description": (
                    "Overrides secret_id_file for the API component only. Use with "
                    "worker_secret_id_file when the API and worker hold separate AppRoles."
                ),
                "x_fallback_of": "secret_id_file",
                "x_component": "api",
            },
            "worker_role_id_file": {
                "type": "string",
                "title": "AppRole role ID file (worker override)",
                "description": (
                    "Overrides role_id_file for the worker component only. Use with "
                    "api_role_id_file when the API and worker hold separate AppRoles."
                ),
                "x_fallback_of": "role_id_file",
                "x_component": "worker",
            },
            "worker_secret_id_file": {
                "type": "string",
                "title": "AppRole secret ID file (worker override)",
                "description": (
                    "Overrides secret_id_file for the worker component only. Use with "
                    "api_secret_id_file when the API and worker hold separate AppRoles."
                ),
                "x_fallback_of": "secret_id_file",
                "x_component": "worker",
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
                    "Accept an http:// address. Off by default: plain HTTP sends the "
                    "AppRole secret ID and every secret value across the network in "
                    "cleartext. Turn it on only for a dev server or a network you "
                    "already trust to carry them."
                ),
                "default": False,
            },
        },
    }


_VAULT_CONFIG_SCHEMA: dict[str, Any] = _config_schema("Vault", "https://vault:8200")
_OPENBAO_CONFIG_SCHEMA: dict[str, Any] = _config_schema("OpenBao", "https://openbao:8200")


def build_vault_backend(config: dict[str, Any]) -> VaultSecretsBackend:
    """Build a :class:`VaultSecretsBackend` from an already-resolved configuration dict."""
    return VaultSecretsBackend(VaultBackendConfig.from_dict(config))


def build_openbao_backend(config: dict[str, Any]) -> VaultSecretsBackend:
    """Build an OpenBao-backed :class:`VaultSecretsBackend`.

    Deliberately a separate function rather than an alias of :func:`build_vault_backend`,
    even though the two are identical today: the registry records the factory object, so a
    distinct callable is what lets OpenBao's construction diverge later without touching
    the Vault types.
    """
    return VaultSecretsBackend(VaultBackendConfig.from_dict(config))


def register(registry: SecretBackendRegistry) -> None:
    """Entry point for the ``hegemony.secret_backends`` group."""
    registry.register_backend_type(
        backend_type="vault",
        display_name="HashiCorp Vault (KV v2)",
        description="Generic HashiCorp Vault KV v2 secrets backend.",
        factory=build_vault_backend,
        config_schema=_VAULT_CONFIG_SCHEMA,
    )
    registry.register_backend_type(
        backend_type="vault_kv2",
        display_name="HashiCorp Vault (KV v2, legacy type)",
        description=(
            "Legacy alias of the generic vault type; kept resolvable for existing "
            "backends but hidden from create-time type pickers."
        ),
        factory=build_vault_backend,
        config_schema=_VAULT_CONFIG_SCHEMA,
        hidden=True,
    )
    registry.register_backend_type(
        backend_type="openbao",
        display_name="OpenBao (KV v2)",
        description=(
            "OpenBao KV v2 secrets backend. OpenBao is the Linux Foundation fork of "
            "HashiCorp Vault and keeps its HTTP API, so the same client serves both."
        ),
        factory=build_openbao_backend,
        config_schema=_OPENBAO_CONFIG_SCHEMA,
    )


__all__ = ["build_openbao_backend", "build_vault_backend", "register"]
