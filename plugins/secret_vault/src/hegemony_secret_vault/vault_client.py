# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Vault secrets backend client.

This module provides a client for HashiCorp Vault KV v2 secrets engine.
It handles AppRole authentication, token caching, and automatic re-authentication.

The connection and authentication core lives in :class:`_VaultAuthenticatedClient` so
other Vault-backed backend types (the SSH one-time-password backend in
``ssh_otp_client``) share it without inheriting the KV v2 methods. The host
feature-detects optional capabilities such as ``list`` on the backend instance, so a
non-KV backend must not carry them.

The client is designed to be used by both API and Worker components.
"""

from __future__ import annotations

import builtins
import logging
import os
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from hegemony_secret_sdk import SecretVersion, VersionConflictError, VersionedSecret

logger = logging.getLogger(__name__)

# Token expiry buffer in seconds - refresh token this many seconds before expiry
TOKEN_EXPIRY_BUFFER_SECONDS = 60

# The KV v2 error text for a check-and-set write whose cas value is not the current
# version. Vault and OpenBao answer it as an HTTP 400 (hvac: InvalidRequest).
_CAS_MISMATCH_MARKER = "check-and-set parameter did not match the current version"

# Per-request timeout. Unbounded requests let an unresponsive server pin the calling
# thread indefinitely, which in the worker means losing a slot per stuck resolution.
DEFAULT_TIMEOUT_SECONDS = 30


def _normalize_timeout(value: Any) -> int:
    """Coerce a configured timeout to a positive int, or raise a clear error.

    Backend config arrives as JSON from the host's database and may have been through
    templating, so a bare ``int()`` here can meet whitespace or an empty string and blow
    up with an opaque ValueError at client construction. A zero or negative value is a
    misconfiguration rather than "no timeout": the schema declares ``minimum: 1``, and
    accepting it would reinstate exactly the unbounded request this field exists to stop.
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        return DEFAULT_TIMEOUT_SECONDS
    try:
        timeout = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Vault backend config has a non-numeric timeout: {value!r}") from exc
    if timeout < 1:
        raise ValueError(f"Vault backend config timeout must be at least 1 second: {timeout}")
    return timeout


def _reject_redirect(response: Any, operation: str) -> Any:
    """Fail loudly when the server answered a request with a redirect.

    The client is built with ``allow_redirects=False``, so hvac hands the raw 3xx
    response back instead of following it. Every caller expects a decoded JSON body, and
    ``write``/``delete`` do not inspect the result at all -- so without this check a
    redirected write would look like a success while nothing was stored.

    A Vault or OpenBao node redirects when it is a standby and request forwarding is
    disabled. The fix is to address the active node, not to follow the redirect.
    """
    status = getattr(response, "status_code", None)
    if isinstance(status, int) and 300 <= status < 400:
        headers = getattr(response, "headers", None)
        location = ""
        if isinstance(headers, Mapping):
            location = str(headers.get("Location", ""))
        target = f" to {location}" if location else ""
        raise VaultError(
            f"Vault {operation} was answered with an HTTP {status} redirect{target}, "
            "which this client does not follow because the request carries a Vault "
            "token. Point the backend address at the active node."
        )
    return response


def _normalize_auth_value(value: Any) -> str | None:
    """Normalize line-oriented Vault auth material from env/file placeholders."""
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _version_metadata_from_error(error: Any) -> Mapping[str, Any] | None:
    """The KV v2 version metadata carried by a 404, or ``None`` for a path that never existed.

    Reading a deleted or destroyed version answers 404 with the version's metadata in
    the body; a path with no versions at all answers 404 without it. hvac keeps the
    decoded body on the exception as ``json``.
    """
    body = getattr(error, "json", None)
    if not isinstance(body, Mapping):
        return None
    data = body.get("data")
    if not isinstance(data, Mapping):
        return None
    metadata = data.get("metadata")
    if not isinstance(metadata, Mapping) or "version" not in metadata:
        return None
    return metadata


def _versioned_secret(payload: Mapping[str, Any]) -> VersionedSecret:
    """Build a :class:`VersionedSecret` from a KV v2 ``data`` payload (``data`` + ``metadata``)."""
    metadata = payload.get("metadata") or {}
    data = payload.get("data")
    version = int(metadata.get("version") or 0)
    created_at = metadata.get("created_time") or None
    if data is None:
        return VersionedSecret(data={}, version=version, created_at=created_at, deleted=True)
    return VersionedSecret(data=dict(data), version=version, created_at=created_at)


@dataclass
class VaultConnectionConfig:
    """Connection and authentication settings shared by every Vault-backed backend type.

    Attributes:
        address: Vault server address (e.g., "https://vault:8200")
        token: Static Vault token (for dev mode - takes precedence over AppRole)
        role_id: AppRole role ID
        secret_id: AppRole secret ID
        role_id_file: Path to file containing role ID
        secret_id_file: Path to file containing secret ID
        ca_cert_file: Optional path to CA certificate for TLS
        verify_ssl: Whether to verify SSL certificates (default: True)
        allow_insecure_http: Opt in to a plain-HTTP address (default: False)
        namespace: Optional namespace to scope every request to (OpenBao / Vault Enterprise)
        timeout: Per-request timeout in seconds
    """

    address: str
    token: str | None = None
    role_id: str | None = None
    secret_id: str | None = None
    role_id_file: str | None = None
    secret_id_file: str | None = None
    ca_cert_file: str | None = None
    verify_ssl: bool = True
    allow_insecure_http: bool = False
    namespace: str | None = None
    timeout: int = DEFAULT_TIMEOUT_SECONDS

    @classmethod
    def _connection_kwargs(cls, config: dict) -> dict[str, Any]:
        """Normalise the shared connection fields of a resolved config dict.

        Every Vault-backed type builds itself as ``cls(**cls._connection_kwargs(config),
        ...)`` so auth material, the legacy ``verify`` key and the timeout are parsed
        identically whichever engine the type talks to.

        Args:
            config: Dictionary with config values. Supports both 'verify_ssl' and
                    legacy 'verify' key for SSL verification setting.
        """
        address = config.get("address")
        if not address:
            raise ValueError("Vault backend config is missing required field: address")
        return {
            "address": address,
            "token": _normalize_auth_value(config.get("token")),
            "role_id": _normalize_auth_value(config.get("role_id")),
            "secret_id": _normalize_auth_value(config.get("secret_id")),
            "role_id_file": config.get("role_id_file"),
            "secret_id_file": config.get("secret_id_file"),
            "ca_cert_file": config.get("ca_cert_file"),
            "verify_ssl": config.get("verify_ssl", config.get("verify", True)),
            "allow_insecure_http": bool(config.get("allow_insecure_http", False)),
            "namespace": _normalize_auth_value(config.get("namespace")),
            "timeout": _normalize_timeout(config.get("timeout")),
        }


@dataclass
class VaultBackendConfig(VaultConnectionConfig):
    """Configuration for a Vault KV v2 backend.

    Adds the KV v2 addressing to :class:`VaultConnectionConfig`:

    Attributes:
        kv_mount: KV v2 mount point (default: "hegemony")
        path_prefix: Optional prefix for all paths (default: "")
    """

    kv_mount: str = "hegemony"
    path_prefix: str = ""

    @classmethod
    def from_dict(cls, config: dict) -> VaultBackendConfig:
        """Create VaultBackendConfig from a dictionary.

        This is a convenience method for creating a config from resolved
        backend configuration (e.g., from database or API response).

        Args:
            config: Dictionary with config values. Supports both 'verify_ssl' and
                    legacy 'verify' key for SSL verification setting.

        Returns:
            VaultBackendConfig instance
        """
        return cls(
            **cls._connection_kwargs(config),
            kv_mount=config.get("kv_mount", "hegemony"),
            path_prefix=config.get("path_prefix", ""),
        )


class _VaultAuthenticatedClient:
    """The hvac client plus the token/AppRole lifecycle every Vault-backed type needs.

    Provides:
    - the HTTPS-only transport policy (plain HTTP needs an explicit opt-in) and a
      client that never follows redirects
    - static token auth (dev mode) or AppRole auth with automatic token refresh,
      re-resolving ``*_file`` credentials on every login
    - thread-safe token caching

    Subclasses add the engine-specific operations: KV v2 in
    :class:`VaultSecretsBackend`, SSH one-time passwords in ``ssh_otp_client``. This
    class deliberately implements none of the ``SecretBackend`` methods -- and in
    particular no ``list`` -- because the host feature-detects optional capabilities
    on the instance with ``hasattr``.
    """

    _config: VaultConnectionConfig

    def __init__(self, config: VaultConnectionConfig):
        """Build the hvac client and validate the configured auth method.

        Args:
            config: Connection and authentication settings

        Raises:
            ImportError: If hvac library is not installed
            ValueError: If the address is not HTTPS without the explicit opt-in, or
                token auth is not provided and neither role_id nor role_id_file is
                provided
        """
        try:
            import hvac
        except ImportError as e:
            raise ImportError(
                "hvac library is required for Vault integration. Install with: pip install hvac"
            ) from e

        self._config = config
        self._client: Any = None
        self._token_expiry: float = 0
        self._lock = threading.Lock()
        self._static_token = _normalize_auth_value(config.token)
        self._use_token_auth = bool(self._static_token)

        # Initialize hvac client
        verify: bool | str = config.verify_ssl
        if config.verify_ssl and config.ca_cert_file:
            verify = config.ca_cert_file

        if not str(config.address).lower().startswith("https://"):
            # Plain HTTP puts the AppRole secret ID and every secret value on the wire in
            # the clear, so it is refused unless the deployment says in its own config
            # that it accepts that. A log warning was not enough: it changes nothing, and
            # an address left on http:// after an upgrade would keep leaking silently.
            if not config.allow_insecure_http:
                raise ValueError(
                    f"Secret backend address {config.address} is not HTTPS. Credentials "
                    "and secret values would be sent in cleartext. Use an https:// "
                    "address, or set allow_insecure_http to true to accept the risk "
                    "(dev servers and trusted-network deployments only)."
                )
            logger.warning(
                "Secret backend address %s is not HTTPS and allow_insecure_http is set: "
                "credentials and secret values are sent in cleartext.",
                config.address,
            )

        self._client = hvac.Client(
            url=config.address,
            verify=verify,
            timeout=config.timeout,
            namespace=config.namespace,
            # The token travels in the X-Vault-Token header. requests drops only
            # Authorization when a redirect crosses hosts, so a custom header like this
            # one would be replayed verbatim to whatever host a 3xx names -- handing the
            # token to it. Refuse to follow; _reject_redirect turns the unfollowed
            # response into a clear error.
            allow_redirects=False,
        )

        if self._use_token_auth:
            # Token auth (dev mode) - use static token directly
            logger.debug("Using static token auth for Vault")
            self._client.token = self._static_token
        else:
            # hvac.Client falls back to the VAULT_TOKEN environment variable when it is
            # constructed without a token. On the AppRole path that would let a stray
            # environment variable silently authenticate this backend -- and keep it
            # working after the configured AppRole stopped being valid, hiding the
            # breakage rather than surfacing it. Clear it: the only token this backend may
            # use is one _authenticate() minted from the configured role.
            self._client.token = None
            # AppRole auth (production) - resolve once now to fail fast on
            # misconfiguration; _authenticate() re-resolves per login so rotated
            # *_file contents (e.g. a credential-rotating sidecar re-writing the
            # secret-id file) are picked up without a client rebuild.
            self._resolve_approle_credentials()

    def _resolve_approle_credentials(self) -> tuple[str, str]:
        """Resolve the AppRole (role_id, secret_id) pair from config values or files.

        Called at construction (validation) and again on every authentication, so
        credentials delivered via files reflect the files' *current* contents.
        """
        role_id = self._resolve_credential(
            self._config.role_id, self._config.role_id_file, "role_id"
        )
        secret_id = self._resolve_credential(
            self._config.secret_id, self._config.secret_id_file, "secret_id"
        )
        return role_id, secret_id

    @staticmethod
    def _resolve_credential(
        value: str | None,
        file_path: str | None,
        name: str,
    ) -> str:
        """Resolve a credential from direct value or file.

        Args:
            value: Direct credential value
            file_path: Path to file containing credential
            name: Credential name for error messages

        Returns:
            The credential value

        Raises:
            ValueError: If neither value nor file_path is provided
        """
        normalized = _normalize_auth_value(value)
        if normalized:
            return normalized

        if file_path:
            if not os.path.exists(file_path):
                raise ValueError(f"{name} file not found: {file_path}")
            with open(file_path) as f:
                return f.read().strip()

        raise ValueError(f"Either {name} or {name}_file must be provided for Vault authentication")

    def _ensure_authenticated(self) -> None:
        """Ensure we have a valid Vault token, re-authenticating if needed.

        This method is thread-safe and will only authenticate once even if
        called concurrently from multiple threads.

        For static token auth (dev mode), this is a no-op since the token
        is set during initialization.
        """
        # Token auth (dev mode) - no authentication needed
        if self._use_token_auth:
            return

        # Fast path: check if token is valid (acquires lock internally)
        if self._is_token_valid():
            return

        with self._lock:
            # Double-check after acquiring outer lock to prevent race
            if self._is_token_valid_unlocked():
                return

            self._authenticate()

    def _is_token_valid_unlocked(self) -> bool:
        """Check if the current token is valid WITHOUT acquiring lock.

        Returns:
            True if the token exists and hasn't expired (with 60s buffer)

        Note: This method MUST only be called while holding self._lock.
        Use _is_token_valid() for thread-safe access from outside the lock.
        """
        # Static token auth - always valid (token doesn't expire)
        if self._use_token_auth:
            return True

        if not self._client.token:
            return False
        return time.time() < (self._token_expiry - TOKEN_EXPIRY_BUFFER_SECONDS)

    def _is_token_valid(self) -> bool:
        """Check if the current token is still valid (thread-safe).

        Returns:
            True if the token exists and hasn't expired (with buffer)

        Note: This method acquires the lock to ensure thread-safe reads
        of token and expiry that are consistent with _ensure_authenticated.
        """
        # Static token auth - always valid
        if self._use_token_auth:
            return True

        with self._lock:
            return self._is_token_valid_unlocked()

    def _authenticate(self) -> None:
        """Authenticate to Vault using AppRole.

        Raises:
            VaultAuthError: If authentication fails
        """
        try:
            logger.debug("Authenticating to Vault with AppRole")

            role_id, secret_id = self._resolve_approle_credentials()
            response = _reject_redirect(
                self._client.auth.approle.login(
                    role_id=role_id,
                    secret_id=secret_id,
                ),
                "AppRole login",
            )

            auth_data = response.get("auth", {})

            # Store the minted token explicitly. hvac's login() also stores it on the
            # adapter as a side effect, but this class treats a falsy client token as
            # "not authenticated yet" (see _is_token_valid_unlocked), and the AppRole
            # path deliberately starts from token=None -- so the two must not drift.
            client_token = auth_data.get("client_token")
            if client_token:
                self._client.token = client_token

            # hvac's login() also stores the token on the adapter, so check the effective
            # state rather than just the response body. If neither produced a token the
            # login did not actually authenticate us: without this, _is_token_valid would
            # stay false and every operation would re-login forever instead of surfacing
            # a broken or changed API response.
            if not self._client.token:
                raise VaultAuthError(
                    "Vault AppRole login returned no client token; the response was "
                    f"missing auth.client_token: {sorted(auth_data)}"
                )

            # Extract token TTL and set expiry
            lease_duration = auth_data.get("lease_duration", 3600)
            if lease_duration and lease_duration > 0:
                self._token_expiry = time.time() + lease_duration
                logger.info(
                    "Vault authentication successful, token valid for %d seconds",
                    lease_duration,
                )
            else:
                # lease_duration 0 means the token never expires; treating it as
                # already-expired would force a fresh AppRole login (and a new
                # Vault token) on every single operation.
                self._token_expiry = float("inf")
                logger.info("Vault authentication successful, token does not expire")

        except VaultAuthError:
            # Already precise about what went wrong; re-wrapping would double the prefix.
            raise
        except Exception as e:
            logger.error("Vault authentication failed: %s", e)
            raise VaultAuthError(f"Vault AppRole authentication failed: {e}") from e


class VaultSecretsBackend(_VaultAuthenticatedClient):
    """Vault KV v2 secrets backend using AppRole authentication.

    This client provides:
    - AppRole authentication with automatic token refresh
    - Thread-safe token caching
    - KV v2 read/write operations
    - Path prefix support for multi-tenant isolation

    Example:
        config = VaultBackendConfig(
            address="http://vault:8200",
            role_id="abc123",
            secret_id="xyz789",
        )
        backend = VaultSecretsBackend(config)

        # Read a secret
        data = backend.read("orgs/default/secrets/db")
        password = data["password"]

        # Write a secret
        backend.write("orgs/default/secrets/db", {"password": "new-pass"})
    """

    _config: VaultBackendConfig

    def __init__(self, config: VaultBackendConfig):
        """Initialize the Vault backend.

        Args:
            config: Vault backend configuration

        Raises:
            ImportError: If hvac library is not installed
            ValueError: If token auth not provided and neither role_id nor role_id_file is provided
        """
        super().__init__(config)

    def _full_path(self, path: str) -> str:
        """Build full path including prefix.

        Args:
            path: Relative path within the backend

        Returns:
            Full path including prefix
        """
        if self._config.path_prefix:
            return f"{self._config.path_prefix.rstrip('/')}/{path.lstrip('/')}"
        return path

    def read(self, path: str) -> dict[str, Any] | None:
        """Read a secret from Vault KV v2.

        Args:
            path: Path to the secret (relative to kv_mount and path_prefix)

        Returns:
            Dictionary containing the secret data, or None if not found

        Raises:
            VaultError: If the read operation fails (other than not found)
        """
        # Import hvac exceptions at the top of method (outside try block)
        from hvac.exceptions import InvalidPath

        self._ensure_authenticated()

        full_path = self._full_path(path)

        try:
            response = _reject_redirect(
                self._client.secrets.kv.v2.read_secret_version(
                    path=full_path,
                    mount_point=self._config.kv_mount,
                    # Explicit: hvac 2.x warns on every call that leaves it unset, and
                    # the pre-3.0 default (True: a deleted version is a 404) is what the
                    # SecretBackend contract wants from read().
                    raise_on_deleted_version=True,
                ),
                "read",
            )

            if response is None:
                return None

            return response.get("data", {}).get("data")

        except InvalidPath:
            # Explicit handling for missing values
            logger.debug("Value not found at path: %s", full_path)
            return None
        except VaultError:
            # Already precise; re-wrapping would nest two prefixes.
            raise
        except Exception as e:
            # Handle any other errors
            logger.error("Vault read failed for path %s: %s", full_path, e)
            raise VaultError(f"Failed to read secret from Vault: {e}") from e

    def write(self, path: str, data: Mapping[str, Any]) -> None:
        """Write a secret to Vault KV v2.

        Args:
            path: Path to the secret (relative to kv_mount and path_prefix)
            data: Dictionary of key-value pairs to store

        Raises:
            VaultError: If the write operation fails
        """
        self._ensure_authenticated()

        full_path = self._full_path(path)

        try:
            _reject_redirect(
                self._client.secrets.kv.v2.create_or_update_secret(
                    path=full_path,
                    secret=data,
                    mount_point=self._config.kv_mount,
                ),
                "write",
            )
            logger.debug("Value written to path: %s", full_path)

        except VaultError:
            raise
        except Exception as e:
            logger.error("Vault write failed for path %s: %s", full_path, e)
            raise VaultError(f"Failed to write secret to Vault: {e}") from e

    def delete(self, path: str) -> None:
        """Delete a secret from Vault KV v2 (permanent deletion).

        This permanently deletes the secret metadata and ALL versions.
        This operation cannot be undone.

        Args:
            path: Path to the secret

        Raises:
            VaultError: If the delete operation fails
        """
        from hvac.exceptions import InvalidPath

        self._ensure_authenticated()

        full_path = self._full_path(path)

        try:
            _reject_redirect(
                self._client.secrets.kv.v2.delete_metadata_and_all_versions(
                    path=full_path,
                    mount_point=self._config.kv_mount,
                ),
                "delete",
            )
            logger.debug("Value deleted at path: %s", full_path)

        except InvalidPath:
            logger.debug("Value already deleted or not found: %s", full_path)
            return
        except VaultError:
            raise
        except Exception as e:
            logger.error("Vault delete failed for path %s: %s", full_path, e)
            raise VaultError(f"Failed to delete secret from Vault: {e}") from e

    # builtins.list because the method name shadows the builtin in class scope.
    def list(self, path: str = "") -> builtins.list[str]:
        """List the immediate children under ``path`` in Vault KV v2.

        Container entries keep Vault's trailing ``"/"``; leaf entries are readable
        secret names. An unknown path returns ``[]``.

        Args:
            path: Folder path relative to kv_mount and path_prefix ("" for the root)

        Raises:
            VaultError: If the list operation fails (other than not found)
        """
        from hvac.exceptions import InvalidPath

        self._ensure_authenticated()

        full_path = self._full_path(path)

        try:
            response = _reject_redirect(
                self._client.secrets.kv.v2.list_secrets(
                    path=full_path,
                    mount_point=self._config.kv_mount,
                ),
                "list",
            )
            if response is None:
                return []
            return [str(key) for key in response.get("data", {}).get("keys", [])]
        except InvalidPath:
            return []
        except VaultError:
            raise
        except Exception as e:
            logger.error("Vault list failed for path %s: %s", full_path, e)
            raise VaultError(f"Failed to list secrets in Vault: {e}") from e

    def test(self) -> None:
        """Verify connectivity and authentication against Vault.

        Performs a lightweight check: authenticates (if needed) and confirms the
        client can reach the configured KV v2 mount. Reads the mount configuration
        when the token's policy allows it; typical app policies don't grant read on
        ``<mount>/config``, so a Forbidden there falls back to a LIST on the metadata
        root (an empty mount's 404 still proves mount + auth are good).

        Raises:
            VaultAuthError: If authentication fails
            VaultError: If the connectivity check fails for any other reason
        """
        from hvac.exceptions import Forbidden, InvalidPath

        try:
            self._ensure_authenticated()
        except VaultError:
            raise
        except Exception as e:
            logger.error("Vault connectivity check failed during authentication: %s", e)
            raise VaultAuthError(f"Vault authentication check failed: {e}") from e

        try:
            _reject_redirect(
                self._client.secrets.kv.v2.read_configuration(mount_point=self._config.kv_mount),
                "connectivity check",
            )
            return
        except Forbidden:
            logger.debug("Vault mount config read forbidden; falling back to metadata LIST")
        except VaultError:
            raise
        except Exception as e:
            logger.error("Vault connectivity check failed: %s", e)
            raise VaultError(f"Vault connectivity check failed: {e}") from e

        try:
            _reject_redirect(
                self._client.secrets.kv.v2.list_secrets(
                    path=self._config.path_prefix or "",
                    mount_point=self._config.kv_mount,
                ),
                "connectivity check",
            )
        except InvalidPath:
            # Empty mount/prefix: the request reached the mount with valid auth.
            return
        except VaultError:
            raise
        except Exception as e:
            logger.error("Vault connectivity check failed: %s", e)
            raise VaultError(f"Vault connectivity check failed: {e}") from e

    # --- KV v2 versions: the optional VersionedSecretBackend capability ------------

    def _read_versioned_at(self, path: str, version: int | None) -> VersionedSecret | None:
        from hvac.exceptions import InvalidPath

        self._ensure_authenticated()

        full_path = self._full_path(path)
        kwargs: dict[str, Any] = {
            "path": full_path,
            "mount_point": self._config.kv_mount,
            "raise_on_deleted_version": True,
        }
        if version is not None:
            kwargs["version"] = version

        try:
            response = _reject_redirect(
                self._client.secrets.kv.v2.read_secret_version(**kwargs), "read"
            )
        except InvalidPath as e:
            # A deleted or destroyed version still occupies the path, so a check-and-set
            # caller must learn its number rather than "nothing there" (cas=0 would then
            # fail forever on a path an operator soft-deleted).
            metadata = _version_metadata_from_error(e)
            if metadata is None:
                logger.debug("Value not found at path: %s", full_path)
                return None
            return _versioned_secret({"data": None, "metadata": metadata})
        except VaultError:
            raise
        except Exception as e:
            logger.error("Vault read failed for path %s: %s", full_path, e)
            raise VaultError(f"Failed to read secret from Vault: {e}") from e

        if response is None:
            return None
        return _versioned_secret(response.get("data") or {})

    def read_versioned(self, path: str) -> VersionedSecret | None:
        """Read the latest version at ``path`` with its version number.

        A deleted or destroyed latest version comes back with empty data and
        ``deleted=True``; ``None`` means nothing was ever stored at ``path``.
        """
        return self._read_versioned_at(path, None)

    def read_version(self, path: str, version: int) -> VersionedSecret | None:
        """Read one specific version at ``path``; ``None`` if the path does not exist."""
        return self._read_versioned_at(path, version)

    def versions(self, path: str) -> builtins.list[SecretVersion]:
        """List every version at ``path`` from its KV v2 metadata, oldest first."""
        from hvac.exceptions import InvalidPath

        self._ensure_authenticated()

        full_path = self._full_path(path)

        try:
            response = _reject_redirect(
                self._client.secrets.kv.v2.read_secret_metadata(
                    path=full_path,
                    mount_point=self._config.kv_mount,
                ),
                "metadata read",
            )
        except InvalidPath:
            return []
        except VaultError:
            raise
        except Exception as e:
            logger.error("Vault metadata read failed for path %s: %s", full_path, e)
            raise VaultError(f"Failed to read secret metadata from Vault: {e}") from e

        if response is None:
            return []
        entries = (response.get("data") or {}).get("versions") or {}
        listed = [
            SecretVersion(
                version=int(number),
                created_at=(info or {}).get("created_time") or None,
                deleted=bool((info or {}).get("deletion_time")),
                destroyed=bool((info or {}).get("destroyed")),
            )
            for number, info in entries.items()
        ]
        listed.sort(key=lambda entry: entry.version)
        return listed

    def write_checked(self, path: str, data: Mapping[str, Any], *, expected_version: int) -> int:
        """Write ``data`` only if the current version is ``expected_version`` (KV v2 cas).

        ``expected_version=0`` writes only when the path holds no version at all. Returns
        the version just written.

        Raises:
            VersionConflictError: If the current version differs; nothing was written.
            VaultError: If the write fails for any other reason.
        """
        from hvac.exceptions import InvalidRequest

        if expected_version < 0:
            raise ValueError(f"expected_version must be 0 or a version number: {expected_version}")

        self._ensure_authenticated()

        full_path = self._full_path(path)

        try:
            response = _reject_redirect(
                self._client.secrets.kv.v2.create_or_update_secret(
                    path=full_path,
                    secret=data,
                    cas=expected_version,
                    mount_point=self._config.kv_mount,
                ),
                "write",
            )
        except InvalidRequest as e:
            if _CAS_MISMATCH_MARKER in str(e):
                raise VersionConflictError(path, expected_version) from e
            logger.error("Vault write failed for path %s: %s", full_path, e)
            raise VaultError(f"Failed to write secret to Vault: {e}") from e
        except VaultError:
            raise
        except Exception as e:
            logger.error("Vault write failed for path %s: %s", full_path, e)
            raise VaultError(f"Failed to write secret to Vault: {e}") from e

        version = None
        if isinstance(response, Mapping):
            version = (response.get("data") or {}).get("version")
        if version is None:
            raise VaultError(
                f"Vault write to {full_path} returned no version number; the mount may not be KV v2"
            )
        logger.debug("Value written to path %s as version %s", full_path, version)
        return int(version)


class VaultError(Exception):
    """Base exception for Vault operations."""

    pass


class VaultAuthError(VaultError):
    """Exception for Vault authentication failures."""

    pass
