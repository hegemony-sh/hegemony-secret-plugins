# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Vault secrets backend client.

This module provides a client for HashiCorp Vault KV v2 secrets engine.
It handles AppRole authentication, token caching, and automatic re-authentication.

The client is designed to be used by both API and Worker components.
"""

from __future__ import annotations

import base64
import builtins
import logging
import os
import re
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# Token expiry buffer in seconds - refresh token this many seconds before expiry
TOKEN_EXPIRY_BUFFER_SECONDS = 60

# Per-request timeout. Unbounded requests let an unresponsive server pin the calling
# thread indefinitely, which in the worker means losing a slot per stuck resolution.
DEFAULT_TIMEOUT_SECONDS = 30

#: Transit key names the backend accepts (they become URL path segments). Vault's own
#: rule also wants a letter, digit or underscore at both ends.
_TRANSIT_KEY_NAME_RE = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,126}[A-Za-z0-9_])?")
#: Size of the data keys wrap_data_key issues (the SDK contract: 256-bit keys).
_DATA_KEY_BITS = 256


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


@dataclass
class VaultBackendConfig:
    """Configuration for a Vault backend.

    Attributes:
        address: Vault server address (e.g., "http://vault:8200")
        kv_mount: KV v2 mount point (default: "hegemony")
        path_prefix: Optional prefix for all paths (default: "")
        token: Static Vault token (for dev mode - takes precedence over AppRole)
        role_id: AppRole role ID (or path to file with _file suffix)
        secret_id: AppRole secret ID (or path to file with _file suffix)
        role_id_file: Path to file containing role ID
        secret_id_file: Path to file containing secret ID
        ca_cert_file: Optional path to CA certificate for TLS
        verify_ssl: Whether to verify SSL certificates (default: True)
        allow_insecure_http: Opt in to a plain-HTTP address (default: False)
        namespace: Optional namespace to scope every request to (OpenBao / Vault Enterprise)
        timeout: Per-request timeout in seconds
        transit_mount: Transit secrets engine mount used for data-key wrapping
    """

    address: str
    kv_mount: str = "hegemony"
    path_prefix: str = ""
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
    transit_mount: str = "transit"

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
        address = config.get("address")
        if not address:
            raise ValueError("Vault backend config is missing required field: address")
        return cls(
            address=address,
            kv_mount=config.get("kv_mount", "hegemony"),
            path_prefix=config.get("path_prefix", ""),
            token=_normalize_auth_value(config.get("token")),
            role_id=_normalize_auth_value(config.get("role_id")),
            secret_id=_normalize_auth_value(config.get("secret_id")),
            role_id_file=config.get("role_id_file"),
            secret_id_file=config.get("secret_id_file"),
            ca_cert_file=config.get("ca_cert_file"),
            verify_ssl=config.get("verify_ssl", config.get("verify", True)),
            allow_insecure_http=bool(config.get("allow_insecure_http", False)),
            namespace=_normalize_auth_value(config.get("namespace")),
            timeout=_normalize_timeout(config.get("timeout")),
            transit_mount=str(config.get("transit_mount") or "").strip().strip("/") or "transit",
        )


class VaultSecretsBackend:
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

    def __init__(self, config: VaultBackendConfig):
        """Initialize the Vault backend.

        Args:
            config: Vault backend configuration

        Raises:
            ImportError: If hvac library is not installed
            ValueError: If token auth not provided and neither role_id nor role_id_file is provided
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

    def wrap_data_key(self, key_name: str) -> tuple[bytes, str]:
        """Issue a fresh 256-bit data key wrapped by the Transit key ``key_name``.

        Uses ``transit/datakey/plaintext/<key_name>``: the plaintext comes back once for
        the caller to encrypt with, the ciphertext is what the caller stores. A missing
        Transit key is created (``aes256-gcm96``) and the request retried once.

        Raises:
            ValueError: ``key_name`` is not a valid Transit key name.
            VaultError: The request failed (missing mount, missing policy, ...).
        """
        from hvac.exceptions import InvalidPath, InvalidRequest

        name = self._transit_key_name(key_name)
        self._ensure_authenticated()
        transit = self._client.secrets.transit
        mount = self._config.transit_mount

        def _generate() -> Any:
            return _reject_redirect(
                transit.generate_data_key(
                    name=name, key_type="plaintext", bits=_DATA_KEY_BITS, mount_point=mount
                ),
                "data key generation",
            )

        try:
            try:
                response = _generate()
            except InvalidRequest as e:
                # A missing key is a 400 "encryption key not found". A missing or
                # misnamed mount is a 404 (InvalidPath), handled below as it is.
                if "encryption key not found" not in str(e).lower():
                    raise
                logger.info("Creating Transit key %s on mount %s", name, mount)
                _reject_redirect(
                    transit.create_key(name=name, key_type="aes256-gcm96", mount_point=mount),
                    "transit key creation",
                )
                response = _generate()
            data = response["data"]
            plaintext = base64.b64decode(data["plaintext"], validate=True)
            if len(plaintext) != _DATA_KEY_BITS // 8:
                raise VaultError(
                    f"Transit returned a {len(plaintext) * 8}-bit data key, "
                    f"expected {_DATA_KEY_BITS} bits"
                )
            return plaintext, str(data["ciphertext"])
        except VaultError:
            raise
        except InvalidPath as e:
            logger.error("No Transit engine at mount %s: %s", mount, e)
            raise VaultError(
                f"No Transit secrets engine at mount {mount!r} (check transit_mount): {e}"
            ) from e
        except Exception as e:
            logger.error("Vault data key generation failed for key %s: %s", name, e)
            raise VaultError(f"Failed to generate a data key with Transit: {e}") from e

    def unwrap_data_key(self, key_name: str, wrapped_key: str) -> bytes:
        """Decrypt a data key :meth:`wrap_data_key` issued, with the Transit key ``key_name``.

        Raises:
            ValueError: ``key_name`` is not a valid Transit key name.
            VaultError: The request failed (wrong key, missing policy, ...).
        """
        name = self._transit_key_name(key_name)
        self._ensure_authenticated()
        try:
            response = _reject_redirect(
                self._client.secrets.transit.decrypt_data(
                    name=name,
                    ciphertext=wrapped_key,
                    mount_point=self._config.transit_mount,
                ),
                "data key unwrap",
            )
            return base64.b64decode(response["data"]["plaintext"])
        except VaultError:
            raise
        except Exception as e:
            logger.error("Vault data key unwrap failed for key %s: %s", name, e)
            raise VaultError(f"Failed to unwrap a data key with Transit: {e}") from e

    @staticmethod
    def _transit_key_name(key_name: str) -> str:
        if not isinstance(key_name, str) or not _TRANSIT_KEY_NAME_RE.fullmatch(key_name):
            raise ValueError(f"invalid Transit key name {key_name!r}")
        return key_name

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


class VaultError(Exception):
    """Base exception for Vault operations."""

    pass


class VaultAuthError(VaultError):
    """Exception for Vault authentication failures."""

    pass
