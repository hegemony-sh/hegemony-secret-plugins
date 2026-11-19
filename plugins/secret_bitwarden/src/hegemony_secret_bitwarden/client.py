# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""HTTP client for the part of the Bitwarden client API this plugin uses.

Vaultwarden and self-hosted Bitwarden serve the identity endpoints under
``<server>/identity`` and the vault endpoints under ``<server>/api``. The client logs
in with a personal API key (the ``client_credentials`` grant), which needs no second
factor, and re-logs in when the access token runs out: that grant issues no refresh
token.

This module moves ciphertext only. Decryption lives in :mod:`.crypto` and
:mod:`.backend`.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx

_DEVICE_NAME = "Hegemony"
# Bitwarden's DeviceType 21 is "SDK": a non-interactive API client.
_DEVICE_TYPE = "21"
_DEVICE_NAMESPACE = uuid.UUID("7d1f4f0c-6f0b-5b0e-9d3a-2c1f0e6f8a11")
# Re-login this long before the token's stated expiry, so a request never races it.
_TOKEN_EXPIRY_MARGIN_SECONDS = 60
_ERROR_MESSAGE_LIMIT = 200


class VaultwardenError(RuntimeError):
    """The server refused a request or answered with something unusable.

    Attributes:
        status_code: The HTTP status, or ``None`` when there was no usable response.
    """

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def get_field(obj: Any, name: str) -> Any:
    """Read ``name`` from a response object, whatever the case of its first letter.

    Vaultwarden moved its JSON from ``PascalCase`` to ``camelCase`` keys in 1.31, and
    the token endpoint still mixes both.
    """
    if not isinstance(obj, Mapping) or not name:
        return None
    for key in (name, name[0].upper() + name[1:], name[0].lower() + name[1:]):
        if key in obj:
            return obj[key]
    return None


def device_identifier(server_url: str, client_id: str) -> str:
    """A stable device id for this backend configuration.

    The server registers every new device identifier as a new device and, when mail is
    configured, sends the account a "new device logged in" email. A stable id keeps
    that to one email per configuration instead of one per process start.
    """
    return str(uuid.uuid5(_DEVICE_NAMESPACE, f"{server_url}\n{client_id}"))


def _error_message(response: httpx.Response) -> str:
    """The server's own error text, bounded; never the request, which holds secrets."""
    message: Any = None
    try:
        body = response.json()
    except ValueError:
        body = None
    if isinstance(body, Mapping):
        model = get_field(body, "errorModel")
        message = (
            get_field(model, "message")
            or get_field(body, "message")
            or body.get("error_description")
            or body.get("error")
        )
    text = str(message).strip() if message else response.reason_phrase or "no error message"
    if len(text) > _ERROR_MESSAGE_LIMIT:
        text = text[:_ERROR_MESSAGE_LIMIT] + "…"
    return text


@dataclass(frozen=True, repr=False)
class LoginResult:
    """What a login returns: the token and the account's still-encrypted key material."""

    access_token: str
    expires_at: float
    user_key: Any
    private_key: Any
    kdf_type: Any
    kdf_iterations: Any
    kdf_memory: Any
    kdf_parallelism: Any
    salt: str | None

    def __repr__(self) -> str:
        return "LoginResult(<redacted>)"


class VaultwardenClient:
    """Authenticated access to one account on a Vaultwarden or Bitwarden server."""

    def __init__(
        self,
        *,
        server_url: str,
        client_id: str,
        client_secret: str,
        timeout: float,
        verify: bool | str = True,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._server_url = server_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._http = httpx.Client(
            base_url=self._server_url,
            timeout=timeout,
            verify=verify,
            transport=transport,
            # A redirect could carry the bearer token or the API key to another host.
            follow_redirects=False,
            headers={"Accept": "application/json", "Device-Type": _DEVICE_TYPE},
        )
        self._login: LoginResult | None = None
        self._lock = threading.Lock()

    def _send(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            return self._http.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            # str(exc) of a transport error names the host and the reason, not the
            # request body or headers.
            raise VaultwardenError(
                f"Vaultwarden request failed: {exc.__class__.__name__}: {exc}"
            ) from None

    def login(self, *, force: bool = False) -> LoginResult:
        """Return the current login, logging in again when it is missing or expired."""
        with self._lock:
            current = self._login
            if not force and current is not None and time.monotonic() < current.expires_at:
                return current
            response = self._send(
                "POST",
                "/identity/connect/token",
                data={
                    "grant_type": "client_credentials",
                    "scope": "api",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "deviceType": _DEVICE_TYPE,
                    "deviceIdentifier": device_identifier(self._server_url, self._client_id),
                    "deviceName": _DEVICE_NAME,
                },
            )
            if response.status_code != 200:
                raise VaultwardenError(
                    f"Vaultwarden login failed ({response.status_code}): "
                    f"{_error_message(response)}",
                    response.status_code,
                )
            try:
                body = response.json()
            except ValueError:
                body = None
            token = body.get("access_token") if isinstance(body, Mapping) else None
            if not isinstance(token, str) or not token:
                raise VaultwardenError(
                    "Vaultwarden login returned no access token; is the server URL the "
                    "base address of a Vaultwarden or Bitwarden server?"
                )
            assert isinstance(body, Mapping)
            expires_in = body.get("expires_in")
            lifetime = float(expires_in) if isinstance(expires_in, int | float) else 0.0
            unlock = get_field(get_field(body, "userDecryptionOptions"), "masterPasswordUnlock")
            salt = get_field(unlock, "salt")
            self._login = LoginResult(
                access_token=token,
                expires_at=time.monotonic() + max(lifetime - _TOKEN_EXPIRY_MARGIN_SECONDS, 0.0),
                user_key=get_field(body, "key"),
                private_key=get_field(body, "privateKey"),
                kdf_type=get_field(body, "kdf"),
                kdf_iterations=get_field(body, "kdfIterations"),
                kdf_memory=get_field(body, "kdfMemory"),
                kdf_parallelism=get_field(body, "kdfParallelism"),
                salt=salt if isinstance(salt, str) and salt else None,
            )
            return self._login

    def request(self, method: str, path: str, *, json: Any = None) -> Any:
        """Call a vault endpoint and return its decoded JSON body (``None`` if empty).

        A 401 is retried once after a fresh login, since the server can revoke a token
        before its stated expiry.

        Raises:
            VaultwardenError: On a transport failure or any non-2xx response.
        """
        response: httpx.Response | None = None
        for attempt in (0, 1):
            login = self.login(force=attempt == 1)
            response = self._send(
                method,
                path,
                json=json,
                headers={"Authorization": f"Bearer {login.access_token}"},
            )
            if response.status_code != 401:
                break
        assert response is not None
        if not response.is_success:
            raise VaultwardenError(
                f"Vaultwarden {method} {path.split('?')[0]} failed "
                f"({response.status_code}): {_error_message(response)}",
                response.status_code,
            )
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            raise VaultwardenError(
                f"Vaultwarden {method} {path.split('?')[0]} returned a non-JSON response"
            ) from None

    def sync(self) -> Mapping[str, Any]:
        """Download the account's whole (encrypted) vault."""
        body = self.request("GET", "/api/sync?excludeDomains=true")
        if not isinstance(body, Mapping):
            raise VaultwardenError("Vaultwarden sync returned an unexpected response")
        return body

    def create_cipher(self, cipher: Mapping[str, Any], collection_ids: list[str]) -> None:
        """Create an organization item in the given collections."""
        self.request(
            "POST", "/api/ciphers/create", json={"cipher": cipher, "collectionIds": collection_ids}
        )

    def update_cipher(self, cipher_id: str, cipher: Mapping[str, Any]) -> None:
        """Replace an existing item."""
        self.request("PUT", f"/api/ciphers/{cipher_id}", json=cipher)

    def trash_cipher(self, cipher_id: str) -> None:
        """Move an item to the trash (a soft delete the server can restore)."""
        self.request("PUT", f"/api/ciphers/{cipher_id}/delete")

    def close(self) -> None:
        self._http.close()
