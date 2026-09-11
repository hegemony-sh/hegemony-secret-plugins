# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""1Password Service Account secrets backend client.

This module provides a client for 1Password using the (async) ``onepassword-sdk``
Service Account SDK. The SDK's client is authenticated and used entirely through
``async``/``await``; since the :class:`~hegemony_secret_sdk.SecretBackend` contract is
synchronous and the host may already be running its own event loop, a dedicated
background event-loop thread is used to run every SDK coroutine.
"""

from __future__ import annotations

import asyncio
import builtins
import concurrent.futures
import logging
import threading
from collections.abc import Coroutine, Mapping
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version as _package_version
from typing import Any, TypeVar

from .fields import build_field_mapping

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

_DEFAULT_INTEGRATION_NAME = "Hegemony"

_SDK_CALL_TIMEOUT_SECONDS = 60
"""Maximum time to wait for a single 1Password SDK coroutine to complete.

Bounds how long the calling thread can be blocked by :meth:`_AsyncLoopRunner.run`;
without it, a hung SDK call (e.g. a stalled network request) would pin a host
worker thread indefinitely.
"""


def _integration_version() -> str:
    """Return this plugin's installed release version for 1Password integration reporting.

    Falls back to a placeholder if the package's distribution metadata is unavailable
    (e.g. running from source without an installed distribution) so authentication
    still succeeds.
    """
    try:
        return _package_version("hegemony-secret-1password")
    except PackageNotFoundError:
        return "0.0.0"


# The SSH-key attributes the SDK computes for an SshKey field, exposed as
# "<field title>.<attribute>" beside the private key.
_SSH_KEY_ATTRIBUTES = ("public_key", "fingerprint", "key_type")


def _section_titles(item: Any) -> dict[str, str]:
    """Map an item's section ids to their titles (``Item.sections``)."""
    titles: dict[str, str] = {}
    for section in getattr(item, "sections", None) or []:
        section_id = getattr(section, "id", None)
        title = getattr(section, "title", None)
        if section_id and title:
            titles[str(section_id)] = str(title)
    return titles


def _field_values(field: Any) -> list[tuple[str, str]]:
    """The ``(key, value)`` pairs a Service Account field contributes.

    A TOTP field carries its seed in ``value`` and the computed code in
    ``details.content.code``; only the code is ever returned. An SshKey field
    contributes the private key (as 1Password stores it) under its title plus the
    computed ``public_key``/``fingerprint``/``key_type`` attributes when the SDK
    supplies them. A field without a value contributes nothing.
    """
    from onepassword import ItemFieldType

    title = str(getattr(field, "title", "") or "")
    if not title:
        return []
    field_type = getattr(field, "field_type", None)
    content = getattr(getattr(field, "details", None), "content", None)

    if field_type == ItemFieldType.TOTP:
        code = getattr(content, "code", None) if content is not None else None
        if not code:
            reason = getattr(content, "error_message", None) if content is not None else None
            logger.warning(
                "1Password field %r is a one-time-password field but no code was "
                "computed%s; skipping it",
                title,
                f" ({reason})" if reason else "",
            )
            return []
        return [(title, str(code))]

    value = getattr(field, "value", None)
    if value is None:
        return []
    pairs = [(title, str(value))]
    if field_type == ItemFieldType.SSHKEY and content is not None:
        for attribute in _SSH_KEY_ATTRIBUTES:
            attribute_value = getattr(content, attribute, None)
            if attribute_value:
                pairs.append((f"{title}.{attribute}", str(attribute_value)))
    return pairs


def _field_entries(item: Any) -> list[tuple[str, str | None, str]]:
    """Extract ``(title, section title, value)`` triples from a Service Account item."""
    sections = _section_titles(item)
    entries: list[tuple[str, str | None, str]] = []
    for field in getattr(item, "fields", None) or []:
        section_id = getattr(field, "section_id", None)
        section = sections.get(str(section_id)) if section_id else None
        entries.extend((key, section, value) for key, value in _field_values(field))
    return entries


def _split_path(path: str) -> tuple[str, str]:
    """Split a ``"<vault>/<item>"`` reference path into its two parts.

    Args:
        path: Reference path in ``"<vault>/<item>"`` form.

    Returns:
        A ``(vault, item)`` tuple.

    Raises:
        ValueError: If ``path`` does not contain exactly two non-empty parts.
    """
    parts = path.split("/", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"1Password secret path must be '<vault>/<item>', got: {path!r}")
    return parts[0], parts[1]


class _AsyncLoopRunner:
    """Runs coroutines on a single dedicated background event loop.

    The 1Password Service Account SDK's authenticated client is bound to the event
    loop it was created on. Rather than spinning up a fresh loop per call (which
    would break that binding, and which ``asyncio.run`` cannot safely do from inside
    a host event loop anyway), a single loop runs forever on a background thread and
    every coroutine — including the initial ``authenticate`` call — is submitted to
    it via :func:`asyncio.run_coroutine_threadsafe`.
    """

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever, daemon=True, name="hegemony-1password"
        )
        self._thread.start()

    def run(self, coro: Coroutine[Any, Any, _T]) -> _T:
        """Submit ``coro`` to the background loop and block for its result.

        Waits at most :data:`_SDK_CALL_TIMEOUT_SECONDS`; if the coroutine has not
        completed by then, it is cancelled on the background loop and a
        :class:`TimeoutError` is raised instead of blocking the calling thread
        forever.
        """
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=_SDK_CALL_TIMEOUT_SECONDS)
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise TimeoutError(
                f"1Password SDK call timed out after {_SDK_CALL_TIMEOUT_SECONDS}s"
            ) from None


_RUNNER: _AsyncLoopRunner | None = None
_RUNNER_LOCK = threading.Lock()


def _runner() -> _AsyncLoopRunner:
    global _RUNNER
    if _RUNNER is None:
        with _RUNNER_LOCK:
            if _RUNNER is None:
                _RUNNER = _AsyncLoopRunner()
    return _RUNNER


@dataclass
class OnePasswordServiceAccountConfig:
    """Configuration for a 1Password Service Account backend.

    Attributes:
        service_account_token: Service account auth token (``ops_...``)
        integration_name: Integration name reported to 1Password (default: "Hegemony")
    """

    service_account_token: str
    integration_name: str = _DEFAULT_INTEGRATION_NAME

    @classmethod
    def from_dict(cls, config: dict) -> OnePasswordServiceAccountConfig:
        """Create an :class:`OnePasswordServiceAccountConfig` from a dictionary.

        Args:
            config: Dictionary with config values, as resolved by the host.

        Returns:
            OnePasswordServiceAccountConfig instance
        """
        return cls(
            service_account_token=config["service_account_token"],
            integration_name=config.get("integration_name", _DEFAULT_INTEGRATION_NAME),
        )


class OnePasswordServiceAccountBackend:
    """1Password secrets backend using a Service Account token.

    The underlying ``onepassword-sdk`` client is asynchronous; this backend
    authenticates lazily on a dedicated background event-loop thread and runs every
    subsequent SDK call on that same loop, so its synchronous ``read``/``test``
    methods can be safely called even from inside a host event loop.

    Example:
        config = OnePasswordServiceAccountConfig(service_account_token="ops_...")
        backend = OnePasswordServiceAccountBackend(config)

        # Read a secret
        data = backend.read("Engineering/Database")
        password = data["password"]
    """

    def __init__(self, config: OnePasswordServiceAccountConfig):
        """Initialize the 1Password Service Account backend.

        Args:
            config: 1Password Service Account backend configuration

        Raises:
            ImportError: If the onepassword-sdk library is not installed
        """
        try:
            import onepassword.client  # noqa: F401
        except ImportError as e:
            raise ImportError(
                "onepassword-sdk library is required for 1Password Service Account "
                "integration. Install with: pip install onepassword-sdk"
            ) from e

        self._config = config
        self._client: Any = None
        self._lock = threading.Lock()

    async def _authenticate(self) -> Any:
        from onepassword.client import Client

        return await Client.authenticate(
            auth=self._config.service_account_token,
            integration_name=self._config.integration_name,
            integration_version=_integration_version(),
        )

    def _ensure_client(self) -> Any:
        """Authenticate lazily, on the shared background loop, and cache the client.

        Must be called from a thread other than the loop runner's own thread (i.e.
        from the synchronous ``read``/``test`` entry points, never from within a
        coroutine already scheduled on the runner), since it blocks on
        :meth:`_AsyncLoopRunner.run`.
        """
        if self._client is not None:
            return self._client

        with self._lock:
            if self._client is None:
                self._client = _runner().run(self._authenticate())
            return self._client

    async def _find_vault_id(self, client: Any, vault: str) -> str | None:
        """Resolve a vault title or id to its id; return ``None`` if not found.

        Raises:
            ValueError: If more than one vault matches the title (silently picking
                one could read or write the wrong vault's secrets).
        """
        vault_overviews = await client.vaults.list()
        matches = [
            overview.id
            for overview in vault_overviews
            if overview.title == vault or overview.id == vault
        ]
        if len(matches) > 1:
            raise ValueError(
                f"1Password vault title {vault!r} is ambiguous ({len(matches)} vaults); "
                "use the vault id instead"
            )
        return matches[0] if matches else None

    async def _find_item_id(self, client: Any, vault_id: str, item: str) -> str | None:
        """Resolve an item title or id to its id; return ``None`` if not found.

        Raises:
            ValueError: If more than one item matches the title.
        """
        item_overviews = await client.items.list(vault_id)
        matches = [
            overview.id
            for overview in item_overviews
            if overview.title == item or overview.id == item
        ]
        if len(matches) > 1:
            raise ValueError(
                f"1Password item title {item!r} is ambiguous ({len(matches)} items in "
                "the vault); use the item id instead"
            )
        return matches[0] if matches else None

    async def _read(self, client: Any, vault: str, item: str) -> dict[str, Any] | None:
        vault_id = await self._find_vault_id(client, vault)
        if vault_id is None:
            return None
        item_id = await self._find_item_id(client, vault_id, item)
        if item_id is None:
            return None
        found_item = await client.items.get(vault_id, item_id)
        return build_field_mapping(
            str(getattr(found_item, "title", item)), _field_entries(found_item)
        )

    def read(self, path: str) -> dict[str, Any] | None:
        """Read a 1Password item's fields via a Service Account.

        Args:
            path: Reference path in ``"<vault>/<item>"`` form (vault title/id and
                item title/id, split on the first ``/``).

        Returns:
            Mapping of field title (and ``<section>.<title>`` for sectioned fields) to
            field value, or ``None`` if the vault or item is not found. TOTP fields map
            to their current code, never the seed; SshKey fields add
            ``<title>.public_key``, ``<title>.fingerprint`` and ``<title>.key_type``.
            See ``fields.build_field_mapping`` for the duplicate-title rule.

        Raises:
            ValueError: If ``path`` is not exactly two non-empty parts.
        """
        vault, item = _split_path(path)
        client = self._ensure_client()
        return _runner().run(self._read(client, vault, item))

    async def _write(
        self, client: Any, vault: str, item_name: str, data: Mapping[str, Any]
    ) -> None:
        from onepassword import ItemCategory, ItemCreateParams, ItemField, ItemFieldType

        vault_id = await self._find_vault_id(client, vault)
        if vault_id is None:
            raise ValueError(f"1Password vault not found: {vault!r}")

        # The SDK's pydantic models declare camelCase aliases (fieldType, vaultId);
        # attribute access stays snake_case (field.field_type, params.vault_id).
        fields = [
            ItemField(id=key, title=key, fieldType=ItemFieldType.CONCEALED, value=str(value))
            for key, value in data.items()
        ]

        item_id = await self._find_item_id(client, vault_id, item_name)
        if item_id is None:
            await client.items.create(
                ItemCreateParams(
                    title=item_name,
                    category=ItemCategory.SECURENOTE,
                    vaultId=vault_id,
                    fields=fields,
                )
            )
            return

        existing = await client.items.get(vault_id, item_id)
        if existing.category != ItemCategory.SECURENOTE:
            raise ValueError(
                f"1Password item {item_name!r} is a {existing.category} item, not a "
                "Hegemony-managed Secure Note; refusing to replace its fields. "
                "Update it in 1Password directly."
            )
        existing.fields = fields
        await client.items.put(existing)

    def write(self, path: str, data: Mapping[str, Any]) -> None:
        """Create or update the 1Password item at ``path`` with ``data`` as its fields.

        A new item is created as a Secure Note whose concealed custom fields are the
        ``data`` keys; an existing Secure Note has its fields replaced with ``data``
        (replace, not merge — the host implements key deletion by writing the reduced
        mapping). Items of any other category (LOGIN, ...) are refused: replacing
        their fields would destroy built-in username/password fields of an item
        Hegemony does not manage.

        Args:
            path: Reference path in ``"<vault>/<item>"`` form.
            data: Mapping of field title to value.

        Raises:
            ValueError: If ``path`` is malformed, the vault cannot be found, or the
                existing item is not a Secure Note.
        """
        vault, item_name = _split_path(path)
        client = self._ensure_client()
        _runner().run(self._write(client, vault, item_name, data))

    async def _delete(self, client: Any, vault: str, item_name: str) -> None:
        vault_id = await self._find_vault_id(client, vault)
        if vault_id is None:
            return
        item_id = await self._find_item_id(client, vault_id, item_name)
        if item_id is None:
            return
        await client.items.delete(vault_id, item_id)

    def delete(self, path: str) -> None:
        """Delete the 1Password item at ``path``; a missing vault or item is not an error.

        Args:
            path: Reference path in ``"<vault>/<item>"`` form.

        Raises:
            ValueError: If ``path`` is malformed.
        """
        vault, item_name = _split_path(path)
        client = self._ensure_client()
        _runner().run(self._delete(client, vault, item_name))

    async def _list(self, client: Any, path: str) -> builtins.list[str]:
        normalized = path.strip("/")
        if not normalized:
            vault_overviews = await client.vaults.list()
            return [f"{overview.title}/" for overview in vault_overviews]
        if "/" in normalized:
            return []

        vault_id = await self._find_vault_id(client, normalized)
        if vault_id is None:
            return []
        item_overviews = await client.items.list(vault_id)
        return [overview.title for overview in item_overviews]

    # builtins.list because the method name shadows the builtin in class scope.
    def list(self, path: str = "") -> builtins.list[str]:
        """List vaults (empty ``path``) or the item titles inside one vault.

        Args:
            path: ``""`` to list vault titles (returned with a trailing ``"/"``), or a
                vault title/id to list its item titles (leaf entries).

        Returns:
            The immediate children under ``path``; ``[]`` for an unknown vault or for
            anything deeper (items are leaves).
        """
        client = self._ensure_client()
        return _runner().run(self._list(client, path))

    def test(self) -> None:
        """Verify connectivity and authentication against 1Password.

        Performs a lightweight check: authenticates (if needed) and lists vaults
        reachable by the configured service account token.

        Raises:
            Exception: If the connectivity/authentication check fails.
        """
        client = self._ensure_client()
        _runner().run(client.vaults.list())
