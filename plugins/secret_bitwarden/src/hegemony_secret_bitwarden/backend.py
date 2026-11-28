# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Vaultwarden secret backend: organization collections as folders, items as secrets.

A reference path is ``"<collection>/<item>"``. Both parts are names, or ids when a name
is not unique. Collection names may themselves contain ``/`` (that is how Bitwarden
nests collections), so a path can split in more than one place; see
:func:`split_candidates`.

The backend works on a decrypted snapshot of one organization, rebuilt from a full
vault sync. Reads reuse a snapshot for ``cache_ttl_seconds``; writes and deletes always
start from a fresh one.
"""

from __future__ import annotations

import builtins
import logging
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric import rsa

from .client import VaultwardenClient, VaultwardenError, get_field
from .crypto import (
    BitwardenCryptoError,
    SymmetricKey,
    decrypt,
    decrypt_text,
    derive_master_key,
    encrypt_text,
    load_private_key,
    rsa_decrypt,
    stretch_master_key,
)

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_CACHE_TTL_SECONDS = 30

_CIPHER_LOGIN = 1
_CIPHER_SECURE_NOTE = 2
_CIPHER_SSH_KEY = 5
_CIPHER_TYPE_NAMES = {
    1: "Login",
    2: "Secure Note",
    3: "Card",
    4: "Identity",
    5: "SSH key",
}

_FIELD_HIDDEN = 1
_FIELD_LINKED = 3

_MEMBERSHIP_CONFIRMED = 2

_PATH_FORMAT = "Vaultwarden secret path must be '<collection>/<item>'"


def _normalize_int(name: str, value: Any, default: int, minimum: int) -> int:
    """Coerce a configured integer, or raise a clear error."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return default
    try:
        if isinstance(value, bool):
            raise ValueError
        number = int(str(value).strip())
    except ValueError:
        raise ValueError(f"Vaultwarden backend config has a non-numeric {name}") from None
    if number < minimum:
        raise ValueError(f"Vaultwarden backend config {name} must be at least {minimum}")
    return number


def _required(config: Mapping[str, Any], name: str) -> str:
    value = config.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Vaultwarden backend config is missing {name}")
    return value


@dataclass(frozen=True, repr=False)
class VaultwardenConfig:
    """Configuration for a Vaultwarden backend.

    Attributes:
        server_url: Base address of the server (e.g. "https://vault.example.com")
        client_id: Personal API key id of the service user ("user.<uuid>")
        client_secret: Personal API key secret of the service user
        master_password: Master password of the service user; decrypts the vault
        organization: Name or id of the organization whose collections are used
        cache_ttl_seconds: How long reads reuse a downloaded vault (0 disables)
        timeout: Per-request timeout in seconds
        ca_cert_file: Optional path to a CA certificate bundle
        verify_ssl: Whether to verify TLS certificates
        allow_insecure_http: Opt in to a plain-HTTP address
    """

    server_url: str
    client_id: str
    client_secret: str
    master_password: str
    organization: str
    cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS
    timeout: int = DEFAULT_TIMEOUT_SECONDS
    ca_cert_file: str | None = None
    verify_ssl: bool = True
    allow_insecure_http: bool = False

    def __repr__(self) -> str:
        # The dataclass default would print the API key secret and the master password.
        return f"VaultwardenConfig(server_url={self.server_url!r}, <credentials redacted>)"

    @classmethod
    def from_dict(cls, config: Mapping[str, Any]) -> VaultwardenConfig:
        """Create a :class:`VaultwardenConfig` from a dictionary resolved by the host.

        Raises:
            ValueError: If a required value is missing or a value is malformed.
        """
        server_url = _required(config, "server_url").strip().rstrip("/")
        allow_insecure_http = bool(config.get("allow_insecure_http", False))
        parts = urlsplit(server_url)
        if (
            parts.scheme not in ("https", "http")
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
        ):
            raise ValueError(
                "Vaultwarden backend config server_url must be an http(s) address "
                "without credentials, query or fragment, e.g. https://vault.example.com"
            )
        if parts.scheme == "http" and not allow_insecure_http:
            raise ValueError(
                "Vaultwarden backend config server_url is not HTTPS. Use an https:// "
                "address, or set allow_insecure_http to true to accept the risk of "
                "sending the API key and access token in cleartext."
            )
        client_id = _required(config, "client_id").strip()
        if not client_id.startswith("user."):
            raise ValueError(
                "Vaultwarden backend config client_id must be a personal API key id "
                "('user.<id>'). An organization API key cannot decrypt vault items."
            )
        ca_cert_file = config.get("ca_cert_file")
        return cls(
            server_url=server_url,
            client_id=client_id,
            client_secret=_required(config, "client_secret").strip(),
            # Not stripped: surrounding whitespace is a legal part of a master password.
            master_password=_required(config, "master_password"),
            organization=_required(config, "organization").strip(),
            cache_ttl_seconds=_normalize_int(
                "cache_ttl_seconds", config.get("cache_ttl_seconds"), DEFAULT_CACHE_TTL_SECONDS, 0
            ),
            timeout=_normalize_int("timeout", config.get("timeout"), DEFAULT_TIMEOUT_SECONDS, 1),
            ca_cert_file=ca_cert_file if isinstance(ca_cert_file, str) and ca_cert_file else None,
            verify_ssl=bool(config.get("verify_ssl", True)),
            allow_insecure_http=allow_insecure_http,
        )


def split_candidates(path: str, collections: Mapping[str, str]) -> list[tuple[str, str]]:
    """Every way ``path`` splits into a known collection and an item reference.

    Args:
        path: Reference path in ``"<collection>/<item>"`` form.
        collections: Mapping of collection id to (decrypted) collection name.

    Returns:
        ``(collection_id, item)`` pairs, longest collection prefix first. A collection
        matches by name or by id. Empty when no collection is a prefix of ``path``.

    Raises:
        ValueError: If ``path`` is not two non-empty parts separated by ``/``.
    """
    head, separator, tail = path.partition("/")
    if not separator or not head or not tail:
        raise ValueError(f"{_PATH_FORMAT}, got: {path!r}")
    found: dict[tuple[str, str], int] = {}
    for collection_id, name in collections.items():
        for prefix in (name, collection_id):
            if prefix and len(path) > len(prefix) + 1 and path.startswith(prefix + "/"):
                pair = (collection_id, path[len(prefix) + 1 :])
                found[pair] = max(found.get(pair, 0), len(prefix))
    return sorted(found, key=lambda pair: (-found[pair], pair))


@dataclass(frozen=True, repr=False)
class _Item:
    id: str
    name: str
    type: int
    collection_ids: frozenset[str]
    key: SymmetricKey
    raw: Mapping[str, Any]


@dataclass(frozen=True, repr=False)
class _Snapshot:
    fetched_at: float
    user_id: str
    organization_id: str
    organization_key: SymmetricKey
    collections: Mapping[str, str]
    items: tuple[_Item, ...]


@dataclass(frozen=True, repr=False)
class _Unlocked:
    """Decrypted account keys, with what they were derived from (to detect a change)."""

    fingerprint: tuple[Any, ...]
    user_key: SymmetricKey
    private_key: rsa.RSAPrivateKey


class VaultwardenBackend:
    """Secrets backend for a Vaultwarden (or self-hosted Bitwarden) organization.

    Example:
        config = VaultwardenConfig.from_dict({
            "server_url": "https://vault.example.com",
            "client_id": "user.00000000-0000-0000-0000-000000000000",
            "client_secret": "...",
            "master_password": "...",
            "organization": "Acme",
        })
        backend = VaultwardenBackend(config)

        # Read a secret
        data = backend.read("Network/Core Switch")
        password = data["password"]
    """

    def __init__(
        self, config: VaultwardenConfig, *, transport: httpx.BaseTransport | None = None
    ) -> None:
        """Initialize the backend. Nothing is sent until the first call.

        Args:
            config: Vaultwarden backend configuration
            transport: Optional httpx transport, for tests
        """
        self._config = config
        verify: bool | str = config.verify_ssl
        if config.verify_ssl and config.ca_cert_file:
            verify = config.ca_cert_file
        if config.server_url.startswith("http://"):
            logger.warning(
                "Secret backend address %s is not HTTPS and allow_insecure_http is set: "
                "the API key and access token cross the network in cleartext",
                config.server_url,
            )
        self._client = VaultwardenClient(
            server_url=config.server_url,
            client_id=config.client_id,
            client_secret=config.client_secret,
            timeout=config.timeout,
            verify=verify,
            transport=transport,
        )
        # Reentrant: write/delete hold it across their own snapshot refresh.
        self._lock = threading.RLock()
        self._snapshot: _Snapshot | None = None
        self._unlocked: _Unlocked | None = None

    # --- snapshot ---------------------------------------------------------------

    def _unlock(self, profile: Any) -> _Unlocked:
        """Derive the account keys, reusing them while the server's key data is unchanged.

        The key derivation is deliberately slow (hundreds of thousands of PBKDF2 rounds,
        or tens of MiB of Argon2id memory), so it must not run on every sync.
        """
        login = self._client.login()
        salt = login.salt or get_field(profile, "email")
        if not isinstance(salt, str) or not salt:
            raise VaultwardenError("Vaultwarden did not report the account email (the KDF salt)")
        fingerprint = (
            login.user_key,
            login.private_key,
            login.kdf_type,
            login.kdf_iterations,
            login.kdf_memory,
            login.kdf_parallelism,
            salt,
        )
        if self._unlocked is not None and self._unlocked.fingerprint == fingerprint:
            return self._unlocked
        if not login.user_key or not login.private_key:
            raise VaultwardenError(
                "The Vaultwarden account has no master-password-protected key or no "
                "key pair; log in to the web vault once with this user to create them"
            )
        master_key = derive_master_key(
            self._config.master_password,
            salt,
            kdf_type=login.kdf_type,
            iterations=login.kdf_iterations,
            memory_mib=login.kdf_memory,
            parallelism=login.kdf_parallelism,
        )
        try:
            user_key = SymmetricKey.from_bytes(
                decrypt(login.user_key, stretch_master_key(master_key))
            )
        except BitwardenCryptoError as exc:
            raise BitwardenCryptoError(
                f"Could not unlock the Vaultwarden account (wrong master password?): {exc}"
            ) from None
        private_key = load_private_key(decrypt(login.private_key, user_key))
        self._unlocked = _Unlocked(fingerprint, user_key, private_key)
        return self._unlocked

    def _organization(self, profile: Any) -> Mapping[str, Any]:
        wanted = self._config.organization
        organizations = get_field(profile, "organizations")
        matches = [
            org
            for org in (organizations if isinstance(organizations, list) else [])
            if isinstance(org, Mapping) and wanted in (get_field(org, "id"), get_field(org, "name"))
        ]
        if not matches:
            raise ValueError(
                f"Vaultwarden organization {wanted!r} not found: the user is not a "
                "member of an organization with that name or id"
            )
        if len(matches) > 1:
            raise ValueError(
                f"Vaultwarden organization name {wanted!r} is ambiguous "
                f"({len(matches)} organizations); use the organization id instead"
            )
        organization = matches[0]
        status = get_field(organization, "status")
        if not get_field(organization, "key") or (
            status is not None and status != _MEMBERSHIP_CONFIRMED
        ):
            raise ValueError(
                f"The user's membership of Vaultwarden organization {wanted!r} is not "
                "confirmed yet; an organization admin must confirm it"
            )
        return organization

    def _refresh(self) -> _Snapshot:
        """Sync the vault and decrypt the organization's collection and item names."""
        with self._lock:
            sync = self._client.sync()
            profile = get_field(sync, "profile")
            user_id = get_field(profile, "id")
            if not isinstance(user_id, str) or not user_id:
                raise VaultwardenError("Vaultwarden sync returned no user profile")
            unlocked = self._unlock(profile)
            organization = self._organization(profile)
            organization_id = str(get_field(organization, "id"))
            organization_key = SymmetricKey.from_bytes(
                rsa_decrypt(get_field(organization, "key"), unlocked.private_key)
            )

            collections: dict[str, str] = {}
            for collection in get_field(sync, "collections") or []:
                collection_id = get_field(collection, "id")
                if get_field(collection, "organizationId") != organization_id or not isinstance(
                    collection_id, str
                ):
                    continue
                try:
                    collections[collection_id] = decrypt_text(
                        get_field(collection, "name"), organization_key
                    )
                except BitwardenCryptoError as exc:
                    # One damaged entry must not take the whole backend down.
                    logger.warning(
                        "Skipping undecryptable Vaultwarden collection %s: %s", collection_id, exc
                    )

            items: list[_Item] = []
            for cipher in get_field(sync, "ciphers") or []:
                cipher_id = get_field(cipher, "id")
                if (
                    get_field(cipher, "organizationId") != organization_id
                    or not isinstance(cipher_id, str)
                    # Items in the trash are gone as far as secret resolution goes.
                    or get_field(cipher, "deletedDate")
                ):
                    continue
                try:
                    item_key = get_field(cipher, "key")
                    key = (
                        SymmetricKey.from_bytes(decrypt(item_key, organization_key))
                        if item_key
                        else organization_key
                    )
                    name = decrypt_text(get_field(cipher, "name"), key)
                except BitwardenCryptoError as exc:
                    logger.warning("Skipping undecryptable Vaultwarden item %s: %s", cipher_id, exc)
                    continue
                collection_ids = get_field(cipher, "collectionIds")
                cipher_type = get_field(cipher, "type")
                items.append(
                    _Item(
                        id=cipher_id,
                        name=name,
                        type=cipher_type if isinstance(cipher_type, int) else 0,
                        collection_ids=frozenset(
                            c
                            for c in (collection_ids if isinstance(collection_ids, list) else [])
                            if isinstance(c, str)
                        ),
                        key=key,
                        raw=cipher,
                    )
                )

            self._snapshot = _Snapshot(
                fetched_at=time.monotonic(),
                user_id=user_id,
                organization_id=organization_id,
                organization_key=organization_key,
                collections=collections,
                items=tuple(items),
            )
            return self._snapshot

    def _current(self) -> tuple[_Snapshot, bool]:
        """A snapshot no older than the cache TTL, and whether it was just fetched."""
        with self._lock:
            snapshot = self._snapshot
            if (
                snapshot is not None
                and time.monotonic() - snapshot.fetched_at < self._config.cache_ttl_seconds
            ):
                return snapshot, False
            return self._refresh(), True

    # --- lookup -----------------------------------------------------------------

    @staticmethod
    def _find(snapshot: _Snapshot, path: str) -> _Item | None:
        """The one live item ``path`` names, or ``None``.

        Raises:
            ValueError: If ``path`` is malformed, or names more than one item
                (silently picking one could read or overwrite the wrong secret).
        """
        matches: dict[str, _Item] = {}
        for collection_id, reference in split_candidates(path, snapshot.collections):
            for item in snapshot.items:
                if collection_id in item.collection_ids and reference in (item.name, item.id):
                    matches[item.id] = item
        if len(matches) > 1:
            raise ValueError(
                f"Vaultwarden secret path {path!r} is ambiguous ({len(matches)} items "
                "match); use the item id instead of its name"
            )
        return next(iter(matches.values()), None)

    @staticmethod
    def _fields(item: _Item) -> dict[str, str]:
        """Decrypt one item into the mapping a secret reference's key is looked up in."""

        def text(value: Any) -> str | None:
            return decrypt_text(value, item.key) if isinstance(value, str) and value else None

        raw = item.raw
        builtin: dict[str, str | None] = {}
        if item.type == _CIPHER_LOGIN:
            login = get_field(raw, "login")
            builtin["username"] = text(get_field(login, "username"))
            builtin["password"] = text(get_field(login, "password"))
            # login.totp is the one-time-password *seed*; it is never exposed.
        elif item.type == _CIPHER_SSH_KEY:
            ssh_key = get_field(raw, "sshKey")
            builtin["private_key"] = text(get_field(ssh_key, "privateKey"))
            builtin["public_key"] = text(get_field(ssh_key, "publicKey"))
            builtin["fingerprint"] = text(get_field(ssh_key, "keyFingerprint"))
        builtin["notes"] = text(get_field(raw, "notes"))

        custom: dict[str, str] = {}
        fields = get_field(raw, "fields")
        for field in fields if isinstance(fields, list) else []:
            if get_field(field, "type") == _FIELD_LINKED:
                # A linked field points at a built-in field; it holds no value.
                continue
            name = text(get_field(field, "name"))
            value = text(get_field(field, "value"))
            # First one wins when a name repeats, as the item shows them in order.
            if name and value is not None and name not in custom:
                custom[name] = value

        # Custom fields win over built-ins: what Hegemony writes (always custom
        # fields) reads back unchanged, whatever the item also carries.
        result = {name: value for name, value in builtin.items() if value is not None}
        result.update(custom)
        return result

    # --- SecretBackend ----------------------------------------------------------

    def read(self, path: str) -> dict[str, str] | None:
        """Read a Vaultwarden item's fields.

        Args:
            path: Reference path in ``"<collection>/<item>"`` form.

        Returns:
            Mapping of field name to value (``username``, ``password`` and ``notes``
            where the item has them, plus every custom field), or ``None`` if no
            collection and item match.

        Raises:
            ValueError: If ``path`` is malformed or ambiguous.
        """
        snapshot, fresh = self._current()
        item = self._find(snapshot, path)
        if item is None and not fresh:
            # Not in the cached copy: it may have been created since.
            item = self._find(self._refresh(), path)
        return self._fields(item) if item is not None else None

    def write(self, path: str, data: Mapping[str, Any]) -> None:
        """Create or update the Vaultwarden item at ``path`` with ``data`` as its fields.

        A new item is created as a Secure Note whose hidden custom fields are the
        ``data`` keys; an existing Secure Note has its custom fields replaced with
        ``data`` (replace, not merge — the host implements key deletion by writing the
        reduced mapping). Items of any other type (Login, ...) are refused: Hegemony
        does not manage them, and their secrets live in built-in fields this method
        does not write.

        Args:
            path: Reference path in ``"<collection>/<item>"`` form.
            data: Mapping of field name to value.

        Raises:
            ValueError: If ``path`` is malformed or ambiguous, no collection matches,
                a key is not a non-empty string, or the existing item is not a
                Secure Note.
        """
        for name in data:
            if not isinstance(name, str) or not name:
                raise ValueError("Vaultwarden secret keys must be non-empty strings")
        with self._lock:
            snapshot = self._refresh()
            item = self._find(snapshot, path)
            try:
                if item is None:
                    self._create(snapshot, path, data)
                else:
                    self._update(snapshot, item, data)
            finally:
                self._snapshot = None

    def _create(self, snapshot: _Snapshot, path: str, data: Mapping[str, Any]) -> None:
        candidates = split_candidates(path, snapshot.collections)
        if not candidates:
            raise ValueError(
                f"Vaultwarden collection not found for path {path!r}: no collection "
                "the user can see is a prefix of it"
            )
        # Longest collection name first: the most specific collection gets the item.
        collection_id, name = candidates[0]
        key = snapshot.organization_key
        self._client.create_cipher(
            {
                "type": _CIPHER_SECURE_NOTE,
                "organizationId": snapshot.organization_id,
                "folderId": None,
                "favorite": False,
                "reprompt": 0,
                "key": None,
                "name": encrypt_text(name, key),
                "notes": None,
                "secureNote": {"type": 0},
                "fields": self._encrypt_fields(data, key),
                "encryptedFor": snapshot.user_id,
            },
            [collection_id],
        )

    def _update(self, snapshot: _Snapshot, item: _Item, data: Mapping[str, Any]) -> None:
        if item.type != _CIPHER_SECURE_NOTE:
            kind = _CIPHER_TYPE_NAMES.get(item.type, f"type {item.type}")
            raise ValueError(
                f"Vaultwarden item {item.name!r} is a {kind} item, not a "
                "Hegemony-managed Secure Note; refusing to replace its fields. "
                "Update it in Vaultwarden directly."
            )
        raw = item.raw
        self._client.update_cipher(
            item.id,
            {
                "type": _CIPHER_SECURE_NOTE,
                "organizationId": snapshot.organization_id,
                "folderId": get_field(raw, "folderId"),
                "favorite": bool(get_field(raw, "favorite")),
                "reprompt": get_field(raw, "reprompt") or 0,
                # Everything but the custom fields is sent back as it came.
                "key": get_field(raw, "key"),
                "name": get_field(raw, "name"),
                "notes": get_field(raw, "notes"),
                "secureNote": get_field(raw, "secureNote") or {"type": 0},
                "passwordHistory": get_field(raw, "passwordHistory"),
                "fields": self._encrypt_fields(data, item.key),
                "encryptedFor": snapshot.user_id,
                # Lets the server refuse the update if the item changed after the sync.
                "lastKnownRevisionDate": get_field(raw, "revisionDate"),
            },
        )

    @staticmethod
    def _encrypt_fields(data: Mapping[str, Any], key: SymmetricKey) -> builtins.list[dict]:
        return [
            {
                "type": _FIELD_HIDDEN,
                "name": encrypt_text(name, key),
                "value": encrypt_text(str(value), key),
                "linkedId": None,
            }
            for name, value in data.items()
        ]

    def delete(self, path: str) -> None:
        """Move the Vaultwarden item at ``path`` to the trash; a missing one is not an error.

        The item stays restorable from the organization's trash until the server
        purges it.

        Args:
            path: Reference path in ``"<collection>/<item>"`` form.

        Raises:
            ValueError: If ``path`` is malformed or ambiguous.
        """
        with self._lock:
            item = self._find(self._refresh(), path)
            if item is None:
                return
            try:
                self._client.trash_cipher(item.id)
            except VaultwardenError as exc:
                # Another caller can remove the item after the successful lookup.
                if exc.status_code != 404:
                    raise
            finally:
                self._snapshot = None

    # builtins.list because the method name shadows the builtin in class scope.
    def list(self, path: str = "") -> builtins.list[str]:
        """List what sits directly under ``path`` in the collection tree.

        Collection names are treated as ``/``-separated paths, as the Bitwarden clients
        show them.

        Args:
            path: ``""`` for the top level, or a collection name or name prefix.

        Returns:
            Sub-collection segments (with a trailing ``"/"``) followed by the item
            names of the collection named exactly ``path``; ``[]`` for anything else.
        """
        snapshot, _ = self._current()
        normalized = path.strip("/")
        prefix = f"{normalized}/" if normalized else ""
        containers: set[str] = set()
        here: set[str] = set()
        for collection_id, name in snapshot.collections.items():
            if normalized and normalized in (name, collection_id):
                here.add(collection_id)
            if name.startswith(prefix) and name != normalized:
                segment = name[len(prefix) :].split("/", 1)[0]
                if segment:
                    containers.add(f"{segment}/")
        leaves = {item.name for item in snapshot.items if item.name and item.collection_ids & here}
        return sorted(containers) + sorted(leaves)

    def test(self) -> None:
        """Verify connectivity, the API key, the master password and the organization.

        Logs in afresh, syncs, and decrypts the organization key, which fails unless
        every configured credential is right.

        Raises:
            Exception: If the connectivity/authentication check fails.
        """
        with self._lock:
            self._client.login(force=True)
            self._refresh()
