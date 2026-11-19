# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Exercise the Vaultwarden backend against a real, throwaway Vaultwarden server.

The unit tests mock HTTP, so they cannot notice the server changing its API. This
script can: it registers a fresh account on the server, gives it an organization with
collections and items the way a Bitwarden client would, and then runs every backend
operation against it. Run it before releasing a change to the plugin and when a new
Vaultwarden version comes out:

    docker run --rm -d --name vaultwarden-check -p 127.0.0.1:8087:80 \
        -e I_REALLY_WANT_VOLATILE_STORAGE=true -e LOGIN_RATELIMIT_MAX_BURST=1000 \
        vaultwarden/server:latest
    uv run python scripts/live_check_vaultwarden.py http://127.0.0.1:8087
    docker stop vaultwarden-check

Only ever point it at a server you can throw away: it creates accounts and data, and
needs open sign-ups. Every credential it uses is random and generated on the spot.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import secrets
import sys
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from hegemony_secret_bitwarden import VaultwardenBackend, VaultwardenConfig
from hegemony_secret_bitwarden.client import VaultwardenError
from hegemony_secret_bitwarden.crypto import (
    KDF_ARGON2ID,
    KDF_PBKDF2_SHA256,
    SymmetricKey,
    derive_master_key,
    encrypt,
    encrypt_text,
    stretch_master_key,
)

_DEVICE = {
    "deviceType": "21",
    "deviceIdentifier": "00000000-0000-4000-8000-000000000001",
    "deviceName": "live-check",
}


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class Provisioner:
    """Plays the part of a Bitwarden client setting an account up."""

    def __init__(self, server_url: str, kdf: dict[str, Any]) -> None:
        self.http = httpx.Client(
            base_url=server_url,
            timeout=30,
            trust_env=False,
            headers={"Accept": "application/json"},
        )
        self.kdf = kdf
        self.email = f"check-{secrets.token_hex(6)}@example.com"
        self.password = secrets.token_urlsafe(18)
        master_key = derive_master_key(
            self.password,
            self.email,
            kdf_type=kdf["kdf"],
            iterations=kdf["kdfIterations"],
            memory_mib=kdf.get("kdfMemory"),
            parallelism=kdf.get("kdfParallelism"),
        )
        self.password_hash = _b64(
            hashlib.pbkdf2_hmac("sha256", master_key, self.password.encode(), 1, 32)
        )
        self.user_key = SymmetricKey.generate()
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.protected_user_key = encrypt(self.user_key.to_bytes(), stretch_master_key(master_key))
        self.headers: dict[str, str] = {}
        self.user_id = ""

    def _call(self, method: str, path: str, **kwargs: Any) -> Any:
        response = self.http.request(method, path, headers=self.headers, **kwargs)
        if not response.is_success:
            raise SystemExit(f"{method} {path} failed ({response.status_code}): {response.text}")
        return response.json() if response.content else None

    def register(self) -> None:
        public_der = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_der = self.private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        # Without mail configured, the server hands the verification token straight back.
        token = self._call(
            "POST",
            "/identity/accounts/register/send-verification-email",
            json={"email": self.email, "name": "Live Check"},
        )
        self._call(
            "POST",
            "/identity/accounts/register/finish",
            json={
                "email": self.email,
                "emailVerificationToken": token,
                "masterPasswordHash": self.password_hash,
                "key": self.protected_user_key,
                **self.kdf,
                "keys": {
                    "publicKey": _b64(public_der),
                    "encryptedPrivateKey": encrypt(private_der, self.user_key),
                },
            },
        )
        token = self._call(
            "POST",
            "/identity/connect/token",
            data={
                "grant_type": "password",
                "username": self.email,
                "password": self.password_hash,
                "scope": "api offline_access",
                "client_id": "web",
                **_DEVICE,
            },
        )
        self.headers = {"Authorization": f"Bearer {token['access_token']}"}
        self.user_id = self._call("GET", "/api/accounts/profile")["id"]

    def api_key(self) -> tuple[str, str]:
        body = self._call(
            "POST", "/api/accounts/api-key", json={"masterPasswordHash": self.password_hash}
        )
        return f"user.{self.user_id}", body["apiKey"]

    def organization(self, name: str, first_collection: str) -> tuple[str, SymmetricKey, str]:
        key = SymmetricKey.generate()
        body = self._call(
            "POST",
            "/api/organizations",
            json={
                "name": name,
                "billingEmail": self.email,
                "collectionName": encrypt_text(first_collection, key),
                "key": self._wrap_for(key, self),
                "planType": 0,
            },
        )
        collections = self._call("GET", f"/api/organizations/{body['id']}/collections")
        return body["id"], key, collections["data"][0]["id"]

    def _wrap_for(self, key: SymmetricKey, member: Provisioner) -> str:
        wrapped = member.private_key.public_key().encrypt(
            key.to_bytes(),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None),
        )
        return f"4.{_b64(wrapped)}"

    def invite(self, organization_id: str, member: Provisioner, collection_id: str) -> str:
        """Invite a registered user with read-only access to one collection."""
        self._call(
            "POST",
            f"/api/organizations/{organization_id}/users/invite",
            json={
                "emails": [member.email],
                "type": 2,
                "groups": [],
                "collections": [
                    {"id": collection_id, "readOnly": True, "hidePasswords": False, "manage": False}
                ],
            },
        )
        members = self._call("GET", f"/api/organizations/{organization_id}/users")["data"]
        return next(m["id"] for m in members if m["email"] == member.email)

    def confirm(
        self, organization_id: str, key: SymmetricKey, member: Provisioner, member_id: str
    ) -> None:
        self._call(
            "POST",
            f"/api/organizations/{organization_id}/users/{member_id}/confirm",
            json={"key": self._wrap_for(key, member)},
        )

    def collection(self, organization_id: str, key: SymmetricKey, name: str) -> str:
        body = self._call(
            "POST",
            f"/api/organizations/{organization_id}/collections",
            json={"name": encrypt_text(name, key), "groups": [], "users": [], "externalId": None},
        )
        return body["id"]

    def login_item(
        self,
        organization_id: str,
        key: SymmetricKey,
        collection_id: str,
        name: str,
        *,
        own_key: bool,
    ) -> str:
        """Create a Login item; with ``own_key`` it gets an item key, as new clients do."""
        item_key = SymmetricKey.generate() if own_key else key
        body = self._call(
            "POST",
            "/api/ciphers/create",
            json={
                "cipher": {
                    "type": 1,
                    "organizationId": organization_id,
                    "key": encrypt(item_key.to_bytes(), key) if own_key else None,
                    "name": encrypt_text(name, item_key),
                    "notes": encrypt_text("rack 12", item_key),
                    "login": {
                        "username": encrypt_text("admin", item_key),
                        "password": encrypt_text("hunter2", item_key),
                        "totp": encrypt_text("JBSWY3DPEHPK3PXP", item_key),
                    },
                    "fields": [
                        {
                            "type": 0,
                            "name": encrypt_text("enable", item_key),
                            "value": encrypt_text("hunter3", item_key),
                        }
                    ],
                    "encryptedFor": self.user_id,
                },
                "collectionIds": [collection_id],
            },
        )
        return body["id"]


def _config(server_url: str, user: Provisioner) -> dict[str, Any]:
    client_id, client_secret = user.api_key()
    return {
        "server_url": server_url,
        "client_id": client_id,
        "client_secret": client_secret,
        "master_password": user.password,
        "organization": "Acme",
        "allow_insecure_http": server_url.startswith("http://"),
    }


def check_member(
    server_url: str, owner: Provisioner, organization_id: str, key: SymmetricKey, network: str
) -> None:
    """The recommended setup: a service user that sees one collection, read-only."""
    member = Provisioner(server_url, owner.kdf)
    member.register()
    member_id = owner.invite(organization_id, member, network)
    backend = VaultwardenBackend(VaultwardenConfig.from_dict(_config(server_url, member)))
    try:
        backend.test()
    except ValueError as exc:
        assert "Acme" in str(exc)
    else:
        raise AssertionError("an unconfirmed membership must fail the test")

    owner.confirm(organization_id, key, member, member_id)
    backend.test()
    assert (backend.read("Network/Core Switch") or {}).get("password") == "hunter2"
    # The nested collection was not shared with this user, so it does not exist for it.
    assert backend.list("") == ["Network/"]
    assert "Core/" not in backend.list("Network")
    assert backend.read("Network/Core/db") is None
    for attempt in (
        lambda: backend.write("Network/blocked", {"k": "v"}),
        lambda: backend.write("Network/db", {"k": "v"}),
        lambda: backend.delete("Network/db"),
    ):
        try:
            attempt()
        except VaultwardenError:
            pass
        else:
            raise AssertionError("a read-only member must not be able to change anything")
    assert backend.read("Network/blocked") is None
    assert backend.read("Network/db") == {"password": "second"}


def check(server_url: str, kdf: dict[str, Any]) -> None:
    user = Provisioner(server_url, kdf)
    user.register()
    organization_id, key, network = user.organization("Acme", "Network")
    user.collection(organization_id, key, "Network/Core")
    switch_id = user.login_item(organization_id, key, network, "Core Switch", own_key=False)
    user.login_item(organization_id, key, network, "Edge Router", own_key=True)

    config = _config(server_url, user)
    backend = VaultwardenBackend(VaultwardenConfig.from_dict(config))
    backend.test()

    expected = {"username": "admin", "password": "hunter2", "notes": "rack 12", "enable": "hunter3"}
    assert backend.read("Network/Core Switch") == expected
    assert backend.read(f"Network/{switch_id}") == expected
    assert backend.read("Network/Edge Router") == expected, "item with its own key"
    assert backend.read("Network/missing") is None
    assert backend.read("Nowhere/item") is None
    assert backend.list("") == ["Network/"]
    assert backend.list("Network") == ["Core/", "Core Switch", "Edge Router"]
    assert backend.list("Network/Core") == []

    # Create, read back, replace, and delete a Hegemony-managed secret, both in a
    # top-level and in a nested collection.
    for path in ("Network/db", "Network/Core/db"):
        backend.write(path, {"user": "svc", "password": "first", "port": 5432})
        assert backend.read(path) == {"user": "svc", "password": "first", "port": "5432"}
        backend.write(path, {"password": "second"})
        assert backend.read(path) == {"password": "second"}
    assert backend.list("Network/Core") == ["db"]
    assert "db" in backend.list("Network")

    try:
        backend.write("Network/Core Switch", {"password": "x"})
    except ValueError as exc:
        assert "Login" in str(exc)
    else:
        raise AssertionError("writing to a Login item must be refused")
    assert backend.read("Network/Core Switch") == expected

    backend.delete("Network/Core/db")
    backend.delete("Network/Core/db")  # a second delete is not an error
    assert backend.read("Network/Core/db") is None
    assert backend.read("Network/db") == {"password": "second"}

    # A second backend instance starts cold: fresh login, fresh key derivation.
    fresh = VaultwardenBackend(VaultwardenConfig.from_dict(config))
    assert fresh.read("Network/db") == {"password": "second"}

    wrong = VaultwardenBackend(VaultwardenConfig.from_dict({**config, "master_password": "nope"}))
    try:
        wrong.test()
    except ValueError as exc:
        assert "master password" in str(exc)
    else:
        raise AssertionError("a wrong master password must fail the test")

    check_member(server_url, user, organization_id, key, network)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check the Vaultwarden backend against a throwaway server."
    )
    parser.add_argument("server_url", help="base URL of a throwaway Vaultwarden server")
    args = parser.parse_args()
    server_url = args.server_url.rstrip("/")
    version = httpx.get(f"{server_url}/api/config", trust_env=False, timeout=30).json()
    print(f"server speaks Bitwarden API version {version.get('version')}")
    for label, kdf in (
        ("PBKDF2", {"kdf": KDF_PBKDF2_SHA256, "kdfIterations": 600_000}),
        (
            "Argon2id",
            {"kdf": KDF_ARGON2ID, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4},
        ),
    ):
        check(server_url, kdf)
        print(f"ok: {label} account")


if __name__ == "__main__":
    try:
        main()
    except AssertionError:
        raise
    except httpx.HTTPError as exc:
        sys.exit(f"cannot reach the server: {exc}")
