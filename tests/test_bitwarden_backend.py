# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the Vaultwarden secret backend plugin: registration + behavior against a fake server.

``FakeVaultwarden`` is an in-memory stand-in served through ``httpx.MockTransport``. It
holds ciphertext only, as the real server does, so every test goes through the plugin's
real key derivation and encryption. Its keys are generated per test run.
"""

import base64
import json
import logging
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import hegemony_secret_bitwarden as plugin
from hegemony_secret_bitwarden import (
    VaultwardenBackend,
    VaultwardenConfig,
    backend as backend_module,
)
from hegemony_secret_bitwarden.backend import split_candidates
from hegemony_secret_bitwarden.client import VaultwardenError, device_identifier, get_field
from hegemony_secret_bitwarden.crypto import (
    BitwardenCryptoError,
    SymmetricKey,
    decrypt_text,
    derive_master_key,
    encrypt,
    encrypt_text,
    stretch_master_key,
)

EMAIL = "svc@example.com"
PASSWORD = "correct horse"
CLIENT_ID = "user.u-1"
CLIENT_SECRET = "sid"
ORG_ID = "org-1"
NETWORK = "col-network"
CORE = "col-core"

BASE_CONFIG: dict[str, Any] = {
    "server_url": "https://vault.example.com",
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    "master_password": PASSWORD,
    "organization": "Acme",
}


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeVaultwarden:
    """The endpoints the plugin calls, over an in-memory encrypted vault."""

    def __init__(self, rsa_key: rsa.RSAPrivateKey, *, pascal_case: bool = False) -> None:
        self.pascal_case = pascal_case
        self.kdf: dict[str, Any] = {"Kdf": 0, "KdfIterations": 1000}
        self.user_key = SymmetricKey.generate()
        self.org_key = SymmetricKey.generate()
        self.rsa_key = rsa_key
        master_key = derive_master_key(PASSWORD, EMAIL, kdf_type=0, iterations=1000)
        self.protected_user_key = encrypt(self.user_key.to_bytes(), stretch_master_key(master_key))
        self.protected_private_key = encrypt(
            rsa_key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            self.user_key,
        )
        self.organizations: list[dict[str, Any]] = [
            {"id": ORG_ID, "name": "Acme", "status": 2, "key": self.wrap(self.org_key)}
        ]
        self.collections: list[dict[str, Any]] = []
        self.ciphers: list[dict[str, Any]] = []
        self.add_collection(NETWORK, "Network")
        self.add_collection(CORE, "Network/Core")
        self.send_salt = True
        self.expires_in = 7200
        self.valid_tokens: set[str] = set()
        self.logins = 0
        self.syncs = 0
        self.requests: list[httpx.Request] = []
        self.fail: dict[tuple[str, str], httpx.Response] = {}
        self.next_id = 0

    # --- building the vault -----------------------------------------------------

    def wrap(self, key: SymmetricKey) -> str:
        wrapped = self.rsa_key.public_key().encrypt(
            key.to_bytes(),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None),
        )
        return "4." + base64.b64encode(wrapped).decode("ascii")

    def add_collection(self, collection_id: str, name: str, org_id: str = ORG_ID) -> None:
        self.collections.append(
            {
                "id": collection_id,
                "organizationId": org_id,
                "name": encrypt_text(name, self.org_key),
            }
        )

    def add_cipher(
        self,
        name: str,
        collections: list[str],
        *,
        cipher_type: int = 1,
        own_key: bool = False,
        fields: dict[str, str] | None = None,
        cipher_id: str | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        key = SymmetricKey.generate() if own_key else self.org_key
        self.next_id += 1
        cipher: dict[str, Any] = {
            "id": cipher_id or f"cipher-{self.next_id}",
            "organizationId": ORG_ID,
            "type": cipher_type,
            "key": encrypt(key.to_bytes(), self.org_key) if own_key else None,
            "name": encrypt_text(name, key),
            "notes": None,
            "collectionIds": collections,
            "deletedDate": None,
            "revisionDate": "2026-01-01T00:00:00Z",
            "fields": [
                {"type": 0, "name": encrypt_text(k, key), "value": encrypt_text(v, key)}
                for k, v in (fields or {}).items()
            ],
        }
        if cipher_type == 1:
            cipher["login"] = {
                "username": encrypt_text("admin", key),
                "password": encrypt_text("hunter2", key),
                "totp": encrypt_text("otp-seed", key),
            }
        cipher.update(extra)
        self.ciphers.append(cipher)
        return cipher

    def cipher_key(self, cipher: dict[str, Any]) -> SymmetricKey:
        from hegemony_secret_bitwarden.crypto import decrypt

        if cipher.get("key"):
            return SymmetricKey.from_bytes(decrypt(cipher["key"], self.org_key))
        return self.org_key

    def plain_fields(self, cipher: dict[str, Any]) -> dict[str, str]:
        key = self.cipher_key(cipher)
        return {
            decrypt_text(f["name"], key): decrypt_text(f["value"], key) for f in cipher["fields"]
        }

    def named(self, name: str) -> list[dict[str, Any]]:
        return [c for c in self.ciphers if decrypt_text(c["name"], self.cipher_key(c)) == name]

    # --- serving ----------------------------------------------------------------

    def _case(self, value: Any) -> Any:
        """Re-key a response in PascalCase, as Vaultwarden before 1.31 did."""
        if not self.pascal_case:
            return value
        if isinstance(value, dict):
            return {k[0].upper() + k[1:]: self._case(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._case(v) for v in value]
        return value

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        route = (request.method, request.url.path)
        if route in self.fail:
            return self.fail[route]
        if route == ("POST", "/identity/connect/token"):
            return self._token(request)
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if token not in self.valid_tokens:
            return httpx.Response(401, json={"message": "Invalid token"})
        if route == ("GET", "/api/sync"):
            self.syncs += 1
            return httpx.Response(200, json=self._case(self._sync()))
        if route == ("POST", "/api/ciphers/create"):
            body = json.loads(request.content)
            cipher = dict(body["cipher"])
            self.next_id += 1
            cipher.update(
                id=f"cipher-{self.next_id}",
                collectionIds=body["collectionIds"],
                deletedDate=None,
                revisionDate="2026-01-02T00:00:00Z",
            )
            self.ciphers.append(cipher)
            return httpx.Response(200, json=cipher)
        for cipher in self.ciphers:
            if route == ("PUT", f"/api/ciphers/{cipher['id']}"):
                body = json.loads(request.content)
                if body.get("lastKnownRevisionDate") != cipher["revisionDate"]:
                    return httpx.Response(400, json={"message": "The client copy is out-of-date"})
                cipher.update({k: v for k, v in body.items() if k != "lastKnownRevisionDate"})
                return httpx.Response(200, json=cipher)
            if route == ("PUT", f"/api/ciphers/{cipher['id']}/delete"):
                cipher["deletedDate"] = "2026-01-03T00:00:00Z"
                return httpx.Response(200)
        return httpx.Response(404, json={"message": "Cipher doesn't exist"})

    def _token(self, request: httpx.Request) -> httpx.Response:
        self.logins += 1
        form = dict(httpx.QueryParams(request.content.decode()))
        if form.get("client_id") != CLIENT_ID or form.get("client_secret") != CLIENT_SECRET:
            return httpx.Response(
                400,
                json={"message": "Incorrect client_secret", "errorModel": {"message": "bad key"}},
            )
        token = f"minted-token-{self.logins}"
        self.valid_tokens = {token}
        body: dict[str, Any] = {
            "access_token": token,
            "expires_in": self.expires_in,
            "token_type": "Bearer",
            "Key": self.protected_user_key,
            "PrivateKey": self.protected_private_key,
            **self.kdf,
            "scope": "api",
        }
        if self.send_salt:
            body["UserDecryptionOptions"] = {"MasterPasswordUnlock": {"Salt": EMAIL}}
        return httpx.Response(200, json=body)

    def _sync(self) -> dict[str, Any]:
        return {
            "profile": {"id": "u-1", "email": EMAIL, "organizations": self.organizations},
            "collections": self.collections,
            "ciphers": self.ciphers,
        }


@pytest.fixture
def server(rsa_key) -> FakeVaultwarden:
    fake = FakeVaultwarden(rsa_key)
    fake.add_cipher("Core Switch", [NETWORK], fields={"enable": "hunter3"})
    return fake


def make_backend(server: FakeVaultwarden, **overrides: Any) -> VaultwardenBackend:
    config = VaultwardenConfig.from_dict({**BASE_CONFIG, **overrides})
    return VaultwardenBackend(config, transport=server.transport())


def must_read(backend: VaultwardenBackend, path: str) -> dict[str, str]:
    data = backend.read(path)
    assert data is not None, path
    return data


# --- registration -----------------------------------------------------------------


class FakeRegistry:
    api_version = 1

    def __init__(self) -> None:
        self.types: dict[str, dict[str, Any]] = {}

    def register_backend_type(self, *, backend_type: str, **kwargs: Any) -> None:
        self.types[backend_type] = kwargs


def test_register_adds_the_vaultwarden_backend_type():
    from hegemony_secret_sdk import ListableSecretBackend, SecretBackendRegistry

    reg = FakeRegistry()
    assert isinstance(reg, SecretBackendRegistry)
    register(reg)
    assert set(reg.types) == {"vaultwarden"}
    entry = reg.types["vaultwarden"]
    assert entry["display_name"] and entry["description"]
    assert entry["factory"] is build_vaultwarden_backend
    backend = entry["factory"](dict(BASE_CONFIG))
    assert isinstance(backend, ListableSecretBackend)


def test_config_schema_marks_exactly_the_credentials_as_secret_refs():
    reg = FakeRegistry()
    register(reg)
    schema = reg.types["vaultwarden"]["config_schema"]
    assert schema["required"] == [
        "server_url",
        "client_id",
        "client_secret",
        "master_password",
        "organization",
    ]
    secret_refs = {name for name, prop in schema["properties"].items() if prop.get("x_secret_ref")}
    assert secret_refs == {"client_secret", "master_password"}
    # Every key the config parser reads is on the form, and the other way round.
    assert set(schema["properties"]) == set(VaultwardenConfig.__dataclass_fields__)


# --- config -----------------------------------------------------------------------


def test_config_defaults_and_normalization():
    config = VaultwardenConfig.from_dict(
        {**BASE_CONFIG, "server_url": " https://vault.example.com/ "}
    )
    assert config.server_url == "https://vault.example.com"
    assert (config.cache_ttl_seconds, config.timeout) == (30, 30)
    assert config.verify_ssl is True and config.ca_cert_file is None
    config = VaultwardenConfig.from_dict(
        {**BASE_CONFIG, "cache_ttl_seconds": "0", "timeout": 5, "master_password": " spaced "}
    )
    assert (config.cache_ttl_seconds, config.timeout) == (0, 5)
    assert config.master_password == " spaced "


def test_config_repr_does_not_print_credentials():
    text = repr(VaultwardenConfig.from_dict(BASE_CONFIG))
    assert text == (
        "VaultwardenConfig(server_url='https://vault.example.com', <credentials redacted>)"
    )
    assert PASSWORD not in text and CLIENT_SECRET not in text


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"server_url": ""}, "missing server_url"),
        ({"client_secret": None}, "missing client_secret"),
        ({"master_password": "   "}, "missing master_password"),
        ({"organization": 5}, "missing organization"),
        ({"server_url": "vault.example.com"}, "http\\(s\\) address"),
        ({"server_url": "ftp://vault.example.com"}, "http\\(s\\) address"),
        ({"server_url": "https://alice:pw@vault.example.com"}, "without credentials"),
        ({"server_url": "https://vault.example.com/?a=b"}, "without credentials"),
        ({"server_url": "http://vault.example.com"}, "not HTTPS"),
        ({"client_id": "organization.o-1"}, "personal API key"),
        ({"timeout": "soon"}, "non-numeric timeout"),
        ({"timeout": 0}, "timeout must be at least 1"),
        ({"cache_ttl_seconds": -1}, "cache_ttl_seconds must be at least 0"),
        ({"cache_ttl_seconds": True}, "non-numeric cache_ttl_seconds"),
    ],
)
def test_config_rejects_bad_values(overrides, message):
    with pytest.raises(ValueError, match=message):
        VaultwardenConfig.from_dict({**BASE_CONFIG, **overrides})


def test_plain_http_needs_the_explicit_opt_in(server, caplog):
    with caplog.at_level(logging.WARNING):
        backend = make_backend(server, server_url="http://vaultwarden:80", allow_insecure_http=True)
    assert "not HTTPS" in caplog.text
    assert backend.read("Network/Core Switch") is not None


def test_ca_bundle_and_verify_flags_reach_the_http_client(monkeypatch):
    seen: list[Any] = []
    real = httpx.Client

    def spy(**kwargs: Any) -> httpx.Client:
        seen.append(kwargs["verify"])
        kwargs["verify"] = True
        return real(**kwargs)

    monkeypatch.setattr("hegemony_secret_bitwarden.client.httpx.Client", spy)
    for overrides in (
        {},
        {"ca_cert_file": "/etc/ssl/ca.pem"},
        {"verify_ssl": False, "ca_cert_file": "/etc/ssl/ca.pem"},
    ):
        VaultwardenBackend(VaultwardenConfig.from_dict({**BASE_CONFIG, **overrides}))
    assert seen == [True, "/etc/ssl/ca.pem", False]


# --- path splitting ---------------------------------------------------------------


def test_split_candidates_prefers_the_longest_collection():
    collections = {"c1": "Network", "c2": "Network/Core", "c3": "Other"}
    assert split_candidates("Network/Core/db", collections) == [("c2", "db"), ("c1", "Core/db")]
    assert split_candidates("Network/db", collections) == [("c1", "db")]
    assert split_candidates("c2/db", collections) == [("c2", "db")]
    assert split_candidates("Missing/db", collections) == []
    # The collection alone is not an item reference.
    assert split_candidates("Network/Core", collections) == [("c1", "Core")]


@pytest.mark.parametrize("path", ["", "/", "Network", "Network/", "/item", "//"])
def test_split_candidates_rejects_malformed_paths(path):
    with pytest.raises(ValueError, match="<collection>/<item>"):
        split_candidates(path, {"c1": "Network"})


# --- read -------------------------------------------------------------------------


def test_read_returns_login_fields_and_custom_fields_but_never_the_totp_seed(server):
    backend = make_backend(server)
    assert backend.read("Network/Core Switch") == {
        "username": "admin",
        "password": "hunter2",
        "enable": "hunter3",
    }
    assert "otp-seed" not in json.dumps(backend.read("Network/Core Switch"))


def test_read_by_ids_and_item_with_its_own_key(server):
    cipher = server.add_cipher("Edge Router", [NETWORK], own_key=True, fields={"enable": "e2"})
    backend = make_backend(server)
    expected = {"username": "admin", "password": "hunter2", "enable": "e2"}
    assert backend.read("Network/Edge Router") == expected
    assert backend.read(f"Network/{cipher['id']}") == expected
    assert backend.read(f"{NETWORK}/Edge Router") == expected


def test_read_field_rules(server):
    key = server.org_key
    server.add_cipher(
        "Note",
        [NETWORK],
        cipher_type=2,
        notes=encrypt_text("built-in note", key),
        fields={"token": "tok"},
    )["fields"].extend(
        [
            {"type": 2, "name": encrypt_text("enabled", key), "value": encrypt_text("true", key)},
            {"type": 3, "name": encrypt_text("linked", key), "value": None, "linkedId": 100},
            {"type": 1, "name": encrypt_text("token", key), "value": encrypt_text("later", key)},
            {"type": 0, "name": encrypt_text("empty", key), "value": None},
            {"type": 0, "name": None, "value": encrypt_text("nameless", key)},
            {"type": 1, "name": encrypt_text("notes", key), "value": encrypt_text("custom", key)},
        ]
    )
    assert make_backend(server).read("Network/Note") == {
        "token": "tok",  # the first of two fields with the same name
        "enabled": "true",
        "notes": "custom",  # a custom field wins over the built-in of the same name
    }


def test_read_ssh_key_item(server):
    key = server.org_key
    server.add_cipher(
        "Deploy Key",
        [NETWORK],
        cipher_type=5,
        sshKey={
            "privateKey": encrypt_text("private", key),
            "publicKey": encrypt_text("public", key),
            "keyFingerprint": encrypt_text("print", key),
        },
    )
    assert make_backend(server).read("Network/Deploy Key") == {
        "private_key": "private",
        "public_key": "public",
        "fingerprint": "print",
    }


def test_read_missing_returns_none_and_malformed_raises(server):
    backend = make_backend(server)
    assert backend.read("Network/missing") is None
    assert backend.read("Nowhere/Core Switch") is None
    for path in ("", "Network", "Network/", "/Core Switch"):
        with pytest.raises(ValueError, match="<collection>/<item>"):
            backend.read(path)


def test_read_ignores_trash_other_organizations_and_personal_items(server):
    server.add_cipher("Trashed", [NETWORK], deletedDate="2026-01-01T00:00:00Z")
    server.add_cipher("Foreign", [NETWORK], organizationId="org-2")
    server.add_cipher("Personal", [NETWORK], organizationId=None)
    server.add_collection("col-foreign", "Elsewhere", org_id="org-2")
    server.add_cipher("Core Switch", ["col-foreign"])
    backend = make_backend(server)
    for name in ("Trashed", "Foreign", "Personal"):
        assert backend.read(f"Network/{name}") is None
    assert backend.read("Elsewhere/Core Switch") is None
    assert backend.list("") == ["Network/"]


def test_read_requires_the_item_to_be_in_the_named_collection(server):
    server.add_cipher("Only Core", [CORE])
    backend = make_backend(server)
    assert backend.read("Network/Only Core") is None
    assert backend.read("Network/Core/Only Core") is not None


def test_nested_collection_paths(server):
    server.add_cipher("db", [CORE], fields={"where": "core"})
    backend = make_backend(server)
    assert must_read(backend, "Network/Core/db")["where"] == "core"
    # An item of the outer collection whose own name contains a slash.
    server.add_cipher("Lab/db", [NETWORK], fields={"where": "lab"})
    assert must_read(make_backend(server), "Network/Lab/db")["where"] == "lab"


def test_ambiguous_names_are_an_error_and_ids_resolve_them(server):
    first = server.add_cipher("Twin", [NETWORK], fields={"n": "1"})
    second = server.add_cipher("Twin", [NETWORK], fields={"n": "2"})
    backend = make_backend(server)
    with pytest.raises(ValueError, match="ambiguous \\(2 items"):
        backend.read("Network/Twin")
    assert must_read(backend, f"Network/{first['id']}")["n"] == "1"
    assert must_read(backend, f"Network/{second['id']}")["n"] == "2"


def test_a_path_matching_through_two_splits_is_ambiguous(server):
    server.add_cipher("Core/db", [NETWORK])
    server.add_cipher("db", [CORE])
    with pytest.raises(ValueError, match="ambiguous"):
        make_backend(server).read("Network/Core/db")


def test_one_item_in_two_matching_collections_is_not_ambiguous(server):
    server.add_collection("col-network-2", "Network")
    server.add_cipher("Shared", [NETWORK, "col-network-2"], fields={"k": "v"})
    assert must_read(make_backend(server), "Network/Shared")["k"] == "v"


def test_undecryptable_entries_are_skipped_with_a_warning_not_fatal(server, caplog):
    server.add_cipher("Broken", [NETWORK])["name"] = "2.AAAA|AAAA|AAAA"
    server.collections.append({"id": "col-bad", "organizationId": ORG_ID, "name": "7.AAAA"})
    backend = make_backend(server)
    with caplog.at_level(logging.WARNING):
        assert backend.read("Network/Core Switch") is not None
    assert "Skipping undecryptable Vaultwarden item cipher-2" in caplog.text
    assert "Skipping undecryptable Vaultwarden collection col-bad" in caplog.text


def test_an_undecryptable_field_of_the_requested_item_is_an_error(server):
    server.add_cipher("Half", [NETWORK])["login"]["password"] = "2.AAAA|AAAA|AAAA"
    with pytest.raises(BitwardenCryptoError):
        make_backend(server).read("Network/Half")


def test_pascal_case_responses_of_older_servers(rsa_key):
    server = FakeVaultwarden(rsa_key, pascal_case=True)
    server.add_cipher("Core Switch", [NETWORK], fields={"enable": "hunter3"})
    backend = make_backend(server)
    assert must_read(backend, "Network/Core Switch")["enable"] == "hunter3"
    assert backend.list("Network") == ["Core/", "Core Switch"]


def test_get_field_reads_either_case():
    assert get_field({"organizationId": 1}, "organizationId") == 1
    assert get_field({"OrganizationId": 1}, "organizationId") == 1
    assert get_field({"key": 1}, "Key") == 1
    assert get_field({"other": 1}, "key") is None
    assert get_field(None, "key") is None and get_field([], "key") is None


# --- caching ----------------------------------------------------------------------


def test_reads_share_one_sync_within_the_ttl_and_one_key_derivation(server, monkeypatch):
    derivations = []
    real = backend_module.derive_master_key
    monkeypatch.setattr(
        backend_module,
        "derive_master_key",
        lambda *a, **kw: derivations.append(1) or real(*a, **kw),
    )
    backend = make_backend(server)
    for _ in range(3):
        assert backend.read("Network/Core Switch") is not None
    assert backend.list("Network") == ["Core/", "Core Switch"]
    assert (server.logins, server.syncs, len(derivations)) == (1, 1, 1)
    # A forced refresh syncs again but does not repeat the slow key derivation.
    backend.test()
    assert (server.syncs, len(derivations)) == (2, 1)


def test_a_miss_on_a_cached_copy_refreshes_once(server):
    backend = make_backend(server)
    assert backend.read("Network/late") is None
    assert server.syncs == 1  # the copy was fresh: no point asking again
    server.add_cipher("late", [NETWORK], cipher_type=2, fields={"k": "v"})
    assert backend.read("Network/late") == {"k": "v"}
    assert server.syncs == 2


def test_ttl_zero_syncs_on_every_read_and_the_ttl_expires(server, monkeypatch):
    backend = make_backend(server, cache_ttl_seconds=0)
    backend.read("Network/Core Switch")
    backend.read("Network/Core Switch")
    assert server.syncs == 2

    now = [1000.0]
    monkeypatch.setattr(backend_module.time, "monotonic", lambda: now[0])
    cached = make_backend(server, cache_ttl_seconds=30)
    cached.read("Network/Core Switch")
    now[0] += 29
    cached.read("Network/Core Switch")
    assert server.syncs == 3
    now[0] += 2
    cached.read("Network/Core Switch")
    assert server.syncs == 4


def test_key_material_change_on_the_server_is_picked_up(server, rsa_key):
    backend = make_backend(server, cache_ttl_seconds=0)
    assert backend.read("Network/Core Switch") is not None
    # The user changed the KDF settings: new protected user key, new parameters.
    master_key = derive_master_key(PASSWORD, EMAIL, kdf_type=0, iterations=2000)
    server.protected_user_key = encrypt(server.user_key.to_bytes(), stretch_master_key(master_key))
    server.kdf = {"Kdf": 0, "KdfIterations": 2000}
    backend.test()
    assert backend.read("Network/Core Switch") is not None


# --- write ------------------------------------------------------------------------


def test_write_creates_a_secure_note_with_hidden_fields(server):
    backend = make_backend(server)
    backend.write("Network/db", {"user": "svc", "password": "hunter2", "port": 5432})

    (cipher,) = server.named("db")
    assert cipher["type"] == 2 and cipher["secureNote"] == {"type": 0}
    assert cipher["organizationId"] == ORG_ID and cipher["collectionIds"] == [NETWORK]
    assert cipher["encryptedFor"] == "u-1"
    assert cipher["key"] is None and cipher["notes"] is None
    assert {field["type"] for field in cipher["fields"]} == {1}
    assert server.plain_fields(cipher) == {"user": "svc", "password": "hunter2", "port": "5432"}
    # Nothing leaves in the clear.
    sent = server.requests[-1].content.decode()
    assert "hunter2" not in sent and "svc" not in sent and '"db"' not in sent
    assert backend.read("Network/db") == {"user": "svc", "password": "hunter2", "port": "5432"}


def test_write_puts_a_new_item_in_the_most_specific_collection(server):
    backend = make_backend(server)
    backend.write("Network/Core/db", {"k": "v"})
    (cipher,) = server.named("db")
    assert cipher["collectionIds"] == [CORE]
    assert backend.list("Network/Core") == ["db"]


def test_write_replaces_the_fields_of_an_existing_secure_note(server):
    backend = make_backend(server)
    backend.write("Network/db", {"user": "svc", "password": "first"})
    (cipher,) = server.named("db")
    name_before = cipher["name"]
    cipher["notes"] = encrypt_text("kept", server.org_key)
    cipher["passwordHistory"] = [{"password": "2.old", "lastUsedDate": "2026-01-01T00:00:00Z"}]

    backend.write("Network/db", {"password": "second"})
    assert server.named("db") == [cipher]
    assert server.plain_fields(cipher) == {"password": "second"}
    assert cipher["name"] == name_before
    assert cipher["passwordHistory"][0]["password"] == "2.old"
    assert backend.read("Network/db") == {"notes": "kept", "password": "second"}

    backend.write("Network/db", {})
    assert cipher["fields"] == []


def test_write_keeps_an_items_own_key(server):
    cipher = server.add_cipher("keyed", [NETWORK], cipher_type=2, own_key=True, fields={"a": "1"})
    wrapped_key = cipher["key"]
    backend = make_backend(server)
    backend.write("Network/keyed", {"b": "2"})
    assert cipher["key"] == wrapped_key
    assert server.plain_fields(cipher) == {"b": "2"}
    assert backend.read("Network/keyed") == {"b": "2"}


def test_write_refuses_items_that_are_not_secure_notes(server):
    backend = make_backend(server)
    with pytest.raises(ValueError, match="is a Login item, not a Hegemony-managed Secure Note"):
        backend.write("Network/Core Switch", {"password": "x"})
    server.add_cipher("Odd", [NETWORK], cipher_type=9)
    with pytest.raises(ValueError, match="is a type 9 item"):
        backend.write("Network/Odd", {"password": "x"})
    assert not [r for r in server.requests if r.method == "PUT"]
    assert must_read(backend, "Network/Core Switch")["password"] == "hunter2"


def test_write_errors(server):
    backend = make_backend(server)
    with pytest.raises(ValueError, match="collection not found"):
        backend.write("Nowhere/db", {"k": "v"})
    with pytest.raises(ValueError, match="<collection>/<item>"):
        backend.write("Network", {"k": "v"})
    invalid: list[Any] = [{"": "v"}, {5: "v"}]
    for bad in invalid:
        with pytest.raises(ValueError, match="non-empty strings"):
            backend.write("Network/db", bad)
    server.add_cipher("Twin", [NETWORK], cipher_type=2)
    server.add_cipher("Twin", [NETWORK], cipher_type=2)
    with pytest.raises(ValueError, match="ambiguous"):
        backend.write("Network/Twin", {"k": "v"})
    assert not [r for r in server.requests if r.method in ("PUT", "POST") and "/api/" in r.url.path]


def test_write_starts_from_a_fresh_copy_and_server_refusals_surface(server):
    backend = make_backend(server)
    backend.write("Network/db", {"k": "1"})
    assert backend.read("Network/db") == {"k": "1"}
    # Changed behind the plugin's cached copy: the write must still see the new revision.
    (cipher,) = server.named("db")
    cipher["revisionDate"] = "2026-02-01T00:00:00Z"
    backend.write("Network/db", {"k": "2"})
    assert server.plain_fields(cipher) == {"k": "2"}

    server.fail[("POST", "/api/ciphers/create")] = httpx.Response(
        400, json={"message": "You don't have permission to add cipher directly to organization"}
    )
    with pytest.raises(VaultwardenError, match="\\(400\\): You don't have permission") as excinfo:
        backend.write("Network/blocked", {"k": "v"})
    assert excinfo.value.status_code == 400


# --- delete -----------------------------------------------------------------------


def test_delete_moves_the_item_to_the_trash(server):
    backend = make_backend(server)
    backend.write("Network/db", {"k": "v"})
    backend.delete("Network/db")
    (cipher,) = server.named("db")
    assert cipher["deletedDate"]
    assert server.requests[-1].url.path == f"/api/ciphers/{cipher['id']}/delete"
    assert server.requests[-1].method == "PUT"
    assert backend.read("Network/db") is None
    # The name is free again.
    backend.write("Network/db", {"k": "again"})
    assert backend.read("Network/db") == {"k": "again"}


def test_delete_of_a_missing_item_is_not_an_error(server):
    backend = make_backend(server)
    backend.delete("Network/missing")
    backend.delete("Nowhere/missing")
    assert not [r for r in server.requests if r.method == "PUT"]
    with pytest.raises(ValueError, match="<collection>/<item>"):
        backend.delete("Network")


def test_delete_tolerates_a_concurrent_delete_but_not_other_failures(server):
    backend = make_backend(server)
    cipher = server.ciphers[0]
    route = ("PUT", f"/api/ciphers/{cipher['id']}/delete")
    server.fail[route] = httpx.Response(404, json={"message": "Cipher doesn't exist"})
    backend.delete("Network/Core Switch")
    server.fail[route] = httpx.Response(400, json={"message": "Cipher can't be deleted by user"})
    with pytest.raises(VaultwardenError, match="can't be deleted"):
        backend.delete("Network/Core Switch")


# --- list -------------------------------------------------------------------------


def test_list_walks_collection_names_as_a_tree(server):
    server.add_collection("col-deep", "Sites/Prague/Racks")
    server.add_cipher("pdu", ["col-deep"])
    server.add_cipher("Aux", [NETWORK])
    backend = make_backend(server)
    assert backend.list() == ["Network/", "Sites/"]
    assert backend.list("/") == ["Network/", "Sites/"]
    assert backend.list("Network") == ["Core/", "Aux", "Core Switch"]
    assert backend.list("Network/") == ["Core/", "Aux", "Core Switch"]
    assert backend.list(NETWORK) == ["Aux", "Core Switch"]
    assert backend.list("Network/Core") == []
    assert backend.list("Sites") == ["Prague/"]
    assert backend.list("Sites/Prague") == ["Racks/"]
    assert backend.list("Sites/Prague/Racks") == ["pdu"]
    assert backend.list("Net") == []
    assert backend.list("Network/Core Switch") == []
    assert backend.list("Missing") == []


def test_list_matches_the_platform_discovery_walk(server):
    """The host walks list() breadth-first and joins names with '/' into read() paths."""
    server.add_collection("col-deep", "Sites/Prague")
    server.add_cipher("pdu", ["col-deep"], cipher_type=2, fields={"k": "v"})
    server.add_cipher("db", [CORE], cipher_type=2, fields={"k": "v"})
    backend = make_backend(server)
    leaves, queue = [], [""]
    while queue:
        path = queue.pop(0)
        for entry in backend.list(path):
            child = f"{path}/{entry.rstrip('/')}" if path else entry.rstrip("/")
            (queue if entry.endswith("/") else leaves).append(child)
    assert sorted(leaves) == ["Network/Core Switch", "Network/Core/db", "Sites/Prague/pdu"]
    assert all(backend.read(leaf) is not None for leaf in leaves)


# --- test() and authentication -----------------------------------------------------


def test_test_logs_in_afresh_and_checks_everything(server):
    backend = make_backend(server)
    backend.test()
    backend.test()
    assert server.logins == 2 and server.syncs == 2
    form = dict(httpx.QueryParams(server.requests[0].content.decode()))
    assert form == {
        "grant_type": "client_credentials",
        "scope": "api",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "deviceType": "21",
        "deviceIdentifier": device_identifier("https://vault.example.com", CLIENT_ID),
        "deviceName": "Hegemony",
    }


def test_device_identifier_is_stable_per_configuration():
    first = device_identifier("https://vault.example.com", CLIENT_ID)
    assert first == device_identifier("https://vault.example.com", CLIENT_ID)
    assert first != device_identifier("https://vault.example.com", "user.u-2")
    assert first != device_identifier("https://other.example.com", CLIENT_ID)


def test_wrong_master_password_fails_clearly_without_leaking_it(server):
    backend = make_backend(server, master_password="wrong horse")
    with pytest.raises(BitwardenCryptoError, match="wrong master password") as excinfo:
        backend.test()
    assert "wrong horse" not in str(excinfo.value)
    with pytest.raises(BitwardenCryptoError, match="wrong master password"):
        backend.read("Network/Core Switch")


def test_wrong_api_key_reports_the_servers_message_without_the_secret(server):
    backend = make_backend(server, client_secret="not-the-sid")
    with pytest.raises(VaultwardenError, match="login failed \\(400\\): bad key") as excinfo:
        backend.test()
    assert excinfo.value.status_code == 400
    assert "not-the-sid" not in str(excinfo.value) and PASSWORD not in str(excinfo.value)


def test_salt_falls_back_to_the_profile_email(server):
    server.send_salt = False
    assert make_backend(server).read("Network/Core Switch") is not None


def test_argon2id_account(server):
    server.kdf = {"Kdf": 1, "KdfIterations": 2, "KdfMemory": 8, "KdfParallelism": 1}
    master_key = derive_master_key(
        PASSWORD, EMAIL, kdf_type=1, iterations=2, memory_mib=8, parallelism=1
    )
    server.protected_user_key = encrypt(server.user_key.to_bytes(), stretch_master_key(master_key))
    assert make_backend(server).read("Network/Core Switch") is not None


def test_organization_selection(server):
    assert make_backend(server, organization=ORG_ID).read("Network/Core Switch") is not None

    with pytest.raises(ValueError, match="organization 'Other' not found"):
        make_backend(server, organization="Other").test()

    server.organizations.append({"id": "org-2", "name": "Acme", "status": 2, "key": "4.AAAA"})
    with pytest.raises(ValueError, match="ambiguous \\(2 organizations\\)"):
        make_backend(server).test()
    make_backend(server, organization=ORG_ID).test()


@pytest.mark.parametrize("change", [{"status": 1}, {"key": None}])
def test_unconfirmed_membership_is_reported(server, change):
    server.organizations[0].update(change)
    with pytest.raises(ValueError, match="not confirmed yet"):
        make_backend(server).test()


def test_account_without_keys_is_reported(server):
    server.protected_private_key = None
    with pytest.raises(VaultwardenError, match="no key pair"):
        make_backend(server).test()


def test_expired_token_triggers_a_new_login(server, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("hegemony_secret_bitwarden.client.time.monotonic", lambda: now[0])
    monkeypatch.setattr(backend_module.time, "monotonic", lambda: now[0])
    backend = make_backend(server, cache_ttl_seconds=0)
    backend.read("Network/Core Switch")
    now[0] += 7200 - 61
    backend.read("Network/Core Switch")
    assert server.logins == 1
    now[0] += 2  # inside the safety margin before the stated expiry
    backend.read("Network/Core Switch")
    assert server.logins == 2


def test_a_revoked_token_is_retried_once_with_a_new_login(server):
    backend = make_backend(server, cache_ttl_seconds=0)
    backend.read("Network/Core Switch")
    server.valid_tokens.clear()
    assert backend.read("Network/Core Switch") is not None
    assert server.logins == 2

    # A server that keeps answering 401 is an error, not an endless loop.
    server.fail[("GET", "/api/sync")] = httpx.Response(401, json={"message": "Invalid token"})
    before = len(server.requests)
    with pytest.raises(VaultwardenError, match="\\(401\\): Invalid token"):
        backend.read("Network/Core Switch")
    assert len(server.requests) - before == 3  # sync, login, sync


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(200, text="<html>welcome</html>"), "returned no access token"),
        (httpx.Response(200, json={"token_type": "Bearer"}), "returned no access token"),
        (httpx.Response(200, json=["nope"]), "returned no access token"),
        (httpx.Response(502, text="Bad Gateway"), "login failed \\(502\\): Bad Gateway"),
        (httpx.Response(429, json={"message": "Too many login requests"}), "Too many login"),
        (
            httpx.Response(302, headers={"Location": "https://evil.example"}),
            "login failed \\(302\\)",
        ),
    ],
)
def test_unusable_login_responses(server, response, message):
    server.fail[("POST", "/identity/connect/token")] = response
    with pytest.raises(VaultwardenError, match=message):
        make_backend(server).test()
    assert all(request.url.host == "vault.example.com" for request in server.requests)


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(200, text="not json"), "non-JSON response"),
        (httpx.Response(200, json=[]), "unexpected response"),
        (httpx.Response(200, json={"ciphers": []}), "no user profile"),
        (httpx.Response(500, json={"message": "x" * 500}), "x{200}…$"),
    ],
)
def test_unusable_sync_responses(server, response, message):
    server.fail[("GET", "/api/sync")] = response
    with pytest.raises(VaultwardenError, match=message):
        make_backend(server).test()


def test_transport_errors_become_backend_errors_without_credentials():
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    backend = VaultwardenBackend(
        VaultwardenConfig.from_dict(BASE_CONFIG), transport=httpx.MockTransport(refuse)
    )
    with pytest.raises(VaultwardenError, match="ConnectError: connection refused") as excinfo:
        backend.test()
    assert excinfo.value.status_code is None
    assert CLIENT_SECRET not in str(excinfo.value) and PASSWORD not in str(excinfo.value)
    assert excinfo.value.__cause__ is None
