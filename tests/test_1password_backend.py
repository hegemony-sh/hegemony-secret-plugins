# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the 1Password secret backend plugin: registration + mocked-client behavior."""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import hegemony_secret_1password as plugin
from hegemony_secret_1password.connect_client import (
    OnePasswordConnectBackend,
    OnePasswordConnectConfig,
)
from hegemony_secret_1password.service_account_client import (
    OnePasswordServiceAccountBackend,
    OnePasswordServiceAccountConfig,
    _AsyncLoopRunner,
)


class FakeRegistry:
    api_version = 1

    def __init__(self) -> None:
        self.types: dict[str, dict[str, Any]] = {}

    def register_backend_type(self, *, backend_type: str, **kwargs: Any) -> None:
        self.types[backend_type] = kwargs


def test_register_adds_expected_backend_types():
    reg = FakeRegistry()
    plugin.register(reg)
    assert set(reg.types) == {"onepassword_connect", "onepassword_service_account"}
    for entry in reg.types.values():
        assert entry["config_schema"]["type"] == "object"
        assert entry["display_name"]
        assert entry["description"]
    assert reg.types["onepassword_connect"]["factory"] is plugin.build_onepassword_connect_backend
    assert (
        reg.types["onepassword_service_account"]["factory"]
        is plugin.build_onepassword_service_account_backend
    )


def test_register_satisfies_sdk_registry_protocol():
    from hegemony_secret_sdk import SecretBackendRegistry

    assert isinstance(FakeRegistry(), SecretBackendRegistry)


def test_connect_config_schema_marks_token_as_secret_ref():
    reg = FakeRegistry()
    plugin.register(reg)
    schema = reg.types["onepassword_connect"]["config_schema"]
    assert schema["required"] == ["connect_host", "connect_token"]
    properties = schema["properties"]
    assert properties["connect_token"].get("x_secret_ref") is True
    assert "x_secret_ref" not in properties["connect_host"]


def test_service_account_config_schema_marks_token_as_secret_ref():
    reg = FakeRegistry()
    plugin.register(reg)
    schema = reg.types["onepassword_service_account"]["config_schema"]
    assert schema["required"] == ["service_account_token"]
    properties = schema["properties"]
    assert properties["service_account_token"].get("x_secret_ref") is True
    assert "x_secret_ref" not in properties["integration_name"]
    assert properties["integration_name"]["default"] == "Hegemony"


# --- Connect backend -------------------------------------------------------------


def _fake_field(label: str, value: Any) -> MagicMock:
    field = MagicMock()
    field.label = label
    field.value = value
    return field


def _connect_backend_with_mock_client() -> tuple[OnePasswordConnectBackend, MagicMock]:
    config = OnePasswordConnectConfig(
        connect_host="https://connect.example.com", connect_token="tok"
    )
    with patch("onepasswordconnectsdk.client.new_client") as mock_new_client:
        mock_client = MagicMock()
        mock_new_client.return_value = mock_client
        backend = OnePasswordConnectBackend(config)
    return backend, mock_client


def test_connect_build_backend_returns_backend_instance():
    with patch("onepasswordconnectsdk.client.new_client") as mock_new_client:
        mock_new_client.return_value = MagicMock()
        backend = plugin.build_onepassword_connect_backend(
            {"connect_host": "https://connect.example.com", "connect_token": "tok"}
        )
    assert isinstance(backend, OnePasswordConnectBackend)


def test_connect_read_returns_field_mapping():
    backend, mock_client = _connect_backend_with_mock_client()
    mock_item = MagicMock()
    mock_item.fields = [_fake_field("username", "alice"), _fake_field("password", "hunter2")]
    mock_client.get_item.return_value = mock_item

    result = backend.read("Engineering/Database")

    assert result == {"username": "alice", "password": "hunter2"}
    mock_client.get_item.assert_called_once_with("Database", "Engineering")


def test_connect_read_skips_none_valued_fields():
    backend, mock_client = _connect_backend_with_mock_client()
    mock_item = MagicMock()
    mock_item.fields = [_fake_field("username", "alice"), _fake_field("otp", None)]
    mock_client.get_item.return_value = mock_item

    result = backend.read("Engineering/Database")

    assert result == {"username": "alice"}


def test_connect_read_handles_fieldless_item():
    backend, mock_client = _connect_backend_with_mock_client()
    mock_item = MagicMock()
    mock_item.fields = None
    mock_client.get_item.return_value = mock_item

    result = backend.read("Engineering/Database")

    assert result == {}


def test_connect_read_raises_value_error_for_malformed_path():
    backend, _ = _connect_backend_with_mock_client()
    try:
        backend.read("nokey")
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "vault" in str(exc).lower() or "path" in str(exc).lower()


def test_connect_read_returns_none_for_missing_item():
    from onepasswordconnectsdk.errors import FailedToRetrieveItemException

    backend, mock_client = _connect_backend_with_mock_client()
    mock_client.get_item.side_effect = FailedToRetrieveItemException(
        "Found 0 items", status_code=404
    )

    result = backend.read("Engineering/Database")

    assert result is None


def _fake_connect_vault(vault_id: str, name: str) -> MagicMock:
    vault = MagicMock()
    vault.id = vault_id
    vault.name = name
    return vault


def test_connect_write_creates_secure_note_when_item_missing():
    from onepasswordconnectsdk.errors import FailedToRetrieveItemException

    backend, mock_client = _connect_backend_with_mock_client()
    mock_client.get_vaults.return_value = [_fake_connect_vault("vault-1", "Engineering")]
    mock_client.get_item.side_effect = FailedToRetrieveItemException("Found 0", status_code=404)

    backend.write("Engineering/Database", {"password": "new"})

    mock_client.create_item.assert_called_once()
    vault_id, item = mock_client.create_item.call_args.args
    assert vault_id == "vault-1"
    assert item.title == "Database"
    assert item.category == "SECURE_NOTE"
    assert [(f.label, f.value) for f in item.fields] == [("password", "new")]
    mock_client.update_item.assert_not_called()


def test_connect_write_replaces_fields_of_existing_item():
    backend, mock_client = _connect_backend_with_mock_client()
    mock_client.get_vaults.return_value = [_fake_connect_vault("vault-1", "Engineering")]
    existing = MagicMock()
    existing.id = "item-1"
    existing.category = "SECURE_NOTE"  # only Hegemony-managed Secure Notes are rewritten
    mock_client.get_item.return_value = existing

    backend.write("Engineering/Database", {"password": "rotated"})

    mock_client.create_item.assert_not_called()
    mock_client.update_item.assert_called_once()
    item_uuid, vault_id, item = mock_client.update_item.call_args.args
    assert (item_uuid, vault_id) == ("item-1", "vault-1")
    assert [(f.label, f.value) for f in item.fields] == [("password", "rotated")]


def test_connect_write_unknown_vault_raises():
    backend, mock_client = _connect_backend_with_mock_client()
    mock_client.get_vaults.return_value = []
    try:
        backend.write("Nope/Database", {"password": "new"})
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "vault" in str(exc).lower()


def test_connect_delete_removes_existing_item():
    backend, mock_client = _connect_backend_with_mock_client()
    mock_client.get_vaults.return_value = [_fake_connect_vault("vault-1", "Engineering")]
    existing = MagicMock()
    existing.id = "item-1"
    mock_client.get_item.return_value = existing

    backend.delete("Engineering/Database")

    mock_client.delete_item.assert_called_once_with("item-1", "vault-1")


def test_connect_delete_missing_item_is_not_an_error():
    from onepasswordconnectsdk.errors import FailedToRetrieveItemException

    backend, mock_client = _connect_backend_with_mock_client()
    mock_client.get_vaults.return_value = [_fake_connect_vault("vault-1", "Engineering")]
    mock_client.get_item.side_effect = FailedToRetrieveItemException("Found 0", status_code=404)

    backend.delete("Engineering/Database")  # should not raise
    mock_client.delete_item.assert_not_called()


def test_connect_test_calls_get_vaults():
    backend, mock_client = _connect_backend_with_mock_client()
    backend.test()
    mock_client.get_vaults.assert_called_once()


# --- Service account backend ------------------------------------------------------


def _fake_vault_overview(vault_id: str, title: str) -> MagicMock:
    overview = MagicMock()
    overview.id = vault_id
    overview.title = title
    return overview


def _fake_item_overview(item_id: str, title: str) -> MagicMock:
    overview = MagicMock()
    overview.id = item_id
    overview.title = title
    return overview


def _fake_item_field(title: str, value: Any) -> MagicMock:
    field = MagicMock()
    field.title = title
    field.value = value
    return field


def _service_account_backend_with_mock_client() -> tuple[
    OnePasswordServiceAccountBackend, MagicMock
]:
    config = OnePasswordServiceAccountConfig(service_account_token="ops_test")
    backend = OnePasswordServiceAccountBackend(config)

    mock_client = MagicMock()
    mock_client.vaults.list = AsyncMock(
        return_value=[_fake_vault_overview("vault-1", "Engineering")]
    )
    mock_client.items.list = AsyncMock(return_value=[_fake_item_overview("item-1", "Database")])
    mock_item = MagicMock()
    mock_item.fields = [
        _fake_item_field("username", "alice"),
        _fake_item_field("password", "hunter2"),
        _fake_item_field("otp", None),
    ]
    mock_client.items.get = AsyncMock(return_value=mock_item)

    with patch(
        "onepassword.client.Client.authenticate",
        new=AsyncMock(return_value=mock_client),
    ):
        # Force authentication eagerly within this patch context so the cached
        # client is the mock, regardless of when read()/test() trigger it.
        backend._ensure_client()

    return backend, mock_client


def test_service_account_build_backend_returns_backend_instance():
    backend = plugin.build_onepassword_service_account_backend(
        {"service_account_token": "ops_test"}
    )
    assert isinstance(backend, OnePasswordServiceAccountBackend)


def test_service_account_read_resolves_vault_and_item_to_fields():
    backend, mock_client = _service_account_backend_with_mock_client()

    result = backend.read("Engineering/Database")

    assert result == {"username": "alice", "password": "hunter2"}
    mock_client.vaults.list.assert_called_once()
    mock_client.items.list.assert_called_once_with("vault-1")
    mock_client.items.get.assert_called_once_with("vault-1", "item-1")


def test_service_account_read_raises_value_error_for_malformed_path():
    backend, _ = _service_account_backend_with_mock_client()
    try:
        backend.read("nokey")
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "vault" in str(exc).lower() or "path" in str(exc).lower()


def test_service_account_read_returns_none_for_unknown_vault():
    backend, mock_client = _service_account_backend_with_mock_client()

    result = backend.read("NoSuchVault/Database")

    assert result is None


def test_service_account_read_returns_none_for_unknown_item():
    backend, mock_client = _service_account_backend_with_mock_client()

    result = backend.read("Engineering/NoSuchItem")

    assert result is None


def test_service_account_write_creates_secure_note_when_item_missing():
    from onepassword import ItemCategory, ItemFieldType

    backend, mock_client = _service_account_backend_with_mock_client()
    mock_client.items.list = AsyncMock(return_value=[])  # no existing items
    mock_client.items.create = AsyncMock()

    backend.write("Engineering/Database", {"password": "new"})

    mock_client.items.create.assert_called_once()
    params = mock_client.items.create.call_args.args[0]
    assert params.title == "Database"
    assert params.vault_id == "vault-1"
    assert params.category == ItemCategory.SECURENOTE
    assert [(f.title, f.value, f.field_type) for f in params.fields] == [
        ("password", "new", ItemFieldType.CONCEALED)
    ]


def test_service_account_write_replaces_fields_of_existing_item():
    from onepassword import ItemCategory

    backend, mock_client = _service_account_backend_with_mock_client()
    existing = MagicMock()
    existing.category = ItemCategory.SECURENOTE  # only Secure Notes are rewritten
    mock_client.items.get = AsyncMock(return_value=existing)
    mock_client.items.put = AsyncMock()

    backend.write("Engineering/Database", {"password": "rotated"})

    mock_client.items.put.assert_called_once_with(existing)
    assert [(f.title, f.value) for f in existing.fields] == [("password", "rotated")]


def test_service_account_write_unknown_vault_raises():
    backend, mock_client = _service_account_backend_with_mock_client()
    mock_client.vaults.list = AsyncMock(return_value=[])
    try:
        backend.write("Nope/Database", {"password": "new"})
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "vault" in str(exc).lower()


def test_service_account_delete_removes_existing_item():
    backend, mock_client = _service_account_backend_with_mock_client()
    mock_client.items.delete = AsyncMock()

    backend.delete("Engineering/Database")

    mock_client.items.delete.assert_called_once_with("vault-1", "item-1")


def test_service_account_delete_missing_item_is_not_an_error():
    backend, mock_client = _service_account_backend_with_mock_client()
    mock_client.items.list = AsyncMock(return_value=[])
    mock_client.items.delete = AsyncMock()

    backend.delete("Engineering/Database")  # should not raise
    mock_client.items.delete.assert_not_called()


def test_service_account_test_calls_vaults_list():
    backend, mock_client = _service_account_backend_with_mock_client()
    backend.test()
    mock_client.vaults.list.assert_called_once()


def test_service_account_config_defaults():
    config = OnePasswordServiceAccountConfig(service_account_token="ops_test")
    assert config.integration_name == "Hegemony"


def test_service_account_config_from_dict_custom_integration_name():
    config = OnePasswordServiceAccountConfig.from_dict(
        {"service_account_token": "ops_test", "integration_name": "Custom"}
    )
    assert config.integration_name == "Custom"


# --- Listing -------------------------------------------------------------------------


def test_connect_list_root_returns_vaults_as_containers():
    backend, mock_client = _connect_backend_with_mock_client()
    mock_client.get_vaults.return_value = [_fake_connect_vault("vault-1", "Engineering")]
    assert backend.list() == ["Engineering/"]


def test_connect_list_vault_returns_item_titles():
    backend, mock_client = _connect_backend_with_mock_client()
    mock_client.get_vaults.return_value = [_fake_connect_vault("vault-1", "Engineering")]
    item = MagicMock()
    item.title = "Database"
    mock_client.get_items.return_value = [item]

    assert backend.list("Engineering") == ["Database"]
    mock_client.get_items.assert_called_once_with("vault-1")


def test_connect_list_unknown_vault_returns_empty():
    backend, mock_client = _connect_backend_with_mock_client()
    mock_client.get_vaults.return_value = []
    assert backend.list("Nope") == []


def test_service_account_list_root_returns_vaults_as_containers():
    backend, _ = _service_account_backend_with_mock_client()
    assert backend.list() == ["Engineering/"]


def test_service_account_list_vault_returns_item_titles():
    backend, mock_client = _service_account_backend_with_mock_client()
    assert backend.list("Engineering") == ["Database"]
    mock_client.items.list.assert_called_once_with("vault-1")


def test_service_account_list_unknown_vault_returns_empty():
    backend, mock_client = _service_account_backend_with_mock_client()
    mock_client.vaults.list = AsyncMock(return_value=[])
    assert backend.list("Nope") == []


def test_backends_satisfy_listable_protocol():
    from hegemony_secret_sdk import ListableSecretBackend

    connect_backend, _ = _connect_backend_with_mock_client()
    sa_backend, _ = _service_account_backend_with_mock_client()
    assert isinstance(connect_backend, ListableSecretBackend)
    assert isinstance(sa_backend, ListableSecretBackend)


# --- Async loop runner timeout -----------------------------------------------------


def test_async_loop_runner_raises_timeout_error_for_hung_coroutine():
    runner = _AsyncLoopRunner()
    with (
        patch(
            "hegemony_secret_1password.service_account_client._SDK_CALL_TIMEOUT_SECONDS",
            0.05,
        ),
        pytest.raises(TimeoutError, match="1Password SDK call timed out"),
    ):
        runner.run(asyncio.sleep(5))


# --- Connect error discrimination (not-found vs real failures) --------------------


def test_connect_read_returns_none_for_lookup_miss_without_status():
    """Title-based lookup misses ("Found 0 items") carry no HTTP status at all."""
    from onepasswordconnectsdk.errors import FailedToRetrieveItemException

    backend, mock_client = _connect_backend_with_mock_client()
    mock_client.get_item.side_effect = FailedToRetrieveItemException(
        "Found 0 items in vault v1 with title Database"
    )

    assert backend.read("Engineering/Database") is None


def test_connect_read_reraises_auth_error_embedded_in_message():
    """Title-based lookups embed the HTTP status only in the message; a 401 must not
    be masked as "secret not found"."""
    from onepasswordconnectsdk.errors import FailedToRetrieveItemException

    backend, mock_client = _connect_backend_with_mock_client()
    mock_client.get_item.side_effect = FailedToRetrieveItemException(
        "Unable to retrieve items. Received 401 for /v1/vaults with message: invalid bearer token"
    )

    with pytest.raises(FailedToRetrieveItemException):
        backend.read("Engineering/Database")


def test_connect_read_reraises_non_404_status_code():
    from onepasswordconnectsdk.errors import FailedToRetrieveItemException

    backend, mock_client = _connect_backend_with_mock_client()
    mock_client.get_item.side_effect = FailedToRetrieveItemException(
        "Unable to retrieve item.", status_code=403
    )

    with pytest.raises(FailedToRetrieveItemException):
        backend.read("Engineering/Database")


def test_connect_delete_reraises_auth_error_on_item_probe():
    from onepasswordconnectsdk.errors import FailedToRetrieveItemException

    backend, mock_client = _connect_backend_with_mock_client()
    mock_client.get_vaults.return_value = [_fake_connect_vault("v1", "Engineering")]
    mock_client.get_item.side_effect = FailedToRetrieveItemException(
        "Unable to retrieve item.", status_code=401
    )

    with pytest.raises(FailedToRetrieveItemException):
        backend.delete("Engineering/Database")
    mock_client.delete_item.assert_not_called()


def test_connect_read_reraises_ambiguous_title():
    """ "Found 2 items" means a duplicated title — surfacing it as "not found" would
    silently hide a real, actionable problem."""
    from onepasswordconnectsdk.errors import FailedToRetrieveItemException

    backend, mock_client = _connect_backend_with_mock_client()
    mock_client.get_item.side_effect = FailedToRetrieveItemException(
        "Found 2 items in vault v1 with title Database"
    )

    with pytest.raises(FailedToRetrieveItemException):
        backend.read("Engineering/Database")


def test_connect_resolve_vault_rejects_ambiguous_title():
    backend, mock_client = _connect_backend_with_mock_client()
    mock_client.get_vaults.return_value = [
        _fake_connect_vault("v1", "Engineering"),
        _fake_connect_vault("v2", "Engineering"),
    ]

    with pytest.raises(ValueError, match="ambiguous"):
        backend.delete("Engineering/Database")


# --- write refuses non-Secure-Note items -------------------------------------------


def test_connect_write_refuses_non_secure_note_item():
    """Replacing a LOGIN item's fields would destroy its built-in username/password;
    Hegemony only rewrites the Secure Notes it manages."""
    backend, mock_client = _connect_backend_with_mock_client()
    mock_client.get_vaults.return_value = [_fake_connect_vault("v1", "Engineering")]
    existing = MagicMock()
    existing.category = "LOGIN"
    mock_client.get_item.return_value = existing

    with pytest.raises(ValueError, match="Secure Note"):
        backend.write("Engineering/Database", {"password": "x"})
    mock_client.update_item.assert_not_called()


def test_service_account_write_refuses_non_secure_note_item():
    from onepassword import ItemCategory

    backend, mock_client = _service_account_backend_with_mock_client()
    mock_client.vaults.list = AsyncMock(return_value=[_fake_vault_overview("v1", "Engineering")])
    mock_client.items.list = AsyncMock(return_value=[_fake_item_overview("i1", "Database")])
    existing = MagicMock()
    existing.category = ItemCategory.LOGIN
    mock_client.items.get = AsyncMock(return_value=existing)
    mock_client.items.put = AsyncMock()

    with pytest.raises(ValueError, match="Secure Note"):
        backend.write("Engineering/Database", {"password": "x"})
    mock_client.items.put.assert_not_called()


def test_service_account_ambiguous_vault_title_raises():
    backend, mock_client = _service_account_backend_with_mock_client()
    mock_client.vaults.list = AsyncMock(
        return_value=[
            _fake_vault_overview("v1", "Engineering"),
            _fake_vault_overview("v2", "Engineering"),
        ]
    )

    with pytest.raises(ValueError, match="ambiguous"):
        backend.read("Engineering/Database")
