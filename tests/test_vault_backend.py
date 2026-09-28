# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the Vault/OpenBao secret backend plugin: registration + behavior via hvac mocks."""

from typing import Any
from unittest.mock import MagicMock, patch

import hegemony_secret_vault as plugin
from hegemony_secret_vault.vault_client import VaultBackendConfig, VaultSecretsBackend


class FakeRegistry:
    api_version = 1

    def __init__(self) -> None:
        self.types: dict[str, dict[str, Any]] = {}

    def register_backend_type(self, *, backend_type: str, **kwargs: Any) -> None:
        self.types[backend_type] = kwargs


def test_register_adds_expected_backend_types():
    reg = FakeRegistry()
    plugin.register(reg)
    assert set(reg.types) == {"vault", "vault_kv2", "openbao"}
    assert reg.types["vault"]["factory"] is plugin.build_vault_backend
    assert reg.types["vault_kv2"]["factory"] is plugin.build_vault_backend
    # A distinct callable, so OpenBao's construction can diverge without touching Vault.
    assert reg.types["openbao"]["factory"] is plugin.build_openbao_backend
    for entry in reg.types.values():
        assert entry["config_schema"]["type"] == "object"
        assert entry["config_schema"]["required"] == ["address"]
        assert entry["display_name"]
        assert entry["description"]


def test_register_uses_distinct_display_names():
    # Every backend type must render as a distinct label in the host's type dropdown;
    # duplicate display names make entries indistinguishable to users.
    reg = FakeRegistry()
    plugin.register(reg)
    display_names = [entry["display_name"] for entry in reg.types.values()]
    assert len(display_names) == len(set(display_names))


def test_register_display_names():
    reg = FakeRegistry()
    plugin.register(reg)
    assert reg.types["vault"]["display_name"] == "HashiCorp Vault (KV v2)"
    assert reg.types["vault_kv2"]["display_name"] == "HashiCorp Vault (KV v2, legacy type)"
    assert reg.types["openbao"]["display_name"] == "OpenBao (KV v2)"


def test_register_marks_only_vault_kv2_hidden():
    # vault_kv2 is a legacy alias of vault: resolvable for existing rows, hidden from
    # create-time type pickers. The preferred vault type stays visible.
    reg = FakeRegistry()
    plugin.register(reg)
    assert reg.types["vault_kv2"].get("hidden") is True
    assert reg.types["vault"].get("hidden", False) is False
    assert reg.types["openbao"].get("hidden", False) is False


def test_register_satisfies_sdk_registry_protocol():
    from hegemony_secret_sdk import SecretBackendRegistry

    assert isinstance(FakeRegistry(), SecretBackendRegistry)


def test_config_schema_marks_auth_material_as_secret_refs():
    reg = FakeRegistry()
    plugin.register(reg)
    schema = reg.types["vault"]["config_schema"]
    properties = schema["properties"]
    for field in (
        "token",
        "role_id",
        "secret_id",
        "api_role_id",
        "api_secret_id",
        "worker_role_id",
        "worker_secret_id",
    ):
        assert properties[field].get("x_secret_ref") is True, field
    assert "x_secret_ref" not in properties["address"]
    assert properties["verify_ssl"]["type"] == "boolean"


def test_config_schema_does_not_mark_credential_paths_as_secret_refs():
    # A filesystem path is not secret material. Marking it x_secret_ref would drag it into
    # the host's no-plaintext policy, which accepts only placeholder expressions -- making
    # a literal path (the only useful value for these fields) fail validation outright.
    reg = FakeRegistry()
    plugin.register(reg)
    properties = reg.types["vault"]["config_schema"]["properties"]
    for field in (
        "role_id_file",
        "secret_id_file",
        "api_role_id_file",
        "api_secret_id_file",
        "worker_role_id_file",
        "worker_secret_id_file",
        "ca_cert_file",
    ):
        assert "x_secret_ref" not in properties[field], field
        assert properties[field]["type"] == "string", field


def test_config_schema_includes_per_component_approle_overrides():
    # The host remaps api_role_id/api_secret_id and worker_role_id/worker_secret_id to
    # role_id/secret_id before building the client (see apps/api/routers/secrets.py,
    # apps/api/services/git_ops.py, apps/worker/template_resolver.py in the host repo).
    # These must be present in the schema so the schema-driven form can set them.
    reg = FakeRegistry()
    plugin.register(reg)
    schema = reg.types["vault"]["config_schema"]
    properties = schema["properties"]
    for field in ("api_role_id", "api_secret_id", "worker_role_id", "worker_secret_id"):
        assert properties[field]["type"] == "string"
        assert properties[field].get("title")


def test_config_schema_marks_component_overrides_with_fallback_of():
    # x_fallback_of lets the host UI show which base field an override inherits from.
    reg = FakeRegistry()
    plugin.register(reg)
    properties = reg.types["vault"]["config_schema"]["properties"]
    assert properties["api_role_id"]["x_fallback_of"] == "role_id"
    assert properties["worker_role_id"]["x_fallback_of"] == "role_id"
    assert properties["api_secret_id"]["x_fallback_of"] == "secret_id"
    assert properties["worker_secret_id"]["x_fallback_of"] == "secret_id"
    assert "x_fallback_of" not in properties["role_id"]
    assert "x_fallback_of" not in properties["secret_id"]


def test_config_schema_includes_per_component_credential_file_overrides():
    # Credential *files* need the same per-component split as the value fields, or a
    # deployment where the API and worker hold separate AppRoles cannot use the
    # re-read-on-login path that makes rotation work.
    reg = FakeRegistry()
    plugin.register(reg)
    properties = reg.types["vault"]["config_schema"]["properties"]
    expected = {
        "api_role_id_file": ("role_id_file", "api"),
        "api_secret_id_file": ("secret_id_file", "api"),
        "worker_role_id_file": ("role_id_file", "worker"),
        "worker_secret_id_file": ("secret_id_file", "worker"),
    }
    for field, (base, component) in expected.items():
        assert properties[field]["x_fallback_of"] == base, field
        assert properties[field]["x_component"] == component, field
    assert "x_component" not in properties["role_id_file"]
    assert "x_component" not in properties["secret_id_file"]


def test_openbao_schema_shares_property_names_with_vault():
    # The host keys its per-component override handling and its sensitive-field policy off
    # property NAMES, so the two products must expose an identical set; only the
    # human-facing labels may differ.
    reg = FakeRegistry()
    plugin.register(reg)
    vault_props = reg.types["vault"]["config_schema"]["properties"]
    openbao_props = reg.types["openbao"]["config_schema"]["properties"]
    assert set(vault_props) == set(openbao_props)
    assert openbao_props["address"]["title"] == "OpenBao address"
    assert vault_props["address"]["title"] == "Vault address"


@patch("hvac.Client")
def test_build_vault_backend_returns_backend_instance(mock_client_cls):
    mock_client_cls.return_value = MagicMock(token="static-token")
    backend = plugin.build_vault_backend({"address": "https://vault:8200", "token": "s3cret"})
    assert isinstance(backend, VaultSecretsBackend)


def _backend_with_mock_client(**config_overrides) -> tuple[VaultSecretsBackend, MagicMock]:
    config = VaultBackendConfig.from_dict(
        {"address": "https://vault:8200", "token": "tok", **config_overrides}
    )
    with patch("hvac.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        backend = VaultSecretsBackend(config)
    return backend, mock_client


def test_read_returns_kv2_data():
    backend, mock_client = _backend_with_mock_client()
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"password": "hunter2"}}
    }
    result = backend.read("orgs/default/secrets/db")
    assert result == {"password": "hunter2"}
    mock_client.secrets.kv.v2.read_secret_version.assert_called_once_with(
        path="orgs/default/secrets/db", mount_point="hegemony"
    )


def test_write_calls_create_or_update_secret():
    backend, mock_client = _backend_with_mock_client()
    backend.write("orgs/default/secrets/db", {"password": "new-pass"})
    mock_client.secrets.kv.v2.create_or_update_secret.assert_called_once_with(
        path="orgs/default/secrets/db", secret={"password": "new-pass"}, mount_point="hegemony"
    )


def test_delete_calls_delete_metadata_and_all_versions():
    backend, mock_client = _backend_with_mock_client()
    backend.delete("orgs/default/secrets/db")
    mock_client.secrets.kv.v2.delete_metadata_and_all_versions.assert_called_once_with(
        path="orgs/default/secrets/db", mount_point="hegemony"
    )


def test_delete_ignores_invalid_path():
    from hvac.exceptions import InvalidPath

    backend, mock_client = _backend_with_mock_client()
    mock_client.secrets.kv.v2.delete_metadata_and_all_versions.side_effect = InvalidPath()
    backend.delete("orgs/default/secrets/db")  # should not raise


def test_test_calls_auth_check_and_reads_kv_configuration():
    backend, mock_client = _backend_with_mock_client()
    backend.test()
    mock_client.secrets.kv.v2.read_configuration.assert_called_once_with(mount_point="hegemony")


def test_test_raises_vault_error_on_connectivity_failure():
    from hegemony_secret_vault.vault_client import VaultError

    backend, mock_client = _backend_with_mock_client()
    mock_client.secrets.kv.v2.read_configuration.side_effect = RuntimeError("connection refused")
    try:
        backend.test()
        raise AssertionError("expected VaultError")
    except VaultError:
        pass


def test_list_returns_kv2_keys():
    backend, mock_client = _backend_with_mock_client()
    mock_client.secrets.kv.v2.list_secrets.return_value = {"data": {"keys": ["db", "apps/"]}}
    assert backend.list("orgs/default") == ["db", "apps/"]
    mock_client.secrets.kv.v2.list_secrets.assert_called_once_with(
        path="orgs/default", mount_point="hegemony"
    )


def test_list_unknown_path_returns_empty():
    from hvac.exceptions import InvalidPath

    backend, mock_client = _backend_with_mock_client()
    mock_client.secrets.kv.v2.list_secrets.side_effect = InvalidPath()
    assert backend.list("nope") == []


def test_backend_satisfies_listable_protocol():
    from hegemony_secret_sdk import ListableSecretBackend

    backend, _ = _backend_with_mock_client()
    assert isinstance(backend, ListableSecretBackend)


def test_vault_backend_config_defaults():
    config = VaultBackendConfig(address="http://vault:8200")
    assert config.address == "http://vault:8200"
    assert config.kv_mount == "hegemony"
    assert config.path_prefix == ""
    assert config.verify_ssl is True


def test_vault_backend_config_all_fields():
    config = VaultBackendConfig(
        address="https://vault.example.com:8200",
        kv_mount="secrets",
        path_prefix="orgs",
        role_id="test-role-id",
        secret_id="test-secret-id",
        ca_cert_file="/path/to/ca.crt",
        verify_ssl=True,
    )
    assert config.kv_mount == "secrets"
    assert config.path_prefix == "orgs"
    assert config.role_id == "test-role-id"
    assert config.secret_id == "test-secret-id"
    assert config.ca_cert_file == "/path/to/ca.crt"


def test_vault_backend_missing_auth_raises():
    config = VaultBackendConfig(address="https://vault:8200")
    assert config.role_id is None
    assert config.secret_id is None
    with patch("hvac.Client") as mock_client_cls:
        mock_client_cls.return_value = MagicMock(token=None)
        try:
            VaultSecretsBackend(config)
            raise AssertionError("expected ValueError for missing auth")
        except ValueError as exc:
            assert "role_id" in str(exc).lower()


# --- AppRole auth lifecycle -------------------------------------------------------


def _approle_backend_with_mock_client(**config_overrides) -> tuple[VaultSecretsBackend, MagicMock]:
    config = VaultBackendConfig.from_dict({"address": "https://vault:8200", **config_overrides})
    with patch("hvac.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        backend = VaultSecretsBackend(config)
    return backend, mock_client


def test_approle_non_expiring_token_authenticates_once():
    """lease_duration 0 = a token that never expires; it must not force a fresh
    AppRole login (and a new Vault token) on every single operation."""
    backend, mock_client = _approle_backend_with_mock_client(role_id="rid", secret_id="sid")
    mock_client.auth.approle.login.return_value = {
        "auth": {"lease_duration": 0, "client_token": "minted-token"}
    }
    mock_client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"k": "v"}}}

    backend.read("a/b")
    backend.read("a/b")

    assert mock_client.auth.approle.login.call_count == 1


def test_approle_positive_lease_reuses_token_within_ttl():
    backend, mock_client = _approle_backend_with_mock_client(role_id="rid", secret_id="sid")
    mock_client.auth.approle.login.return_value = {
        "auth": {"lease_duration": 3600, "client_token": "minted-token"}
    }
    mock_client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"k": "v"}}}

    backend.read("a/b")
    backend.read("a/b")

    assert mock_client.auth.approle.login.call_count == 1


def test_approle_reauth_rereads_credential_files(tmp_path):
    """Rotated *_file contents (e.g. a Vault Agent re-writing the secret-id file) must
    be picked up on the next authentication without rebuilding the client."""
    role_file = tmp_path / "role_id"
    secret_file = tmp_path / "secret_id"
    role_file.write_text("rid-1\n")
    secret_file.write_text("sid-1\n")
    backend, mock_client = _approle_backend_with_mock_client(
        role_id_file=str(role_file), secret_id_file=str(secret_file)
    )
    mock_client.auth.approle.login.return_value = {
        "auth": {"lease_duration": 3600, "client_token": "minted-token"}
    }
    mock_client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {}}}

    backend.read("a/b")
    assert mock_client.auth.approle.login.call_args.kwargs == {
        "role_id": "rid-1",
        "secret_id": "sid-1",
    }

    secret_file.write_text("sid-2\n")
    backend._token_expiry = 0  # force re-authentication on the next call
    backend.read("a/b")
    assert mock_client.auth.approle.login.call_args.kwargs == {
        "role_id": "rid-1",
        "secret_id": "sid-2",
    }


# --- connectivity self-test probe --------------------------------------------------


def test_test_falls_back_to_metadata_list_when_config_read_forbidden():
    """Typical app policies don't grant read on <mount>/config; the probe must fall
    back to a metadata LIST instead of reporting a false failure."""
    from hvac.exceptions import Forbidden

    backend, mock_client = _backend_with_mock_client()
    mock_client.secrets.kv.v2.read_configuration.side_effect = Forbidden()
    mock_client.secrets.kv.v2.list_secrets.return_value = {"data": {"keys": ["a"]}}

    backend.test()  # must not raise

    mock_client.secrets.kv.v2.list_secrets.assert_called_once_with(path="", mount_point="hegemony")


def test_test_fallback_tolerates_empty_mount():
    from hvac.exceptions import Forbidden, InvalidPath

    backend, mock_client = _backend_with_mock_client()
    mock_client.secrets.kv.v2.read_configuration.side_effect = Forbidden()
    mock_client.secrets.kv.v2.list_secrets.side_effect = InvalidPath()

    backend.test()  # 404 on an empty mount still proves mount + auth are good


def test_test_fallback_raises_on_real_failure():
    from hvac.exceptions import Forbidden

    from hegemony_secret_vault.vault_client import VaultError

    backend, mock_client = _backend_with_mock_client()
    mock_client.secrets.kv.v2.read_configuration.side_effect = Forbidden()
    mock_client.secrets.kv.v2.list_secrets.side_effect = ConnectionError("boom")

    try:
        backend.test()
        raise AssertionError("expected VaultError")
    except VaultError:
        pass


# --- client construction hardening -------------------------------------------------


def _client_kwargs_for(**config_overrides) -> dict[str, Any]:
    config = VaultBackendConfig.from_dict({"address": "https://openbao:8200", **config_overrides})
    with patch("hvac.Client") as mock_client_cls:
        mock_client_cls.return_value = MagicMock()
        VaultSecretsBackend(config)
    return dict(mock_client_cls.call_args.kwargs)


def test_client_is_built_with_a_request_timeout():
    # Unbounded requests let an unresponsive server pin the calling thread indefinitely.
    assert _client_kwargs_for(token="tok")["timeout"] == 30
    assert _client_kwargs_for(token="tok", timeout=5)["timeout"] == 5


def test_client_is_built_with_the_configured_namespace():
    assert _client_kwargs_for(token="tok")["namespace"] is None
    assert _client_kwargs_for(token="tok", namespace="team-a")["namespace"] == "team-a"
    # Blank namespaces are normalized away rather than sent as an empty header.
    assert _client_kwargs_for(token="tok", namespace="  ")["namespace"] is None


def test_approle_auth_clears_any_ambient_environment_token():
    """hvac falls back to VAULT_TOKEN when constructed without a token.

    On the AppRole path that would let a stray environment variable authenticate this
    backend, and keep it working after the configured AppRole stopped being valid -- so
    the construction must clear it. The only token this backend may use is one it minted.
    """
    _, mock_client = _approle_backend_with_mock_client(role_id="rid", secret_id="sid")
    assert mock_client.token is None


def test_static_token_auth_still_sets_the_configured_token():
    _, mock_client = _backend_with_mock_client()
    assert mock_client.token == "tok"


def test_vault_backend_config_timeout_and_namespace_defaults():
    config = VaultBackendConfig(address="https://openbao:8200")
    assert config.timeout == 30
    assert config.namespace is None


def test_approle_login_stores_the_minted_client_token():
    # Load-bearing: the AppRole path starts from token=None, so if the minted token were
    # not stored the client would re-authenticate on every single operation.
    backend, mock_client = _approle_backend_with_mock_client(role_id="rid", secret_id="sid")
    mock_client.auth.approle.login.return_value = {
        "auth": {"lease_duration": 3600, "client_token": "minted-token"}
    }
    mock_client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {}}}

    backend.read("a/b")

    assert mock_client.token == "minted-token"


# --- config normalization and failure surfacing --------------------------------------


def test_timeout_accepts_numeric_strings_and_blank_values():
    # Backend config arrives as JSON from the host's database and may have been through
    # templating, so a bare int() here can meet whitespace and blow up opaquely.
    assert VaultBackendConfig.from_dict({"address": "https://openbao:8200"}).timeout == 30
    assert (
        VaultBackendConfig.from_dict({"address": "https://openbao:8200", "timeout": "45"}).timeout
        == 45
    )
    assert (
        VaultBackendConfig.from_dict({"address": "https://openbao:8200", "timeout": "  "}).timeout
        == 30
    )


def test_timeout_rejects_junk_and_non_positive_values():
    for bad in ("soon", 0, -5, "0"):
        try:
            VaultBackendConfig.from_dict({"address": "https://openbao:8200", "timeout": bad})
        except ValueError as exc:
            assert "timeout" in str(exc).lower(), bad
        else:
            raise AssertionError(f"expected ValueError for timeout={bad!r}")


def test_schema_timeout_default_matches_the_runtime_default():
    # Two hardcoded copies of the same number drift; the schema must derive from the one
    # the client actually applies.
    from hegemony_secret_vault.vault_client import DEFAULT_TIMEOUT_SECONDS

    reg = FakeRegistry()
    plugin.register(reg)
    properties = reg.types["vault"]["config_schema"]["properties"]
    assert properties["timeout"]["default"] == DEFAULT_TIMEOUT_SECONDS


def test_approle_login_without_a_token_raises_instead_of_looping():
    """A login that mints nothing must fail loudly.

    Left unchecked it leaves the client unauthenticated, so _is_token_valid stays false
    and every operation re-logs-in forever rather than surfacing the broken response.
    """
    from hegemony_secret_vault.vault_client import VaultAuthError

    backend, mock_client = _approle_backend_with_mock_client(role_id="rid", secret_id="sid")
    mock_client.token = None
    mock_client.auth.approle.login.return_value = {"auth": {"lease_duration": 3600}}

    try:
        backend.read("a/b")
    except VaultAuthError as exc:
        assert "client_token" in str(exc)
    else:
        raise AssertionError("expected VaultAuthError when the login returns no token")


def test_plaintext_address_is_rejected_without_an_explicit_opt_in():
    """A warning changed nothing; an http:// address now has to be asked for.

    Plain HTTP puts the AppRole secret ID and every secret value on the wire in the
    clear, and an address left on http:// after an upgrade would keep leaking silently.
    """
    config = VaultBackendConfig.from_dict({"address": "http://vault:8200", "token": "tok"})
    with patch("hvac.Client") as mock_client_cls:
        mock_client_cls.return_value = MagicMock()
        try:
            VaultSecretsBackend(config)
        except ValueError as exc:
            assert "allow_insecure_http" in str(exc)
            assert "http://vault:8200" in str(exc)
        else:
            raise AssertionError("expected a plain-HTTP address to be rejected")
    # The client is never built, so nothing can reach the network over cleartext.
    mock_client_cls.assert_not_called()


def test_plaintext_address_is_allowed_with_the_opt_in_but_still_warned_about(caplog):
    import logging

    config = VaultBackendConfig.from_dict(
        {"address": "http://vault:8200", "token": "tok", "allow_insecure_http": True}
    )
    with caplog.at_level(logging.WARNING), patch("hvac.Client") as mock_client_cls:
        mock_client_cls.return_value = MagicMock()
        VaultSecretsBackend(config)
    assert any("cleartext" in record.message for record in caplog.records)


def test_https_address_is_not_warned_about(caplog):
    import logging

    config = VaultBackendConfig.from_dict({"address": "https://openbao:8200", "token": "tok"})
    with caplog.at_level(logging.WARNING), patch("hvac.Client") as mock_client_cls:
        mock_client_cls.return_value = MagicMock()
        VaultSecretsBackend(config)
    assert not any("cleartext" in record.message for record in caplog.records)


def test_config_schema_exposes_the_plain_http_opt_in_defaulting_to_off():
    reg = FakeRegistry()
    plugin.register(reg)
    for backend_type in ("vault", "vault_kv2", "openbao"):
        field = reg.types[backend_type]["config_schema"]["properties"]["allow_insecure_http"]
        assert field["type"] == "boolean"
        assert field["default"] is False


def test_the_opt_in_is_not_needed_for_https():
    # The flag only widens what is accepted; it never has to be set on a secure address.
    config = VaultBackendConfig.from_dict({"address": "https://openbao:8200", "token": "tok"})
    assert config.allow_insecure_http is False


def test_client_does_not_follow_redirects():
    """The Vault token rides in X-Vault-Token, a custom header.

    requests only strips Authorization when a redirect crosses hosts, so a followed 3xx
    would hand the token to whatever host the Location names.
    """
    assert _client_kwargs_for(token="tok")["allow_redirects"] is False


def _redirect_response(location: str = "https://attacker.example/v1/") -> MagicMock:
    """A stand-in for what hvac returns for an unfollowed 3xx: the raw response."""
    response = MagicMock()
    response.status_code = 307
    response.headers = {"Location": location}
    return response


def test_a_redirected_read_raises_instead_of_returning_the_raw_response():
    from hegemony_secret_vault.vault_client import VaultError

    backend, mock_client = _backend_with_mock_client()
    mock_client.secrets.kv.v2.read_secret_version.return_value = _redirect_response()

    try:
        backend.read("a/b")
    except VaultError as exc:
        assert "307" in str(exc)
        assert "https://attacker.example/v1/" in str(exc)
    else:
        raise AssertionError("expected a redirect to surface as a VaultError")


def test_a_redirected_write_is_not_reported_as_a_success():
    """write() ignores its return value, so a redirect would look like a stored secret."""
    from hegemony_secret_vault.vault_client import VaultError

    backend, mock_client = _backend_with_mock_client()
    mock_client.secrets.kv.v2.create_or_update_secret.return_value = _redirect_response()

    try:
        backend.write("a/b", {"password": "hunter2"})
    except VaultError as exc:
        assert "307" in str(exc)
    else:
        raise AssertionError("expected a redirected write to fail loudly")


def test_a_redirected_delete_is_not_reported_as_a_success():
    from hegemony_secret_vault.vault_client import VaultError

    backend, mock_client = _backend_with_mock_client()
    mock_client.secrets.kv.v2.delete_metadata_and_all_versions.return_value = _redirect_response()

    try:
        backend.delete("a/b")
    except VaultError as exc:
        assert "307" in str(exc)
    else:
        raise AssertionError("expected a redirected delete to fail loudly")


def test_a_redirected_login_raises_instead_of_being_read_as_a_token():
    from hegemony_secret_vault.vault_client import VaultError

    backend, mock_client = _backend_with_mock_client(token=None, role_id="r", secret_id="s")
    mock_client.token = None
    mock_client.auth.approle.login.return_value = _redirect_response()

    try:
        backend.read("a/b")
    except VaultError as exc:
        assert "307" in str(exc)
    else:
        raise AssertionError("expected a redirected login to fail loudly")


def test_a_non_redirect_response_passes_through_untouched():
    backend, mock_client = _backend_with_mock_client()
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"password": "hunter2"}}
    }
    assert backend.read("a/b") == {"password": "hunter2"}


# -- Transit data-key wrapping (DataKeyWrappingSecretBackend) --


def test_vault_backend_satisfies_the_data_key_wrapping_protocol():
    from hegemony_secret_sdk import DataKeyWrappingSecretBackend

    backend, _client = _backend_with_mock_client()
    assert isinstance(backend, DataKeyWrappingSecretBackend)


def test_wrap_data_key_returns_plaintext_and_ciphertext():
    import base64

    backend, client = _backend_with_mock_client(transit_mount="kms")
    client.secrets.transit.generate_data_key.return_value = {
        "data": {"plaintext": base64.b64encode(b"k" * 32).decode(), "ciphertext": "vault:v1:abc"}
    }

    plaintext, wrapped = backend.wrap_data_key("hegemony-org-acme")

    assert plaintext == b"k" * 32
    assert wrapped == "vault:v1:abc"
    client.secrets.transit.generate_data_key.assert_called_once_with(
        name="hegemony-org-acme", key_type="plaintext", bits=256, mount_point="kms"
    )
    client.secrets.transit.create_key.assert_not_called()


def test_wrap_data_key_creates_a_missing_transit_key():
    import base64

    from hvac.exceptions import InvalidRequest

    backend, client = _backend_with_mock_client()
    client.secrets.transit.generate_data_key.side_effect = [
        InvalidRequest("encryption key not found"),
        {"data": {"plaintext": base64.b64encode(b"x" * 32).decode(), "ciphertext": "vault:v1:x"}},
    ]

    plaintext, _ = backend.wrap_data_key("hegemony-org-acme")

    assert plaintext == b"x" * 32
    client.secrets.transit.create_key.assert_called_once_with(
        name="hegemony-org-acme", key_type="aes256-gcm96", mount_point="transit"
    )
    assert client.secrets.transit.generate_data_key.call_count == 2


def test_wrap_data_key_reports_a_missing_mount_without_creating_a_key():
    """A missing or misnamed mount is a 404, not a missing key: nothing is created."""
    import pytest
    from hvac.exceptions import InvalidPath

    from hegemony_secret_vault.vault_client import VaultError

    backend, client = _backend_with_mock_client(transit_mount="trasit")
    client.secrets.transit.generate_data_key.side_effect = InvalidPath(
        'no handler for route "trasit/datakey/plaintext/hegemony-org-acme"'
    )
    with pytest.raises(VaultError, match="No Transit secrets engine at mount 'trasit'"):
        backend.wrap_data_key("hegemony-org-acme")
    client.secrets.transit.create_key.assert_not_called()


def test_wrap_data_key_refuses_a_key_of_the_wrong_size():
    import base64

    import pytest

    from hegemony_secret_vault.vault_client import VaultError

    backend, client = _backend_with_mock_client()
    client.secrets.transit.generate_data_key.return_value = {
        "data": {"plaintext": base64.b64encode(b"k" * 16).decode(), "ciphertext": "vault:v1:abc"}
    }
    with pytest.raises(VaultError, match="128-bit data key, expected 256 bits"):
        backend.wrap_data_key("hegemony-org-acme")


def test_transit_mount_is_normalized():
    for configured, expected in (
        (" transit/ ", "transit"),
        ("/kms/\n", "kms"),
        ("", "transit"),
        (None, "transit"),
    ):
        backend, _client = _backend_with_mock_client(transit_mount=configured)
        assert backend._config.transit_mount == expected, configured


def test_wrap_data_key_surfaces_other_errors():
    import pytest
    from hvac.exceptions import Forbidden

    from hegemony_secret_vault.vault_client import VaultError

    backend, client = _backend_with_mock_client()
    client.secrets.transit.generate_data_key.side_effect = Forbidden("permission denied")
    with pytest.raises(VaultError, match="permission denied"):
        backend.wrap_data_key("hegemony-org-acme")
    client.secrets.transit.create_key.assert_not_called()


def test_unwrap_data_key():
    import base64

    backend, client = _backend_with_mock_client()
    client.secrets.transit.decrypt_data.return_value = {
        "data": {"plaintext": base64.b64encode(b"d" * 32).decode()}
    }
    assert backend.unwrap_data_key("hegemony-org-acme", "vault:v1:abc") == b"d" * 32
    client.secrets.transit.decrypt_data.assert_called_once_with(
        name="hegemony-org-acme", ciphertext="vault:v1:abc", mount_point="transit"
    )


def test_transit_key_names_are_validated():
    import pytest

    backend, _client = _backend_with_mock_client()
    for bad in ("", "a/b", "../x", "x" * 129, "ok\n", "-x", "x-", "a.b"):
        with pytest.raises(ValueError, match="invalid Transit key name"):
            backend.wrap_data_key(bad)
        with pytest.raises(ValueError, match="invalid Transit key name"):
            backend.unwrap_data_key(bad, "vault:v1:abc")
    for good in ("x", "hegemony-org-00000000-0000-0000-0000-000000000001-tf-state", "x" * 128):
        assert backend._transit_key_name(good) == good
