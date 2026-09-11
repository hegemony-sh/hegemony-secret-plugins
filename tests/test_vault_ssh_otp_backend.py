# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the SSH one-time-password backend types: registration + behaviour via hvac mocks."""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import hegemony_secret_vault as plugin
from hegemony_secret_vault.ssh_otp_client import (
    VaultSshOtpBackend,
    VaultSshOtpConfig,
    _parse_otp_path,
    engine_role_name,
)
from hegemony_secret_vault.vault_client import VaultAuthError, VaultError


class FakeRegistry:
    api_version = 1

    def __init__(self) -> None:
        self.types: dict[str, dict[str, Any]] = {}

    def register_backend_type(self, *, backend_type: str, **kwargs: Any) -> None:
        self.types[backend_type] = kwargs


OTP_TYPES = ("vault_ssh_otp", "openbao_ssh_otp")


def _registered() -> dict[str, dict[str, Any]]:
    reg = FakeRegistry()
    plugin.register(reg)
    return reg.types


# --- registration --------------------------------------------------------------------


def test_register_adds_the_two_otp_types_beside_the_kv_types():
    types = _registered()
    assert set(types) == {"vault", "vault_kv2", "openbao", "vault_ssh_otp", "openbao_ssh_otp"}
    assert types["vault_ssh_otp"]["factory"] is plugin.build_vault_ssh_otp_backend
    assert types["openbao_ssh_otp"]["factory"] is plugin.build_openbao_ssh_otp_backend
    # Distinct callables, so OpenBao's construction can diverge without touching Vault.
    assert types["vault_ssh_otp"]["factory"] is not types["openbao_ssh_otp"]["factory"]
    for backend_type in OTP_TYPES:
        assert types[backend_type].get("hidden", False) is False
        assert types[backend_type]["config_schema"]["required"] == ["address"]
        assert types[backend_type]["description"]


def test_otp_display_names():
    types = _registered()
    assert types["vault_ssh_otp"]["display_name"] == "HashiCorp Vault (SSH one-time passwords)"
    assert types["openbao_ssh_otp"]["display_name"] == "OpenBao (SSH one-time passwords)"


def test_otp_schema_shares_the_auth_properties_with_the_kv_schema():
    # Same property names (and the same x_* markers) as the KV schema, so the host's
    # per-component AppRole overrides and its no-plaintext policy apply unchanged.
    types = _registered()
    kv = types["vault"]["config_schema"]["properties"]
    otp = types["vault_ssh_otp"]["config_schema"]["properties"]
    assert set(otp) == (set(kv) - {"kv_mount", "path_prefix"}) | {"ssh_mount"}
    for name, prop in kv.items():
        if name in ("kv_mount", "path_prefix"):
            continue
        for marker in ("x_secret_ref", "x_fallback_of", "x_component"):
            assert otp[name].get(marker) == prop.get(marker), (name, marker)
    assert otp["ssh_mount"]["default"] == "ssh"


def test_otp_schema_has_no_kv_mount():
    # The host drags every type whose schema declares kv_mount into the UI's KV folder
    # convention (tests/api/test_settings_secret_backend_types.py in the host repo); an
    # OTP backend stores nothing to put in a folder.
    types = _registered()
    for backend_type in OTP_TYPES:
        assert "kv_mount" not in types[backend_type]["config_schema"]["properties"]


def test_openbao_otp_schema_shares_property_names_with_vault_otp():
    types = _registered()
    vault_props = types["vault_ssh_otp"]["config_schema"]["properties"]
    openbao_props = types["openbao_ssh_otp"]["config_schema"]["properties"]
    assert set(vault_props) == set(openbao_props)
    assert vault_props["address"]["title"] == "Vault address"
    assert openbao_props["address"]["title"] == "OpenBao address"


def test_build_factories_return_otp_backends():
    with patch("hvac.Client") as mock_client_cls:
        mock_client_cls.return_value = MagicMock(token="tok")
        config = {"address": "https://vault:8200", "token": "tok"}
        assert isinstance(plugin.build_vault_ssh_otp_backend(config), VaultSshOtpBackend)
        assert isinstance(plugin.build_openbao_ssh_otp_backend(config), VaultSshOtpBackend)


# --- path grammar --------------------------------------------------------------------


def test_parse_otp_path_splits_the_five_segments():
    assert _parse_otp_path("orgs/acme/linux/10.0.0.5/ubuntu") == (
        "acme",
        "linux",
        "10.0.0.5",
        "ubuntu",
    )
    assert _parse_otp_path("orgs/acme-corp/db_hosts/2001:db8::5/postgres") == (
        "acme-corp",
        "db_hosts",
        "2001:db8::5",
        "postgres",
    )


@pytest.mark.parametrize(
    "path",
    [
        "orgs/acme/linux/10.0.0.5",  # four segments
        "orgs/acme/linux/10.0.0.5/ubuntu/key",  # six: the field is not part of the path
        "shared/acme/linux/10.0.0.5/ubuntu",  # not the orgs namespace
        "orgs//linux/10.0.0.5/ubuntu",  # empty segment
        "orgs/acme/linux-hosts/10.0.0.5/ubuntu",  # hyphen in the role
        "orgs/acme/linux/host.example/ubuntu",  # not an IP address
        "orgs/acme/linux/10.0.0.5/",  # empty username
    ],
)
def test_parse_otp_path_rejects_malformed_paths(path):
    with pytest.raises(ValueError):
        _parse_otp_path(path)


def test_hyphenated_roles_are_refused_because_the_engine_role_name_would_be_ambiguous():
    # Organization slugs may contain hyphens, so `a` + `b-c` and `a-b` + `c` would both
    # mint from the role `a-b-c`. With no hyphen in the role, the last hyphen always
    # separates slug from role.
    with pytest.raises(ValueError, match="hyphen"):
        _parse_otp_path("orgs/a/b-c/10.0.0.5/root")
    assert engine_role_name("a-b", "c") == "a-b-c"
    assert engine_role_name("acme", "linux") == "acme-linux"


# --- backend behaviour ---------------------------------------------------------------


def _otp_backend_with_mock_client(**config_overrides) -> tuple[VaultSshOtpBackend, MagicMock]:
    config = VaultSshOtpConfig.from_dict(
        {"address": "https://openbao:8200", "token": "tok", **config_overrides}
    )
    with patch("hvac.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        backend = VaultSshOtpBackend(config)
    return backend, mock_client


def _issued(**overrides: Any) -> dict[str, Any]:
    data = {
        "ip": "10.0.0.5",
        "key": "2f9c1d1e-6d8a-4a0b-9c1e-8f2a6b3c4d5e",
        "key_type": "otp",
        "port": 22,
        "username": "ubuntu",
    }
    data.update(overrides)
    return {"data": data, "lease_id": "", "lease_duration": 0}


def _redirect_response(location: str = "https://attacker.example/v1/") -> MagicMock:
    response = MagicMock()
    response.status_code = 307
    response.headers = {"Location": location}
    return response


def test_read_mints_from_the_org_scoped_role():
    backend, mock_client = _otp_backend_with_mock_client()
    mock_client.secrets.ssh.generate_ssh_credentials.return_value = _issued()

    result = backend.read("orgs/acme/linux/10.0.0.5/ubuntu")

    assert result == _issued()["data"]
    assert result["key"] == "2f9c1d1e-6d8a-4a0b-9c1e-8f2a6b3c4d5e"
    mock_client.secrets.ssh.generate_ssh_credentials.assert_called_once_with(
        name="acme-linux", username="ubuntu", ip="10.0.0.5", mount_point="ssh"
    )


def test_read_honours_a_custom_mount():
    backend, mock_client = _otp_backend_with_mock_client(ssh_mount="/ssh-otp/")
    mock_client.secrets.ssh.generate_ssh_credentials.return_value = _issued()
    backend.read("orgs/acme/linux/10.0.0.5/ubuntu")
    kwargs = mock_client.secrets.ssh.generate_ssh_credentials.call_args.kwargs
    assert kwargs["mount_point"] == "ssh-otp"


def test_config_falls_back_to_the_default_mount_when_blank():
    config = VaultSshOtpConfig.from_dict({"address": "https://openbao:8200", "ssh_mount": " "})
    assert config.ssh_mount == "ssh"


def test_every_read_mints_again():
    backend, mock_client = _otp_backend_with_mock_client()
    mock_client.secrets.ssh.generate_ssh_credentials.side_effect = [
        _issued(key="first"),
        _issued(key="second"),
    ]
    assert backend.read("orgs/acme/linux/10.0.0.5/ubuntu")["key"] == "first"
    assert backend.read("orgs/acme/linux/10.0.0.5/ubuntu")["key"] == "second"
    assert mock_client.secrets.ssh.generate_ssh_credentials.call_count == 2


def test_read_rejects_a_malformed_path_before_any_request():
    backend, mock_client = _otp_backend_with_mock_client()
    with pytest.raises(ValueError):
        backend.read("orgs/acme/linux-hosts/10.0.0.5/ubuntu")
    mock_client.secrets.ssh.generate_ssh_credentials.assert_not_called()


def test_read_never_returns_none_on_an_engine_error():
    from hvac.exceptions import InvalidRequest

    backend, mock_client = _otp_backend_with_mock_client()
    mock_client.secrets.ssh.generate_ssh_credentials.side_effect = InvalidRequest(
        errors=['unknown role "acme-linux"']
    )
    with pytest.raises(VaultError) as exc_info:
        backend.read("orgs/acme/linux/10.0.0.5/ubuntu")
    assert "acme-linux" in str(exc_info.value)
    assert "unknown role" in str(exc_info.value)


def test_read_surfaces_a_cidr_refusal_from_the_engine():
    from hvac.exceptions import InvalidRequest

    backend, mock_client = _otp_backend_with_mock_client()
    mock_client.secrets.ssh.generate_ssh_credentials.side_effect = InvalidRequest(
        errors=["ip '203.0.113.9' does not belong to the CIDR ranges of the role"]
    )
    with pytest.raises(VaultError, match="CIDR"):
        backend.read("orgs/acme/linux/203.0.113.9/ubuntu")


def test_read_names_the_mount_when_the_engine_is_not_mounted():
    from hvac.exceptions import InvalidPath

    backend, mock_client = _otp_backend_with_mock_client(ssh_mount="ssh-otp")
    mock_client.secrets.ssh.generate_ssh_credentials.side_effect = InvalidPath(
        "no handler for route 'ssh-otp/creds/acme-linux'"
    )
    with pytest.raises(VaultError) as exc_info:
        backend.read("orgs/acme/linux/10.0.0.5/ubuntu")
    assert "'ssh-otp'" in str(exc_info.value)
    assert "not mounted" in str(exc_info.value) or "mounted at" in str(exc_info.value)


def test_read_refuses_a_redirected_issue():
    backend, mock_client = _otp_backend_with_mock_client()
    mock_client.secrets.ssh.generate_ssh_credentials.return_value = _redirect_response()
    with pytest.raises(VaultError) as exc_info:
        backend.read("orgs/acme/linux/10.0.0.5/ubuntu")
    assert "307" in str(exc_info.value)
    assert "attacker.example" in str(exc_info.value)


def test_read_without_a_key_in_the_answer_is_an_error():
    backend, mock_client = _otp_backend_with_mock_client()
    answer = _issued()
    del answer["data"]["key"]
    mock_client.secrets.ssh.generate_ssh_credentials.return_value = answer
    with pytest.raises(VaultError, match="key_type otp"):
        backend.read("orgs/acme/linux/10.0.0.5/ubuntu")


def test_write_and_delete_refuse():
    backend, _ = _otp_backend_with_mock_client()
    with pytest.raises(VaultError, match="read-only"):
        backend.write("orgs/acme/linux/10.0.0.5/ubuntu", {"key": "x"})
    with pytest.raises(VaultError, match="read-only"):
        backend.delete("orgs/acme/linux/10.0.0.5/ubuntu")


def test_backend_has_no_list_and_is_a_plain_secret_backend():
    from hegemony_secret_sdk import ListableSecretBackend, SecretBackend

    backend, _ = _otp_backend_with_mock_client()
    # The host feature-detects browsing with hasattr(client, "list"); an inherited helper
    # would flip an OTP backend into browsing mode against a mount it does not have.
    assert not hasattr(backend, "list")
    assert isinstance(backend, SecretBackend)
    assert not isinstance(backend, ListableSecretBackend)


def test_test_proves_the_token_and_tolerates_a_forbidden_role_listing():
    from hvac.exceptions import Forbidden

    backend, mock_client = _otp_backend_with_mock_client()
    mock_client.secrets.ssh.list_roles.side_effect = Forbidden("permission denied")
    backend.test()
    mock_client.auth.token.lookup_self.assert_called_once_with()
    mock_client.secrets.ssh.list_roles.assert_called_once_with(mount_point="ssh")


def test_test_tolerates_an_engine_with_no_roles_yet():
    from hvac.exceptions import InvalidPath

    backend, mock_client = _otp_backend_with_mock_client()
    mock_client.secrets.ssh.list_roles.side_effect = InvalidPath()
    backend.test()


def test_test_fails_when_the_engine_is_not_mounted():
    from hvac.exceptions import InvalidPath

    backend, mock_client = _otp_backend_with_mock_client()
    mock_client.secrets.ssh.list_roles.side_effect = InvalidPath(
        "no handler for route 'ssh/roles/'"
    )
    with pytest.raises(VaultError, match="'ssh'"):
        backend.test()


def test_test_fails_when_the_token_is_rejected():
    from hvac.exceptions import Forbidden

    backend, mock_client = _otp_backend_with_mock_client()
    mock_client.auth.token.lookup_self.side_effect = Forbidden("permission denied")
    with pytest.raises(VaultAuthError):
        backend.test()
    mock_client.secrets.ssh.list_roles.assert_not_called()


def test_test_fails_on_a_connection_error():
    backend, mock_client = _otp_backend_with_mock_client()
    mock_client.secrets.ssh.list_roles.side_effect = ConnectionError("connection refused")
    with pytest.raises(VaultError):
        backend.test()


def test_test_never_mints():
    backend, mock_client = _otp_backend_with_mock_client()
    backend.test()
    mock_client.secrets.ssh.generate_ssh_credentials.assert_not_called()


def test_test_refuses_a_redirected_token_lookup():
    backend, mock_client = _otp_backend_with_mock_client()
    mock_client.auth.token.lookup_self.return_value = _redirect_response()
    with pytest.raises(VaultError, match="307"):
        backend.test()


# --- inherited hardening (one test per behaviour; the KV suite covers the rest) ------


def test_plaintext_address_is_rejected_for_the_otp_backend():
    config = VaultSshOtpConfig.from_dict({"address": "http://openbao:8200", "token": "tok"})
    with (
        patch("hvac.Client") as mock_client_cls,
        pytest.raises(ValueError, match="allow_insecure_http"),
    ):
        VaultSshOtpBackend(config)
    mock_client_cls.assert_not_called()


def test_approle_login_is_reused_across_mints():
    config = VaultSshOtpConfig.from_dict(
        {"address": "https://openbao:8200", "role_id": "rid", "secret_id": "sid"}
    )
    with patch("hvac.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        backend = VaultSshOtpBackend(config)
    mock_client.auth.approle.login.return_value = {
        "auth": {"lease_duration": 3600, "client_token": "minted-token"}
    }
    mock_client.secrets.ssh.generate_ssh_credentials.return_value = _issued()

    backend.read("orgs/acme/linux/10.0.0.5/ubuntu")
    backend.read("orgs/acme/linux/10.0.0.5/ubuntu")

    assert mock_client.auth.approle.login.call_count == 1
    assert mock_client.token == "minted-token"


def test_client_is_built_without_redirects_and_with_the_shared_transport_settings():
    config = VaultSshOtpConfig.from_dict(
        {
            "address": "https://openbao:8200",
            "token": "tok",
            "namespace": "team-a",
            "timeout": "15",
            "ca_cert_file": "/openbao/tls/ca.crt",
        }
    )
    with patch("hvac.Client") as mock_client_cls:
        mock_client_cls.return_value = MagicMock()
        VaultSshOtpBackend(config)
    kwargs = mock_client_cls.call_args.kwargs
    assert kwargs["allow_redirects"] is False
    assert kwargs["namespace"] == "team-a"
    assert kwargs["timeout"] == 15
    assert kwargs["verify"] == "/openbao/tls/ca.crt"
