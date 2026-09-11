# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Contract tests for the secret backend SDK."""

import subprocess
import sys

import hegemony_secret_sdk as sdk


def test_public_surface_is_exported():
    assert sdk.SECRET_BACKEND_ENTRY_POINT_GROUP == "hegemony.secret_backends"
    assert isinstance(sdk.SDK_ABI_VERSION, int)
    assert hasattr(sdk, "SecretBackend")
    assert hasattr(sdk, "ListableSecretBackend")
    assert hasattr(sdk, "SecretBackendRegistry")
    assert hasattr(sdk, "BackendFactory")
    assert hasattr(sdk, "VersionedSecretBackend")
    assert hasattr(sdk, "VersionedSecret")
    assert hasattr(sdk, "SecretVersion")
    assert hasattr(sdk, "VersionConflictError")


def test_secret_backend_is_runtime_checkable_protocol():
    class _Backend:
        def read(self, path: str):
            return None

        def write(self, path: str, data) -> None:
            return None

        def delete(self, path: str) -> None:
            return None

        def test(self) -> None:
            return None

    assert isinstance(_Backend(), sdk.SecretBackend)


def test_listable_backend_is_optional_extension():
    class _PlainBackend:
        def read(self, path: str):
            return None

        def write(self, path: str, data) -> None:
            return None

        def delete(self, path: str) -> None:
            return None

        def test(self) -> None:
            return None

    class _ListableBackend(_PlainBackend):
        def list(self, path: str = "") -> list[str]:
            return []

    assert isinstance(_PlainBackend(), sdk.SecretBackend)
    assert not isinstance(_PlainBackend(), sdk.ListableSecretBackend)
    assert isinstance(_ListableBackend(), sdk.ListableSecretBackend)


def test_versioned_backend_is_optional_extension():
    class _PlainBackend:
        def read(self, path: str):
            return None

        def write(self, path: str, data) -> None:
            return None

        def delete(self, path: str) -> None:
            return None

        def test(self) -> None:
            return None

    class _VersionedBackend(_PlainBackend):
        def read_versioned(self, path: str):
            return None

        def read_version(self, path: str, version: int):
            return None

        def versions(self, path: str) -> list[sdk.SecretVersion]:
            return []

        def write_checked(self, path: str, data, *, expected_version: int) -> int:
            return expected_version + 1

    assert isinstance(_PlainBackend(), sdk.SecretBackend)
    assert not isinstance(_PlainBackend(), sdk.VersionedSecretBackend)
    assert isinstance(_VersionedBackend(), sdk.VersionedSecretBackend)


def test_version_conflict_error_carries_path_and_expected_version():
    exc = sdk.VersionConflictError("orgs/acme/secrets/db", 3)
    assert isinstance(exc, Exception)
    assert exc.path == "orgs/acme/secrets/db"
    assert exc.expected_version == 3
    assert "orgs/acme/secrets/db" in str(exc)
    assert "3" in str(exc)


def test_versioned_secret_dataclasses_are_frozen_values():
    secret = sdk.VersionedSecret(data={"k": "v"}, version=2, created_at="2026-01-01T00:00:00Z")
    assert secret.deleted is False
    version = sdk.SecretVersion(version=2, created_at=None, deleted=False, destroyed=False)
    assert version == sdk.SecretVersion(version=2, created_at=None, deleted=False, destroyed=False)


def test_registry_is_runtime_checkable_protocol():
    class _Impl:
        api_version = sdk.SDK_ABI_VERSION

        def register_backend_type(self, **_kwargs):
            return None

    assert isinstance(_Impl(), sdk.SecretBackendRegistry)


def test_sdk_imports_nothing_heavy():
    """Importing the SDK must not pull FastAPI, SQLAlchemy, Temporal, or the platform."""
    code = (
        "import sys, hegemony_secret_sdk\n"
        "heavy = {'fastapi', 'sqlalchemy', 'temporalio', 'apps', 'packages'}\n"
        "leaked = heavy & set(sys.modules)\n"
        "assert not leaked, leaked\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
