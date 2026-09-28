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


def test_data_key_wrapping_backend_is_optional_extension():
    assert hasattr(sdk, "DataKeyWrappingSecretBackend")

    class _PlainBackend:
        def read(self, path):
            return None

        def write(self, path, data):
            return None

        def delete(self, path):
            return None

        def test(self):
            return None

    class _WrappingBackend(_PlainBackend):
        def wrap_data_key(self, key_name):
            return b"k" * 32, "wrapped"

        def unwrap_data_key(self, key_name, wrapped_key):
            return b"k" * 32

    assert not isinstance(_PlainBackend(), sdk.DataKeyWrappingSecretBackend)
    assert isinstance(_WrappingBackend(), sdk.DataKeyWrappingSecretBackend)
