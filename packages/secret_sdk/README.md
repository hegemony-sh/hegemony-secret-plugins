<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-secret-sdk

Public, dependency-light SDK for building **Hegemony secret backend plugins** —
out-of-tree wheels that add secret storage backends to the core platform at
runtime.

A plugin depends only on this package (which depends only on `pydantic`) and
exposes a `register(registry)` callable under the
`hegemony.secret_backends` entry-point group:

```toml
# In your plugin's pyproject.toml
[project.entry-points."hegemony.secret_backends"]
my_plugin = "my_plugin:register"

[project]
# Pin the exact SDK version of the release you build against, as the plugins in
# this repository do; each release ships the SDK and its plugins together.
dependencies = ["hegemony-secret-sdk==0.2.0"]
```

## Backends are leaf components

Unlike notification transports, secret backends receive no injected services or
context from the host. A registered `factory` builds a concrete backend
instance directly from an already-resolved configuration dict:

```python
# my_plugin/__init__.py
from hegemony_secret_sdk import SecretBackend, SecretBackendRegistry


class MyBackend:
    def __init__(self, config: dict) -> None:
        self._config = config

    def read(self, path: str) -> dict[str, str] | None: ...
    def write(self, path: str, data: dict[str, str]) -> None: ...
    def delete(self, path: str) -> None: ...
    def test(self) -> None: ...


def build_my_backend(config: dict) -> MyBackend:
    return MyBackend(config)


def register(registry: SecretBackendRegistry) -> None:
    registry.register_backend_type(
        backend_type="my_backend",
        display_name="My Backend",
        description="Stores secrets in My Backend.",
        factory=build_my_backend,
        config_schema={
            "type": "object",
            "required": ["address"],
            "properties": {
                "address": {"type": "string", "title": "Server address"},
                "token": {"type": "string", "title": "Auth token", "x_secret_ref": True},
            },
        },
    )
```

A backend implements `read`, `write`, `delete`, and `test` (a lightweight
connectivity/auth check that raises on failure). See
[`SecretBackend`](src/hegemony_secret_sdk/backend.py).

### Optional capabilities

Two further protocols are optional. The host feature-detects them on the backend
*instance* (`hasattr`), so a backend that does not implement one simply does not get
the feature; nothing in the registration contract changes and `SDK_ABI_VERSION`
stays the same.

- [`ListableSecretBackend`](src/hegemony_secret_sdk/backend.py) adds
  `list(path="") -> list[str]`: the immediate children under `path`, containers
  ending in `/`. The host uses it to browse a backend in Settings and to discover
  secrets that exist in the backend but are not managed by Hegemony.
- [`VersionedSecretBackend`](src/hegemony_secret_sdk/backend.py) adds versioned reads
  and check-and-set writes. `read_versioned(path)` and `read_version(path, version)`
  return a `VersionedSecret` — the data plus the version it was read at; a latest
  version whose data was deleted comes back with empty data and `deleted=True`,
  because the path is still occupied. `versions(path)` lists `SecretVersion`
  entries, oldest first. `write_checked(path, data, expected_version=...)` writes
  only when the current version equals `expected_version` (`0` means "nothing
  stored yet") and returns the new version; otherwise it raises
  `VersionConflictError` and writes nothing. The host uses it to make a secret
  update fail with a conflict instead of silently overwriting a concurrent change.

### Config-schema extension keys

The host understands a few `x_`-prefixed property keys in `config_schema`:

- `x_secret_ref: true` — the field holds raw auth material; the host UI renders it
  with the secret/variable picker instead of a plain text input.
- `x_fallback_of: "<base field>"` — the field overrides `<base field>` when set; the
  host UI shows the inheritance relationship on the form.
- `x_component: "api" | "worker"` — combined with `x_fallback_of`, restricts the
  override to one host process: before calling the factory, the named process copies
  the field's value onto its base field and strips every `x_component`-marked field.
  Factories therefore only ever see base fields (see the vault plugin's
  `api_role_id`/`worker_role_id`, which let the API and worker authenticate with
  different AppRoles).

## ABI

`SDK_ABI_VERSION` is bumped only on incompatible changes to the registration
contract. The platform exposes its value as `registry.api_version` so a plugin
can self-gate if needed.
