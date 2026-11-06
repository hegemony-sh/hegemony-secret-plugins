<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

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
# In your plugin's pyproject.toml. The SDK is 0.x, where a breaking change
# releases a new minor version, so depend on one minor at a time.
[project]
dependencies = ["hegemony-secret-sdk>=0.3,<0.4"]

[project.entry-points."hegemony.secret_backends"]
my_plugin = "my_plugin:register"
```

## Backends are leaf components

Unlike notification transports, secret backends receive no injected services or
context from the host. A registered `factory` builds a concrete backend
instance directly from an already-resolved configuration dict:

```python
# my_plugin/__init__.py
from collections.abc import Mapping
from typing import Any

from hegemony_secret_sdk import SecretBackend, SecretBackendRegistry


class MyBackend:
    def __init__(self, config: dict) -> None:
        self._config = config

    def read(self, path: str) -> dict[str, str] | None: ...
    def write(self, path: str, data: Mapping[str, Any]) -> None: ...
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

A backend implements `read`, `write`, `delete`, and `test` (a lightweight connectivity/auth
check that raises on failure). See [`SecretBackend`](src/hegemony_secret_sdk/backend.py).

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

## API reference

Import public contracts from `hegemony_secret_sdk`. These are synchronous
Python interfaces, not HTTP endpoints or coroutines. The host resolves
configuration before calling the registered `BackendFactory(config)`, which
returns a `SecretBackend`.

`register_backend_type(...)` accepts keyword-only backend identity, display
name, description and factory, plus optional configuration model, schema,
defaults and hidden flag; it returns `None`. The model and schema are
independent: the host may use the model for validation and the schema for UI
rendering. The hidden flag requires host support.

| Backend method | Inputs | Result |
| --- | --- | --- |
| `read` | Secret path string | Mapping of secret fields, or `None` if absent |
| `write` | Path and mapping of fields | `None` |
| `delete` | Path | `None`; deleting an absent secret is not an error |
| `test` | No arguments | `None`; raises on connectivity/authentication failure |
| `list` (optional `ListableSecretBackend`) | Path, defaulting to the empty string | Immediate child names; containers end in `/`; unknown/empty locations return an empty list |
| `wrap_data_key` (optional `DataKeyWrappingSecretBackend`) | Wrapping-key name | Tuple of fresh 256-bit plaintext key bytes and wrapped-key string; creates a missing wrapping key |
| `unwrap_data_key` (optional `DataKeyWrappingSecretBackend`) | Wrapping-key name and wrapped-key string | Plaintext key bytes |

The host feature-detects the optional protocols. Data-key wrapping keeps the
wrapping key inside the store; the host stores the wrapped key alongside
encrypted data. Do not include plaintext secrets or data keys in logs or errors.
Backend failures raise exceptions; the SDK does not define a shared error
envelope. The [Vault/OpenBao](../../plugins/secret_vault/README.md) and
[1Password](../../plugins/secret_1password/README.md) references describe
backend configuration, path mapping and limitations.

From the repository root, render complete signatures and docstrings with:

```bash
uv sync --frozen --all-packages
uv run python -m pydoc hegemony_secret_sdk
uv run python -m pydoc hegemony_secret_sdk.backend
uv run python -m pydoc hegemony_secret_sdk.registry
```

For local HTML browsing, run `uv run python -m pydoc -b`, open the SDK module,
and follow its class/module links; stop the server when finished. With an
installed SDK, omit `uv run`.
