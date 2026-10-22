<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-secret-1password

1Password secret backend plugin for Hegemony, packaged as an out-of-tree wheel.
It is discovered at runtime via the `hegemony.secret_backends` entry-point group
(`onepassword = "hegemony_secret_1password:register"`) and contributes two
backend types:

| Backend type | Notes |
|--------------|-------|
| `onepassword_connect` | Authenticates against a self-hosted [1Password Connect](https://developer.1password.com/docs/connect/) server |
| `onepassword_service_account` | Authenticates with a [1Password Service Account](https://developer.1password.com/docs/service-accounts/) token |

Both types resolve a `{{ secret('scheme://vault/item/field') }}` reference's
`path` as `"<vault>/<item>"` (vault title/id and item title/id, split on the
first `/`) and return a mapping of item field name to field value. Per the
`SecretBackend` contract, `read` returns `None` — rather than raising — when
the vault or item cannot be found; a malformed `path` (not exactly two
non-empty parts) still raises `ValueError`, since that is an input error
rather than a missing secret.

## Multi-tenant (organization) path layout

Hegemony namespaces per-organization secrets as `orgs/<slug>/secrets/<folder>`
and enforces that confinement host-side, before any backend call. Under the
split-on-first-`/` rule above such a path maps to the 1Password vault named
`orgs` with the item title `"<slug>/secrets/<folder>"`: reads and writes work
and stay distinct per organization (the slug is part of the item title), but
every organization's items land in that single `orgs` vault, and `list` does
not browse below one path segment, so backend folder discovery is unavailable
for org namespaces. For multi-tenant deployments prefer the Vault backend
(which maps the org namespace onto a real path hierarchy), or register a
dedicated 1Password backend per organization.

Secret backends are leaf components: unlike notification transports, the host
injects no services or context into a backend. The registered `factory` receives
only an already-resolved configuration dict and returns a backend instance whose
`read`/`write`/`delete`/`list`/`test` methods talk directly to 1Password. Writes
upsert an item at `"<vault>/<item>"`: a new item is created as a Secure Note whose
concealed custom fields are the written keys, and an existing item has its fields
replaced. To prevent Hegemony from modifying a 1Password vault, mark the configured
backend as read-only in its Hegemony backend settings.

The Service Account backend wraps the official `onepassword-sdk`, which is
asynchronous; it authenticates and runs all subsequent SDK calls on a dedicated
background event-loop thread so its synchronous methods remain safe to call even
from inside a host event loop.

This package depends only on [`hegemony-secret-sdk`](../../packages/secret_sdk),
[`onepasswordconnectsdk`](https://pypi.org/project/onepasswordconnectsdk/) (the
official Connect client, used by `onepassword_connect`), and
[`onepassword-sdk`](https://pypi.org/project/onepassword-sdk/) (the official
Service Account SDK, used by `onepassword_service_account`); it never imports
Hegemony platform internals. Both third-party SDKs are pulled in as direct
dependencies of this wheel — no separate install step is needed for either
backend type.

## Install

The wheel is **opt-in** — it is not bundled in the default images. See the root
[Install From A Release](../../README.md#install-from-a-release) guide for Docker
commands, checksum verification, and local-wheel development installs. Both the
**API** (to list/validate the backend type and resolve secrets) and the
**worker** (to resolve secrets at run time) need the wheel installed into
`/opt/venv`; restart both after installing so each registry reloads its entry
points.

The wheels are published on this repository's GitHub Releases, not on PyPI, so
`uv pip install hegemony-secret-1password` finds nothing to install. For local development, work
from a checkout of this repository, where the package is a workspace member:

```bash
uv sync --all-packages
```

## Configure

Create a secret backend using whichever type matches your 1Password
deployment. The form is schema-driven, so each field below is rendered
automatically and auth-material fields (`connect_token`,
`service_account_token`) get a secret/variable picker.

### `onepassword_connect`

Requires a running [1Password Connect server](https://developer.1password.com/docs/connect/)
and an issued Connect API token (a Connect *access token*, not an account
password).

| Field | Required | Default | Notes |
|---|---|---|---|
| `connect_host` | yes | — | 1Password Connect server address, e.g. `https://connect.example.com` |
| `connect_token` | yes | — | Connect API token |

```json
{
  "connect_host": "https://connect.example.com",
  "connect_token": "{{ env('OP_CONNECT_TOKEN') }}"
}
```

### `onepassword_service_account`

Requires a [1Password Service Account](https://developer.1password.com/docs/service-accounts/)
token (`ops_...`) with access to the vaults it should read from. No separate
host to run — the SDK talks to 1Password's cloud API directly.

| Field | Required | Default | Notes |
|---|---|---|---|
| `service_account_token` | yes | — | 1Password Service Account token, e.g. `ops_...` |
| `integration_name` | no | `Hegemony` | Integration name reported to 1Password |

```json
{
  "service_account_token": "{{ env('OP_SERVICE_ACCOUNT_TOKEN') }}"
}
```

Auth tokens may also come from a bootstrap secret backend instead of the
environment: any backend whose own config uses `env()`/`file()` exclusively
(e.g. the platform's internal Vault) can be referenced with
`{{ secret('vault://orgs/default/secrets/op/token') }}`.

## Usage

Once a backend of either type is registered under a name (the *scheme*, e.g.
`onepassword`), reference an item field from any Hegemony template field with:

```text
{{ secret('onepassword://Engineering/Database/password') }}
```

The portion after `scheme://` splits on the last `/`: everything before it is
the `path` passed to `read(path)` — here `Engineering/Database`, split on the
first `/` into vault (`Engineering`) and item (`Database`) title-or-id — and
the final segment is the `key` looked up by field name in the item (here
`password`). Both backend types also implement `write` — it upserts the item at
`path` (creating a Secure Note, or replacing an existing Secure Note's fields),
as described above; mark the backend read-only in its Hegemony settings to keep
a 1Password vault from being modified.
