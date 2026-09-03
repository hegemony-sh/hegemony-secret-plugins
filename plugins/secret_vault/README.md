<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-secret-vault

HashiCorp Vault and OpenBao secret backend plugin for Hegemony, packaged as an
out-of-tree wheel. It is discovered at runtime via the
`hegemony.secret_backends` entry-point group
(`vault = "hegemony_secret_vault:register"`) and contributes three backend type
strings:

| Backend type | Display name | Notes |
|--------------|--------------|-------|
| `vault` | HashiCorp Vault (KV v2) | Generic, preferred Vault KV v2 backend |
| `vault_kv2` | HashiCorp Vault (KV v2, legacy type) | Legacy alias of `vault` (same client); registered **hidden** — existing backends of this type keep working, but it no longer appears in the create-form type picker |
| `openbao` | OpenBao (KV v2) | [OpenBao](https://openbao.org), the Linux Foundation fork of Vault. Used by the host's bundled internal backend |

All three types build the same `VaultSecretsBackend`, which supports static
token auth (dev mode) and AppRole auth (production), with thread-safe token
caching and automatic re-authentication.

## Why OpenBao is a separate type, not a separate client

OpenBao keeps Vault's HTTP API — the `X-Vault-Token` header, the KV v2 paths and
the AppRole login are unchanged — so `hvac` talks to both and one client serves
them. The separate type string exists so the host UI names the product honestly,
and so the two can diverge later without migrating existing backend rows. The
config schemas are identical in every property *name*; only the labels differ.

Secret backends are leaf components: unlike notification transports, the host
injects no services or context into a backend. The registered `factory`
receives only an already-resolved configuration dict and returns a backend
instance whose `read`/`write`/`test` methods talk directly to Vault.

This package depends only on [`hegemony-secret-sdk`](../../packages/secret_sdk)
and [`hvac`](https://pypi.org/project/hvac/) (the official HashiCorp Vault
client); it never imports Hegemony platform internals.

## Install

The wheel is **auto-installed** with the platform — it is already bundled in the
default Hegemony API and worker images, so no separate install step is needed
there. See the root [Install From A Release](../../README.md#install-from-a-release)
guide for Docker commands, checksum verification, and local-wheel development
installs if you need to install or upgrade it manually. Both the **API** (to
list/validate the backend type and resolve secrets) and the **worker** (to
resolve secrets at run time) need the wheel installed into `/opt/venv`; restart
both after installing so each registry reloads its entry points.

For local development against this repository:

```bash
uv pip install hegemony-secret-vault
```

## Configure

Create a secret backend of type `vault` pointing at your Vault server. The form
is schema-driven, so each field below is rendered automatically and
auth-material fields (`token`, `role_id`, `secret_id`, `api_role_id`,
`api_secret_id`, `worker_role_id`, `worker_secret_id`) get a secret/variable
picker. The `api_*`/`worker_*` override fields carry an `x_fallback_of` schema
key naming the base field they override, so the host form can show which value
they inherit when left empty.

The `*_file` fields are **paths**, not credentials, so they are deliberately not
marked as auth material: the host requires auth-material fields to be placeholder
expressions rather than literal values, which would make a filesystem path
unusable.

| Field | Required | Default | Notes |
|---|---|---|---|
| `address` | yes | — | Vault server address, e.g. `http://vault:8200` |
| `kv_mount` | no | `hegemony` | KV mount point |
| `path_prefix` | no | — | Optional prefix applied to all secret paths |
| `token` | no | — | Static Vault token (dev mode). Takes precedence over AppRole |
| `role_id` / `secret_id` | no | — | AppRole credentials (production auth) |
| `role_id_file` / `secret_id_file` | no | — | Paths to files containing the AppRole role/secret ID, as an alternative to inline values. Prefer these when credentials are rotated — see [Rotating AppRole credentials](#rotating-approle-credentials) |
| `api_role_id` / `api_secret_id` | no | — | Per-component AppRole override for the **API** process; remapped to `role_id`/`secret_id` before the client is built. Set these when the API and worker authenticate with different AppRoles |
| `worker_role_id` / `worker_secret_id` | no | — | Per-component AppRole override for the **worker** process; remapped to `role_id`/`secret_id` before the client is built |
| `api_role_id_file` / `api_secret_id_file` | no | — | Per-component override of `role_id_file`/`secret_id_file` for the **API** process |
| `worker_role_id_file` / `worker_secret_id_file` | no | — | Per-component override of `role_id_file`/`secret_id_file` for the **worker** process |
| `namespace` | no | — | Namespace to scope every request to. An OpenBao feature (and a Vault Enterprise one); leave empty otherwise |
| `timeout` | no | `30` | Per-request timeout in seconds |
| `ca_cert_file` | no | — | Optional path to a CA certificate bundle for TLS verification |
| `verify_ssl` | no | `true` | Verify the TLS certificate |

Exactly one auth method must resolve: a static `token`, or an AppRole pair
(`role_id`/`role_id_file` plus `secret_id`/`secret_id_file`). Registering the
backend fails with a clear error if neither is configured. The `api_*`/`worker_*`
overrides are applied by the host before the backend factory runs, so from the
plugin's perspective the resolved config always uses the plain
`role_id`/`secret_id` and `role_id_file`/`secret_id_file` keys.

### Rotating AppRole credentials

Inline `role_id`/`secret_id` values are read once, when the host builds the
client. A deployment that rotates AppRole secret IDs must use the `*_file`
fields instead: the client re-resolves them on **every** authentication, so a
rotated file is picked up without rebuilding the backend or restarting the
process. Give the API and worker their own files (`api_secret_id_file` /
`worker_secret_id_file`) when they hold separate AppRoles.

Set a `secret_id_ttl` on the role and re-mint before it expires. Leave a grace
period before destroying the superseded secret-ID accessor, so a process that
has not yet re-read the file does not fail authentication mid-flight.

Minimal config (dev mode, static token):

```json
{
  "address": "http://vault:8200",
  "token": "{{ env('VAULT_TOKEN') }}"
}
```

AppRole (production):

```json
{
  "address": "https://vault.example.com:8200",
  "kv_mount": "hegemony",
  "role_id": "{{ env('VAULT_ROLE_ID') }}",
  "secret_id": "{{ env('VAULT_SECRET_ID') }}"
}
```

## Usage

Once a `vault` (or legacy `vault_kv2`) backend is registered under a name
(the *scheme*, e.g. `vault`), reference secrets stored in it from any Hegemony
template field with:

```text
{{ secret('vault://orgs/default/secrets/db/password') }}
```

The portion after `scheme://` splits on the last `/`: everything before it is
the `path` passed to `read(path)` (here `orgs/default/secrets/db`, the KV
secret path under `kv_mount`), and the final segment is the `key` looked up in
the returned field mapping (here `password`). `write(path, data)` follows the
same path convention when secrets are managed through the Hegemony API rather
than directly in Vault.
