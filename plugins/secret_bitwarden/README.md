<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-secret-bitwarden

[Vaultwarden](https://github.com/dani-garcia/vaultwarden) secret backend plugin
for Hegemony, packaged as an out-of-tree wheel. It is discovered at runtime via
the `hegemony.secret_backends` entry-point group
(`bitwarden = "hegemony_secret_bitwarden:register"`) and contributes one backend
type:

| Backend type | Notes |
|--------------|-------|
| `vaultwarden` | The items of one organization on a Vaultwarden server, addressed as `<collection>/<item>` |

Vaultwarden implements the client API of the Bitwarden password manager, so the
plugin is a small Bitwarden client. A self-hosted Bitwarden server serves the
same API under the same paths and should work, but only Vaultwarden is tested.

This is **not** a client for
[Bitwarden Secrets Manager](https://bitwarden.com/products/secrets-manager/)
(machine accounts and access tokens). That is a separate product with a separate
API, and Vaultwarden does not implement it.

## How it works

A Vaultwarden server stores only encrypted data. The client holds the keys, so
the plugin does what the Bitwarden apps do:

1. It logs in with the **personal API key** of a Vaultwarden user. An API key
   login needs no second factor, so it works unattended.
2. It derives that user's keys from the **master password**, which never leaves
   the Hegemony process, and uses them to decrypt the organization's key.
3. It downloads the vault and decrypts the names of the organization's
   collections and items; an item's values are decrypted only when it is read.

The crypto is composed from the standard primitives of
[`cryptography`](https://pypi.org/project/cryptography/) (PBKDF2 or Argon2id,
HKDF, AES-256-CBC with HMAC-SHA256, RSA-OAEP); see
[`crypto.py`](src/hegemony_secret_bitwarden/crypto.py). Every value is
authenticated before it is decrypted. Encryption types the plugin does not know
are refused with a clear error, never guessed at.

The client API is not a published, versioned contract, so a server upgrade can
change it. [`scripts/live_check_vaultwarden.py`](../../scripts/live_check_vaultwarden.py)
runs every backend operation against a real, throwaway server; the plugin was
last checked against Vaultwarden 1.37.5.

## Set up Vaultwarden

Use a **dedicated user**, not a person's account. Whoever holds this backend's
configuration can read everything that user can read.

1. Create a user for Hegemony (for example `hegemony@example.com`) and log in to
   the web vault once with it, so its keys exist.
2. Invite that user to your organization and confirm the membership. Give it
   access to only the collections Hegemony should see. Use read-only access
   ("Can view") if Hegemony should never change anything.
3. As that user, open **Settings → Security → Keys → View API key** and note the
   `client_id` (`user.<id>`) and the `client_secret`.

The plugin reads organization collections only. The user's personal vault is
ignored.

## Paths

A reference path is `<collection>/<item>`:

```text
{{ secret('vaultwarden://Network/Core Switch/password') }}
```

The portion after `scheme://` splits on the last `/`: everything before it is
the `path` passed to `read(path)`, here `Network/Core Switch`, and the final
segment is the `key` looked up in the item, here `password`.

- **Collection** and **item** are names. Names are case-sensitive and may
  contain spaces.
- Bitwarden nests collections by putting `/` in their names (`Network/Core`).
  The path `Network/Core/db` therefore means item `db` in collection
  `Network/Core`, or item `Core/db` in collection `Network`. The plugin accepts
  whichever exists.
- If a path matches more than one item, by either route or because two items
  share a name, the call fails. It never picks one. Use the item's id in place
  of its name (`Network/<item id>`), and likewise a collection's id in place of
  its name.
- An item is found only through a collection it is in.
- Items in the trash do not exist as far as the plugin is concerned.

Per the `SecretBackend` contract, `read` returns `None`, rather than raising,
when no collection and item match; a malformed `path` (not two non-empty parts)
raises `ValueError`.

## Fields

`read` returns a mapping of field name to value:

| Item type | Keys |
|---|---|
| Login | `username`, `password` |
| SSH key | `private_key`, `public_key`, `fingerprint` |
| any | `notes`, and every custom field under its own name |

- A custom field wins over a built-in key of the same name. When two custom
  fields share a name, the first one is used.
- Boolean custom fields read as `true` or `false`. Linked custom fields hold no
  value and are skipped.
- The one-time-password (TOTP) seed of a Login item is never returned.
- Card and Identity items expose only their notes and custom fields.

## Writing and deleting

- `write` to a path with no item creates a **Secure Note** in the collection,
  with one hidden custom field per key. When the path fits more than one
  collection, the one with the longest name gets the item.
- `write` to an existing Secure Note replaces its custom fields with the written
  ones (replace, not merge: the host deletes a key by writing the reduced
  mapping). Its name, notes and collections are left alone.
- `write` to an item of any other type is refused. Hegemony does not manage
  those items, and their secrets live in built-in fields the plugin does not
  write. Change them in Vaultwarden.
- `delete` moves the item to the organization's **trash**, from where it can be
  restored until the server purges it. Deleting a missing item is not an error.

To keep Hegemony from changing the vault at all, give the user read-only access
to its collections, and mark the backend read-only in its Hegemony settings.

## Multi-tenant (organization) path layout

Hegemony namespaces per-organization secrets as `orgs/<slug>/secrets/<folder>`
and enforces that confinement host-side, before any backend call. This backend
maps such a path like any other: it needs a collection whose name is a prefix of
it. A collection named `orgs/<slug>/secrets` per Hegemony organization gives
each one its own collection, with `<folder>` as the item name, and browsing
works because `list` walks collection names as a tree. A single collection named
`orgs` also works: every organization's items then share it and stay distinct by
name (`<slug>/secrets/<folder>`). The plugin does not create collections.

## Install

The wheel is **opt-in** — it is not bundled in the default images. See the root
[Install From A Release](../../README.md#install-from-a-release) guide for Docker
commands, checksum verification, and local-wheel development installs. Both the
**API** (to list/validate the backend type and resolve secrets) and the
**worker** (to resolve secrets at run time) need the wheel installed into
`/opt/venv`; restart both after installing so each registry reloads its entry
points.

The wheels are published on this repository's GitHub Releases, not on PyPI, so
`uv pip install hegemony-secret-bitwarden` finds nothing to install. For local
development, work from a checkout of this repository, where the package is a
workspace member:

```bash
uv sync --all-packages
```

This package depends only on [`hegemony-secret-sdk`](../../packages/secret_sdk),
[`cryptography`](https://pypi.org/project/cryptography/) and
[`httpx`](https://pypi.org/project/httpx/); it never imports Hegemony platform
internals.

## Configure

Create a secret backend of type `vaultwarden`. The form is schema-driven, so
each field below is rendered automatically, and the credential fields
(`client_secret`, `master_password`) get a secret/variable picker and refuse
plain text.

| Field | Required | Default | Notes |
|---|---|---|---|
| `server_url` | yes | — | Base address of the server, e.g. `https://vault.example.com` |
| `client_id` | yes | — | Personal API key id, `user.<id>` |
| `client_secret` | yes | — | Personal API key secret |
| `master_password` | yes | — | Master password of the user; used locally to decrypt, never sent |
| `organization` | yes | — | Name or id of the organization |
| `cache_ttl_seconds` | no | `30` | How long reads reuse a downloaded vault; `0` downloads on every read |
| `timeout` | no | `30` | Per-request timeout in seconds |
| `ca_cert_file` | no | — | Path to a CA certificate bundle for TLS verification |
| `verify_ssl` | no | `true` | Verify the server's TLS certificate |
| `allow_insecure_http` | no | `false` | Accept an `http://` address; only for a dev server |

```json
{
  "server_url": "https://vault.example.com",
  "client_id": "user.00000000-0000-0000-0000-000000000000",
  "client_secret": "{{ secret('vault://orgs/default/secrets/vaultwarden/client_secret') }}",
  "master_password": "{{ secret('vault://orgs/default/secrets/vaultwarden/master_password') }}",
  "organization": "Acme"
}
```

The credentials come from a bootstrap secret backend (any backend whose own
config uses `env()`/`file()` exclusively, such as the platform's internal
OpenBao) or from the environment with `{{ env('...') }}`.

## Operational notes

- **Caching.** The Bitwarden API has no "read one item by name": the plugin
  downloads the whole vault and searches it. Reads reuse that copy for
  `cache_ttl_seconds`, so a value changed in Vaultwarden can take that long to
  be seen. A read that finds nothing in a cached copy downloads a fresh one
  before answering, and writes and deletes always start from a fresh one.
- **Memory.** The decrypted organization key, and the names of the
  organization's collections and items, stay in the memory of the API and worker
  processes while the backend is configured. Item values are decrypted per read.
- **Logins.** Each API and worker process logs in when it first uses the
  backend, and again when its access token runs out (two hours on Vaultwarden).
  Testing the backend from its settings page logs in every time. Vaultwarden
  limits login attempts per address (`LOGIN_RATELIMIT_MAX_BURST`, ten by
  default); many workers starting at once behind one address can reach it.
- **New-device email.** The plugin reports one stable device per backend
  configuration, so a server with mail configured sends its "new device" notice
  once, not on every restart.
- **Rotation.** After changing the user's master password or API key in
  Vaultwarden, update the backend's configuration; the old values stop working.
  Changing only the key-derivation settings needs no change here.
- **Not supported.** Accounts without a master password (single sign-on only),
  accounts on the older unauthenticated encryption types, attachments, and
  one-time-password codes.
