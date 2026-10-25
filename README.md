<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-secret-plugins

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/License-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![CI](https://github.com/hegemony-sh/hegemony-secret-plugins/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/hegemony-sh/hegemony-secret-plugins/actions/workflows/ci.yml)
[![REUSE status](https://api.reuse.software/badge/github.com/hegemony-sh/hegemony-secret-plugins)](https://api.reuse.software/info/github.com/hegemony-sh/hegemony-secret-plugins)
[![Latest release](https://img.shields.io/github/v/release/hegemony-sh/hegemony-secret-plugins?label=Release)](https://github.com/hegemony-sh/hegemony-secret-plugins/releases)
[![FOSSA license scan](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fhegemony-sh%2Fhegemony-secret-plugins.svg?type=shield&issueType=license)](https://app.fossa.com/projects/git%2Bgithub.com%2Fhegemony-sh%2Fhegemony-secret-plugins?ref=badge_shield&issueType=license)
[![FOSSA security scan](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fhegemony-sh%2Fhegemony-secret-plugins.svg?type=shield&issueType=security)](https://app.fossa.com/projects/git%2Bgithub.com%2Fhegemony-sh%2Fhegemony-secret-plugins?ref=badge_shield&issueType=security)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/hegemony-sh/hegemony-secret-plugins/badge)](https://scorecard.dev/viewer/?uri=github.com/hegemony-sh/hegemony-secret-plugins)



Secret-backend SDK and plugin wheels for [Hegemony](https://github.com/hegemony-sh/hegemony),
a self-hosted orchestration platform for long-running infrastructure changes.
Hegemony flows carry secret *references*, such as `{{ secret('vault://orgs/default/secrets/db/password') }}`,
never values; a secret backend is what resolves a reference at run time.

| Package | What it is |
| --- | --- |
| [`hegemony-secret-sdk`](packages/secret_sdk/README.md) | The public SDK a backend is written against: the `SecretBackend` protocol, the registry and the entry-point group. Depends only on `pydantic`. |
| [`hegemony-secret-vault`](plugins/secret_vault/README.md) | HashiCorp Vault and OpenBao KV v2 backends (`vault`, the hidden legacy alias `vault_kv2`, and `openbao`), plus optional Transit data-key wrapping. |
| [`hegemony-secret-1password`](plugins/secret_1password/README.md) | 1Password backends: `onepassword_connect` (Connect server) and `onepassword_service_account`. |

The SDK and all plugin wheels are released together under one semver tag such as
`v0.3.1`, cut automatically when a releasable change merges to `main`. Plugin wheels depend on the exact SDK version from the same release.

A plugin depends only on `hegemony-secret-sdk` (which depends only on `pydantic`) and
exposes a `register(registry)` callable under the `hegemony.secret_backends`
entry-point group. Secret backends are leaf components — the host injects no services or
context into them; a registered factory receives only an already-resolved configuration
dict and returns a backend instance directly. See the
[SDK README](packages/secret_sdk/README.md).

## How this relates to Hegemony

The platform, [`hegemony-sh/hegemony`](https://github.com/hegemony-sh/hegemony),
owns the secret references, the Settings → Secret Backends screens and the
registry that loads plugins. This repository owns the backends and the SDK they
register through, so a backend can be released, and installed, without a
platform release.

- The platform pins this repository by release tag and commit in its
  `.github/plugin-pins.json`, and builds `hegemony-secret-sdk` and
  `hegemony-secret-vault` into its API and worker images from a checkout at
  that tag.
- Version numbers here are independent of the platform's. These packages have
  their own 0.x line, so a platform release does not imply a release here.
- The other plugin kinds live in sibling repositories:
  [`hegemony-step-plugins`](https://github.com/hegemony-sh/hegemony-step-plugins),
  [`hegemony-inventory-plugins`](https://github.com/hegemony-sh/hegemony-inventory-plugins) and
  [`hegemony-notification-plugins`](https://github.com/hegemony-sh/hegemony-notification-plugins).

## What is auto-installed vs opt-in

- **Auto-installed** with the platform (already present in Hegemony API and worker
  images): `hegemony-secret-sdk` and `hegemony-secret-vault` (the built-in KV v2
  backends — `vault`, the hidden legacy alias `vault_kv2`, and `openbao`). One `hvac`
  client serves both products because OpenBao keeps Vault's HTTP API. See its
  [README](plugins/secret_vault/README.md).
- **Opt-in**: `hegemony-secret-1password` adds the 1Password backend
  (`onepassword_connect` / `onepassword_service_account` backend types). Install it in any
  deployment that wants a 1Password-backed secrets backend. See its
  [README](plugins/secret_1password/README.md).

Both the **API** (to list/validate the backend type and resolve secrets) and the
**worker** (to resolve secrets at run time) must have an opt-in plugin installed to use it.
Restart both after installing so each registry reloads its entry points. Do not use
`--system`; Hegemony runs from `/opt/venv`.

## Install From A Release

Released wheels are published with a `SHA256SUMS` file. Verify downloaded wheels before
installing them. `hegemony-secret-sdk` and `hegemony-secret-vault` are already in the API
and worker images, so only the opt-in `hegemony-secret-1password` wheel is installed here.
It is installed *with* dependencies so its 1Password SDKs (`onepasswordconnectsdk`,
`onepassword-sdk`) are pulled in.

```bash
VERSION=<release version without the v, for example 0.3.1>
API_CONTAINER=<your API container name>
WORKER_CONTAINER=<your worker container name>

for CONTAINER in "${API_CONTAINER}" "${WORKER_CONTAINER}"; do
  docker exec -u root -it "${CONTAINER}" bash -lc "
set -euo pipefail
version=${VERSION}
base=https://github.com/hegemony-sh/hegemony-secret-plugins/releases/download/v\${version}
tmp=\$(mktemp -d)
cd \"\${tmp}\"
curl -fsSLO \"\${base}/SHA256SUMS\"
for wheel in \
  hegemony_secret_1password-\${version}-py3-none-any.whl
do
  curl -fsSLO \"\${base}/\${wheel}\"
  grep \"  \${wheel}$\" SHA256SUMS | sha256sum -c -
done
uv pip install --python /opt/venv/bin/python ./*.whl
rm -rf \"\${tmp}\"
"
  docker restart "${CONTAINER}"
done
```

For a stronger supply-chain guarantee than checksums alone, also verify the build
provenance attestation generated by the release workflow (requires the `gh` CLI):

```bash
gh attestation verify hegemony_secret_1password-${VERSION}-py3-none-any.whl \
  --repo hegemony-sh/hegemony-secret-plugins \
  --signer-workflow hegemony-sh/hegemony-github-workflows/.github/workflows/plugin-release.yml
```

The release workflow of this repository calls the shared `plugin-release.yml`
workflow in `hegemony-sh/hegemony-github-workflows`, and that shared workflow
signs the attestation. So `gh` needs both flags: `--repo` checks that the wheel
was built from this repository, and `--signer-workflow` checks which workflow
signed it.

Attestations are bound to the repository path at publish time: wheels from
releases published before the move to the `hegemony-sh` organization are bound
to the path this repository carried then, so verifying one means passing that
path to `--repo` instead, and the workflow that signed that release to
`--signer-workflow`. The release workflow creates attestations only while
the repository is public (the feature needs a public repository or an
Enterprise plan), and creates them when it publishes. A release published while
the repository was private therefore has none, and making the repository public
afterwards does not add one: `gh attestation verify` has nothing to check on it.
`SHA256SUMS` still ships beside every release's assets, but it
checks integrity against a manifest published in the same release rather than
provenance, so where there is no attestation treat it as a consistency check and
not as a stand-in for one.

Or build local wheels from this repository and copy them into the running dev containers:

```bash
cd ../hegemony-secret-plugins
task build

for CONTAINER in hegemony-dev-api-1 hegemony-dev-worker-1; do
  docker exec -u root "${CONTAINER}" mkdir -p /tmp/secret-wheels
  docker cp dist/. "${CONTAINER}:/tmp/secret-wheels/"
  docker exec -u root -it "${CONTAINER}" bash -lc '
  uv pip install --python /opt/venv/bin/python \
    /tmp/secret-wheels/hegemony_secret_1password-*.whl
  '
  docker restart "${CONTAINER}"
done
```

These Docker-command installs are runtime changes. Re-run them after recreating a container
or replacing the image.

## Build a secret backend

A backend does not have to live in this repository: any wheel that depends on
`hegemony-secret-sdk` and registers a `register(registry)` callable under the
`hegemony.secret_backends` entry-point group is discovered by the platform
(install it into the API and the worker, as above, and restart both). The
[SDK README](packages/secret_sdk/README.md) has the entry-point declaration, a
complete minimal backend (`read`, `write`, `test`), and the config-schema keys
the host form understands. The two plugins here are worked examples:
[Vault and OpenBao](plugins/secret_vault/README.md) for a backend with several
auth methods, and [1Password](plugins/secret_1password/README.md) for one that
wraps an SDK.

## Documentation

- [Hegemony documentation](https://hegemony.sh): the documentation site.
- [Secrets](https://github.com/hegemony-sh/hegemony/blob/HEAD/docs/features/secrets.md):
  secret references, backends and how they are configured in the platform.
- [Internal OpenBao lifecycle](https://github.com/hegemony-sh/hegemony/blob/HEAD/docs/features/openbao-internal.md):
  the bundled OpenBao backend.
- [Installed plugins](https://github.com/hegemony-sh/hegemony/blob/HEAD/docs/guides/plugins.md):
  where the platform lists what is installed.
- Per-package configuration reference: the package READMEs linked above.

## Development

```bash
uv sync --all-packages
uv run pre-commit install --install-hooks
```

If you have [Task](https://taskfile.dev/) installed, the common workflow is:

```bash
task setup
task lint
task test
task build
task smoke
task md:lint
```

The hook set mirrors Hegemony where applicable for this package-only repo: general file
hygiene, pyproject validation, typos, Zizmor, workflow schema checks, REUSE, Ruff,
typecheck, tests, Gitleaks, and commitlint. UI, Docker, OpenAPI, and task-runner hooks stay
in Hegemony because those surfaces are not present here. Gitleaks reads
[`.gitleaks.toml`](.gitleaks.toml), which extends the default ruleset and lists
the one file it allowlists, with the reason.

Run the local equivalent of CI:

```bash
task ci
```

Run every configured pre-commit hook manually:

```bash
task precommit
```

Releases are cut automatically when a releasable change merges to `main`; see
[Contributing](CONTRIBUTING.md#releasing). Do not bump versions or push tags by
hand. `task version:set -- X.Y.Z` and `task version:verify -- vX.Y.Z` stay
available for trying the lockstep bump locally.

## Contributing, security and licence

- Read [Contributing](CONTRIBUTING.md) first. Every commit needs a DCO sign-off
  (`git commit -s`) and follows Conventional Commits, because a merge to `main`
  is a release.
- Report vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes, and
  do not open public issues for them.
- Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
- Licensed under `AGPL-3.0-or-later`. See [Licensing](LICENSING.md).

[![FOSSA license report](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fhegemony-sh%2Fhegemony-secret-plugins.svg?type=large&issueType=license)](https://app.fossa.com/projects/git%2Bgithub.com%2Fhegemony-sh%2Fhegemony-secret-plugins?ref=badge_large&issueType=license)
