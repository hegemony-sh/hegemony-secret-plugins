<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Contributing

This repository is part of the Hegemony project. Its source is licensed under
`AGPL-3.0-or-later`. Your contribution is licensed under the same terms, and
contributing it transfers no copyright to the project. There is no Contributor
License Agreement. See [LICENSING.md](LICENSING.md).

The project's own files name Rexonix s.r.o. as the copyright holder, and those
with an SPDX header also name Jakub Trávník as the author (see
[LICENSING.md](LICENSING.md)). If you do not write on behalf of Rexonix s.r.o.,
you keep the copyright in your contribution and may add your own
`SPDX-FileCopyrightText` line to the header of a file you change, as REUSE
recommends.

## Code of Conduct and security

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

Report vulnerabilities privately through the process in
[SECURITY.md](SECURITY.md). Do **not** open public issues for vulnerabilities,
leaked secrets, exploit details, or suspected compromise.

## Licensing and DCO

The [Code of Conduct](CODE_OF_CONDUCT.md) is adapted third-party documentation
under CC-BY-4.0; preserve its attribution and license when editing it. The
source-code licensing and contribution rules below continue to apply to code.

Every commit must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/) (DCO),
version 1.1. A `Signed-off-by:` line certifies that you wrote the change, or
otherwise have the right to submit it under the project licence. Sign off with
`git commit -s`, which adds a trailer like this:

```text
Signed-off-by: Your Name <your.email@example.com>
```

The DCO GitHub App checks every commit in a pull request: the
sign-off's name and email must match the commit's author. Merge
commits and commits by GitHub bot accounts are skipped. To add a missing
sign-off to every commit on your branch, run
`git rebase --signoff origin/main` and force-push the branch.

A commit written by an AI coding agent is signed off by the person who directs
the agent and submits the work, as its author; the agent is credited in a
`Co-authored-by:` trailer and never signs off in its own name. See the
platform's
[CONTRIBUTING.md](https://github.com/hegemony-sh/hegemony/blob/HEAD/CONTRIBUTING.md#licensing-and-dco).

Licensing questions: [contact@hegemony.sh](mailto:contact@hegemony.sh).

## Development setup

You need Python 3.11 or newer (CI runs 3.12) and [uv](https://docs.astral.sh/uv/);
[Task](https://taskfile.dev/) is optional. You do not need a checkout of the
Hegemony platform, and no Vault, OpenBao or 1Password server: the tests mock
the clients.

```bash
git clone https://github.com/hegemony-sh/hegemony-secret-plugins.git
cd hegemony-secret-plugins
uv sync --all-packages
uv run pre-commit install --install-hooks
```

Before you open a pull request, run the checks CI runs (`task ci` runs the same
set):

```bash
uv run ruff check packages plugins tests scripts
uv run ruff format --check packages plugins tests scripts
uv run reuse lint
uv run ty check
uv run pytest
uv run python scripts/build_wheels.py
uv run python scripts/smoke_install_wheels.py
```

`task md:lint` lints the Markdown, and `task precommit` runs every pre-commit
hook, including typos, Zizmor and Gitleaks. Gitleaks reads
[`.gitleaks.toml`](.gitleaks.toml): it extends the default ruleset, and the one
file it allowlists is listed there with the reason. A scan failure is never
fixed by disabling a rule.

The repository is [REUSE](https://reuse.software/) compliant. Every file carries
an `SPDX-FileCopyrightText` and an `SPDX-License-Identifier` tag: copy the
header of a neighbouring file into a new one. Files that cannot carry a comment
(JSON, lockfiles) are covered by `REUSE.toml`.

A first-party file with an SPDX header names Rexonix s.r.o. as the copyright
holder and Jakub Trávník as the author, in the file's own comment syntax:

<!-- REUSE-IgnoreStart -->

```python
# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
```

<!-- REUSE-IgnoreEnd -->

## Commits and pull requests

Use [Conventional Commits](https://www.conventionalcommits.org/) for every
commit. The commit-msg hook and CI enforce it through `commitlint.config.mjs`;
a scope is optional and free-form (lower-case letters, digits and single dashes,
at most 20 characters, comma-separated).

The commit type matters more here than in most projects, because **a merge to
`main` is a release**: `fix`, `perf`, `revert` and `feat` publish a new version
of all three packages, and the other types do not. The table under
[Releasing](#releasing) lists them. Use `docs`, `ci`, `test`, `refactor` and
`chore` for changes that must not ship, and `fix` or `feat` only for a change to
the packages themselves.

Keep a pull request small and tied to an issue or a clear problem. A change to
a backend comes with tests for its success and failure paths. Say in the
description what you ran.

## Test fixtures

Test data and examples are synthetic. Never commit a real token, role or secret
ID, password, service account token, Connect token or private key, even one that
has been revoked or is only ever used in a test, and never the address of a real
server.

- Use values that cannot be mistaken for real credentials: short and plainly
  fake, such as `tok`, `rid` and `sid`, `hunter2`, `ops_test`, `minted-token`.
  A string shaped like a real token (a Vault `hvs.` token, a JWT, a 1Password
  `ops_` token with a real-looking body) is not acceptable, even if it is fake.
- Use reserved names and addresses: `example.com` and `*.example` hostnames,
  Docker-style service names such as `vault` and `openbao`, and the private
  ranges of RFC 1918 for addresses.
- Use made-up people and organizations (`alice`, `acme`), never real ones.
- Never paste output captured from a real Vault, OpenBao or 1Password server.
  Write the smallest response the test needs by hand.

If a scanner reports a fixture, change the fixture; do not suppress the finding
unless it is a false positive, and then say why next to the suppression.

## Adding a backend

A secret backend does not have to live in this repository: any wheel that
depends on `hegemony-secret-sdk` and registers under the
`hegemony.secret_backends` entry-point group is discovered by the platform. The
[SDK README](packages/secret_sdk/README.md) shows how. Open an issue before you
start on a new backend here, so we can agree whether it belongs in this
repository or in a package of its own.

## Releasing

A merge to `main` is a release. The `Release` workflow calls the shared
`plugin-release.yml` release workflow of the Hegemony organization, pinned by
commit in `.github/workflows/release.yml`, which runs
[semantic-release](https://semantic-release.gitbook.io/):
it reads the Conventional Commits since the last tag, derives the next
version from them, bumps every package and SDK pin (`scripts/set_version.py`),
refreshes `uv.lock`, builds and smoke-installs the wheels, prepends
`CHANGELOG.md`, commits `chore(release): X.Y.Z [skip ci]`, tags `vX.Y.Z` and
publishes the wheels plus `SHA256SUMS` as the GitHub Release. There is no
manual step any more: do not bump versions or push `v*` tags by hand. The
workflow needs a `RELEASE_TOKEN` repository or organization secret; the shared
workflow fails fast with a clear message when it is empty.

| Commits since the last tag | Release |
|---|---|
| `fix`, `perf`, `revert` | patch |
| `feat` | minor |
| breaking change (`feat!:`, `fix!:` or a `BREAKING CHANGE:` footer) | **minor, while the major is 0** |
| `chore`, `docs`, `ci`, `test`, `refactor`, `build`, `style` | none |

The 0.x rule is the `"breaking": true` entry in `.releaserc.json`'s
`releaseRules`; once the packages reach 1.0, change its `release` to
`major`. Deleting it is not enough: the rules are tried in order and the
first match wins, so a breaking `feat` would still match the `feat` rule and
release a minor.

Releases are immutable. The pipeline refuses to run when a GitHub Release for
the next tag already exists and never replaces published assets: fix forward
with a new commit, which becomes the next release. Attestations are created
only while the repository is public, so a release cut while it was private
ships checksums only.

One failure a re-run cannot repair: semantic-release pushes the release
commit and the `vX.Y.Z` tag before it publishes the GitHub Release, so if
publication fails after that push the tag exists without a Release, and the
next run reads the tag as the last release. Maintainers publish that tag's
assets by hand from a checkout of the tag: rebuild the wheels at that tag
(`uv run python scripts/build_wheels.py`), write the checksums with
`(cd dist && sha256sum *.whl > SHA256SUMS)`, and run
`gh release create vX.Y.Z --verify-tag ... dist/*.whl dist/SHA256SUMS`.

A change merged to the shared workflow reaches this repository through a pull
request that bumps the pinned SHA.
