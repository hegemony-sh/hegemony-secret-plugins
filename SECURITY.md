<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Security Policy

This repository holds the Hegemony secret-backend SDK and plugins
(`hegemony-secret-sdk`, `hegemony-secret-vault`, `hegemony-secret-1password`).
They handle the credentials Hegemony uses to reach HashiCorp Vault, OpenBao and
1Password, so a vulnerability here can expose secrets.

Security reports are handled privately. Please do not open a public GitHub issue
for vulnerabilities, suspected vulnerabilities, leaked secrets, or exploit
details.

## Reporting a vulnerability

Report vulnerabilities privately by emailing
[security@hegemony.sh](mailto:security@hegemony.sh).

Please include as much detail as you can safely share:

- Affected package (`hegemony-secret-sdk`, `hegemony-secret-vault` or
  `hegemony-secret-1password`) and version.
- Backend type and the relevant configuration, with every credential removed.
- Impact and attack scenario.
- Reproduction steps or proof-of-concept details.
- Whether the issue is already public or under active exploitation.
- A safe way to contact you for follow-up.

Do not include real tokens, role or secret IDs, service account tokens, private
keys or customer data. Use placeholders.

## What is in scope

- The three packages in this repository, for example a credential that reaches a
  log line or an error message, a bypass of TLS verification or of the
  `https://` requirement, a request that is redirected with the token attached,
  or a secret path that escapes its intended namespace.
- The release pipeline of these packages: the published wheels, their
  `SHA256SUMS` and their provenance attestation.

Vulnerabilities in the Hegemony platform itself belong to the platform's
[security policy](https://github.com/hegemony-sh/hegemony/blob/HEAD/SECURITY.md).
Vulnerabilities in HashiCorp Vault, OpenBao, 1Password or in the client
libraries these packages use (`hvac`, `onepasswordconnectsdk`, `onepassword-sdk`)
should be reported to their own projects; tell us as well if the way these
packages use them makes the problem worse.

## Supported versions

The packages are released together, on one version line, and releases are
immutable: a fix is published as a new release, never by replacing the assets of
an existing one. Only the latest release receives security fixes; to get a fix,
upgrade to it. The packages are on a 0.x line, so a minor version can change
behaviour; the release notes of each version say what changed.

## Response targets

Maintainers aim to follow this timeline, the same as the platform's:

| Stage | Target |
| --- | --- |
| Acknowledge receipt | 48 hours |
| Initial triage and severity assessment | 7 days |
| Coordinated fix and disclosure target | 90 days |

These targets may vary based on severity, complexity, affected dependencies,
maintainer availability, and responsible-disclosure coordination.

## Disclosure process

1. Maintainers acknowledge the report and establish a private coordination
   channel.
2. Maintainers validate the report, assess severity, and identify affected
   versions.
3. A fix, mitigation, or advisory is prepared privately.
4. Disclosure timing is coordinated with the reporter when possible.
5. Public details are published after a fix or mitigation is available, or after
   the coordinated disclosure window expires.

Security fixes are announced as GitHub security advisories on this repository's
[Security tab](https://github.com/hegemony-sh/hegemony-secret-plugins/security/advisories),
and each fix ships as a release whose notes link the advisory. To be notified,
watch this repository: choose **Watch → Custom**, then select **Releases**.

## Safe harbor

Security research conducted in good faith is welcome. Please avoid privacy
violations, service disruption, data destruction, persistence, social
engineering, spam, and testing against systems you do not own or do not have
permission to test.

## Secrets

If you believe a secret was committed or exposed, report it privately. Do not
rotate, use, or test credentials unless they belong to you and you are
authorized to do so.
