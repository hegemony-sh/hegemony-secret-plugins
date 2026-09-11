# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Vault / OpenBao SSH one-time-password backend client.

``read(path)`` does not read a stored value: it asks the SSH secrets engine to mint a
one-time password (OTP) for one login on one host and returns what the engine answered.
Every read mints. The path carries everything the engine needs::

    orgs/<slug>/<role>/<ip>/<username>

and a reference's final segment picks the field, so
``{{ secret('ssh_otp://orgs/acme/linux/10.0.0.5/ubuntu/key') }}`` is a password for
user ``ubuntu`` on ``10.0.0.5``, minted from the engine role ``acme-linux``.

Tenancy rides on the path. The host confines every ``orgs/<slug>/...`` reference to the
run's own organization before the backend is called, and the engine role is always
``<slug>-<role>``: an organization can only mint from roles that carry its own slug. The
role segment may not contain a hyphen, so the composed name splits back unambiguously at
its last hyphen (slugs are ``[a-z0-9-]``). A configurable template would let organization
``a`` with role ``b-c`` reach organization ``a-b``'s role ``c``, which is why there is none.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .vault_client import (
    VaultAuthError,
    VaultConnectionConfig,
    VaultError,
    _reject_redirect,
    _VaultAuthenticatedClient,
)

logger = logging.getLogger(__name__)

DEFAULT_SSH_MOUNT = "ssh"

#: The engine role segment: a name fragment, never a path and never hyphenated.
_ROLE_SEGMENT = re.compile(r"^[A-Za-z0-9_]+$")

_GRAMMAR = "orgs/<organization slug>/<role>/<ip>/<username>"

# Vault answers a request to an engine that is not mounted with a 404 whose body says
# "no handler for route"; a 404 without it means an unknown path inside a mounted engine.
_UNMOUNTED_MARKER = "no handler for route"

_REFERENCE_ONLY = (
    "This backend issues SSH one-time passwords; it stores nothing, so secrets cannot be "
    "created, updated or deleted through it. Mark the backend read-only in Settings and "
    "reference it from device credentials only."
)


def _parse_otp_path(path: str) -> tuple[str, str, str, str]:
    """Split an OTP reference path into ``(slug, role, ip, username)``.

    Raises:
        ValueError: If the path does not follow the grammar. Raised before any request,
            so a malformed reference never reaches the engine.
    """
    segments = path.strip("/").split("/")
    if len(segments) != 5 or any(not segment for segment in segments):
        raise ValueError(
            f"SSH OTP reference path {path!r} must be {_GRAMMAR}: five non-empty "
            "segments (the reference's final segment names the field, e.g. key)"
        )
    namespace, slug, role, ip, username = segments
    if namespace != "orgs":
        raise ValueError(f"SSH OTP reference path {path!r} must start with orgs/: {_GRAMMAR}")
    if not _ROLE_SEGMENT.fullmatch(role):
        raise ValueError(
            f"SSH OTP role {role!r} in {path!r} may contain only letters, digits and "
            "underscores: the engine role is named <slug>-<role>, and a hyphen in the role "
            "would make that name ambiguous between organizations"
        )
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(
            f"SSH OTP reference path {path!r} needs a literal IP address, got {ip!r}: the "
            "engine binds the password to the address the target's vault-ssh-helper sees "
            "on its own interfaces"
        ) from exc
    return slug, role, ip, username


def engine_role_name(slug: str, role: str) -> str:
    """The SSH engine role an organization's reference resolves to: ``<slug>-<role>``."""
    return f"{slug}-{role}"


@dataclass
class VaultSshOtpConfig(VaultConnectionConfig):
    """Configuration for an SSH one-time-password backend.

    Adds the engine location to :class:`VaultConnectionConfig`:

    Attributes:
        ssh_mount: Mount point of the SSH secrets engine (default: "ssh")
    """

    ssh_mount: str = DEFAULT_SSH_MOUNT

    @classmethod
    def from_dict(cls, config: dict) -> VaultSshOtpConfig:
        """Create a VaultSshOtpConfig from an already-resolved configuration dict."""
        mount = str(config.get("ssh_mount") or DEFAULT_SSH_MOUNT).strip().strip("/")
        return cls(**cls._connection_kwargs(config), ssh_mount=mount or DEFAULT_SSH_MOUNT)


class VaultSshOtpBackend(_VaultAuthenticatedClient):
    """Mint SSH one-time passwords from a Vault / OpenBao SSH secrets engine.

    A reference-only backend: ``read`` issues a credential, ``write`` and ``delete``
    refuse (there is nothing stored to change), and there is no ``list`` -- so the host
    neither browses nor discovers anything here. Every ``read`` mints a new password; a
    reference to the ``port`` or ``ip`` field mints one too, so references should name
    ``key`` only.

    Example:
        config = VaultSshOtpConfig(address="https://openbao:8200", role_id=..., secret_id=...)
        backend = VaultSshOtpBackend(config)
        password = backend.read("orgs/acme/linux/10.0.0.5/ubuntu")["key"]
    """

    _config: VaultSshOtpConfig

    def __init__(self, config: VaultSshOtpConfig):
        """Initialize the SSH OTP backend.

        Args:
            config: SSH OTP backend configuration

        Raises:
            ImportError: If hvac library is not installed
            ValueError: If the address is not HTTPS without the explicit opt-in, or
                token auth is not provided and neither role_id nor role_id_file is
                provided
        """
        super().__init__(config)

    def read(self, path: str) -> dict[str, Any]:
        """Mint a one-time password for the login the path describes.

        Args:
            path: ``orgs/<slug>/<role>/<ip>/<username>``

        Returns:
            The engine's answer: ``ip``, ``key`` (the password), ``key_type`` (``otp``),
            ``port`` and ``username``. Never ``None``: a minting endpoint has nothing to
            find, so every failure is an error rather than a missing secret.

        Raises:
            ValueError: If the path does not follow the grammar (before any request).
            VaultError: If the engine refused or is not mounted. The server's own message
                (unknown role, address outside the role's CIDR list, ...) is included.
        """
        from hvac.exceptions import InvalidPath

        slug, role, ip, username = _parse_otp_path(path)
        role_name = engine_role_name(slug, role)
        mount = self._config.ssh_mount

        self._ensure_authenticated()
        try:
            response = _reject_redirect(
                self._client.secrets.ssh.generate_ssh_credentials(
                    name=role_name, username=username, ip=ip, mount_point=mount
                ),
                "SSH OTP issue",
            )
        except InvalidPath as e:
            if _UNMOUNTED_MARKER in str(e):
                raise VaultError(
                    f"No SSH secrets engine is mounted at {mount!r}: enable it "
                    f"(bao secrets enable -path={mount} ssh) or correct ssh_mount"
                ) from e
            raise VaultError(f"SSH OTP issue failed for role {role_name!r}: {e}") from e
        except VaultError:
            raise
        except Exception as e:
            logger.error("SSH OTP issue failed for role %s: %s", role_name, e)
            raise VaultError(f"SSH OTP issue failed for role {role_name!r}: {e}") from e

        data = response.get("data") if isinstance(response, Mapping) else None
        if not isinstance(data, Mapping) or not data.get("key"):
            raise VaultError(
                f"SSH OTP issue for role {role_name!r} returned no key; the role may not "
                "be of key_type otp"
            )
        return dict(data)

    def write(self, path: str, data: Mapping[str, Any]) -> None:
        """Refuse: the backend stores nothing."""
        raise VaultError(_REFERENCE_ONLY)

    def delete(self, path: str) -> None:
        """Refuse: the backend stores nothing."""
        raise VaultError(_REFERENCE_ONLY)

    def test(self) -> None:
        """Verify authentication and, where the policy allows, that the engine is mounted.

        ``lookup-self`` proves the token: a static token is otherwise exercised only by
        the first mint, and Vault answers 403 alike for a bad token and a missing policy.
        Listing the roles then checks the mount. A Forbidden (neither Hegemony AppRole
        lists roles) or a bare 404 (an engine with no roles yet) still passes, because
        the request reached the engine with valid auth; a 404 saying "no handler for
        route" fails, because nothing is mounted there. Cheap and never minting: the
        host's dashboard probe runs this every 30 seconds.

        Raises:
            VaultAuthError: If authentication or the token lookup fails
            VaultError: If the engine is not mounted or the request fails otherwise
        """
        from hvac.exceptions import Forbidden, InvalidPath

        try:
            self._ensure_authenticated()
        except VaultError:
            raise
        except Exception as e:
            logger.error("Vault connectivity check failed during authentication: %s", e)
            raise VaultAuthError(f"Vault authentication check failed: {e}") from e

        try:
            _reject_redirect(self._client.auth.token.lookup_self(), "connectivity check")
        except VaultError:
            raise
        except Exception as e:
            logger.error("Vault token lookup failed: %s", e)
            raise VaultAuthError(f"Vault token lookup failed: {e}") from e

        mount = self._config.ssh_mount
        try:
            _reject_redirect(
                self._client.secrets.ssh.list_roles(mount_point=mount), "connectivity check"
            )
        except Forbidden:
            logger.debug(
                "SSH role listing at %s is forbidden for this token; auth is proven, the "
                "mount is not verified",
                mount,
            )
        except InvalidPath as e:
            if _UNMOUNTED_MARKER in str(e):
                raise VaultError(
                    f"No SSH secrets engine is mounted at {mount!r}: enable it "
                    f"(bao secrets enable -path={mount} ssh) or correct ssh_mount"
                ) from e
            # An engine with no roles yet answers 404: the request reached the mount.
        except VaultError:
            raise
        except Exception as e:
            logger.error("SSH engine connectivity check failed: %s", e)
            raise VaultError(f"SSH engine connectivity check failed: {e}") from e
