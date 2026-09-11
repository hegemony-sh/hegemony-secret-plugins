# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The field-mapping rule shared by both 1Password clients.

Each client extracts ``(name, section, value)`` triples from its own SDK's item model;
this module turns them into the keys a ``{{ secret('scheme://vault/item/key') }}``
reference may name:

1. Every field is available under its bare name. When several fields share a name,
   the bare key resolves to the last one -- the behaviour readers have relied on --
   and one warning per read names the section-qualified keys instead.
2. A field inside a section is *also* available as ``<section>.<name>``, which is the
   unambiguous way to address a duplicate.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

logger = logging.getLogger(__name__)


def build_field_mapping(
    item_title: str, entries: Iterable[tuple[str, str | None, str]]
) -> dict[str, str]:
    """Map extracted ``(name, section, value)`` triples to reference keys.

    Args:
        item_title: The item's title, for the duplicate warning.
        entries: One triple per field that contributes a value, in item order.
            ``section`` is the section's human label, or ``None`` outside a section.
    """
    mapping: dict[str, str] = {}
    occurrences: dict[str, list[tuple[str | None, str]]] = {}
    for name, section, value in entries:
        mapping[name] = value
        if section:
            mapping[f"{section}.{name}"] = value
        occurrences.setdefault(name, []).append((section, value))

    for name, seen in sorted(occurrences.items()):
        if len({value for _, value in seen}) < 2:
            continue
        qualified = sorted({f"{section}.{name}" for section, _ in seen if section})
        logger.warning(
            "1Password item %r has %d fields named %r with different values; the bare key "
            "resolves to the last one. Use a section-qualified key instead: %s",
            item_title,
            len(seen),
            name,
            ", ".join(qualified) or "none available (the fields are not in sections)",
        )
    return mapping
