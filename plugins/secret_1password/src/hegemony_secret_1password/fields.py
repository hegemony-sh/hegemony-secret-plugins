# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The field-mapping rule shared by both 1Password clients.

Each client extracts ``(name, section, value, generated)`` tuples from its own SDK's
item model; this module turns them into the keys a
``{{ secret('scheme://vault/item/key') }}`` reference may name:

1. Every field is available under its bare name. When several fields share a name,
   the bare key resolves to the last one -- the behaviour readers have relied on --
   and one warning per read names the section-qualified keys instead.
2. A field inside a section is *also* available as ``<section>.<name>``, which is the
   unambiguous way to address a duplicate.
3. Keys the plugin *generates* (the section-qualified aliases, the SSH-key attributes
   a client derives) never shadow a field that really carries that name: the field
   wins, the generated key is dropped, and a warning says so. Item order therefore
   never decides between a user's field and a synthetic key.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

logger = logging.getLogger(__name__)

#: One extracted field: ``(name, section label or None, value, generated)``, where
#: ``generated`` marks keys the client derived (SSH-key attributes) rather than read.
FieldEntry = tuple[str, str | None, str, bool]


def build_field_mapping(item_title: str, entries: Iterable[FieldEntry]) -> dict[str, str]:
    """Map extracted field entries to reference keys.

    Args:
        item_title: The item's title, for the warnings.
        entries: One entry per field that contributes a value, in item order.
            ``section`` is the section's human label, or ``None`` outside a section.
    """
    native: dict[str, str] = {}
    generated: dict[str, str] = {}
    occurrences: dict[str, list[tuple[str | None, str]]] = {}
    for name, section, value, is_generated in entries:
        target = generated if is_generated else native
        target[name] = value
        if section:
            generated[f"{section}.{name}"] = value
        if not is_generated:
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

    shadowed = sorted(key for key in generated if key in native and generated[key] != native[key])
    if shadowed:
        logger.warning(
            "1Password item %r has fields named like generated keys (%s); the fields win "
            "and the generated keys are not available under those names",
            item_title,
            ", ".join(shadowed),
        )

    mapping = {key: value for key, value in generated.items() if key not in native}
    mapping.update(native)
    return mapping
