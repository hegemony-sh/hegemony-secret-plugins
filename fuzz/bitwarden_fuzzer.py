#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Fuzz Vaultwarden path splitting and encrypted-value parsing without a server."""

import contextlib
import sys

import atheris

with atheris.instrument_imports(include=["hegemony_secret_bitwarden"]):
    from hegemony_secret_bitwarden.backend import split_candidates
    from hegemony_secret_bitwarden.crypto import (
        BitwardenCryptoError,
        SymmetricKey,
        decrypt,
        decrypt_text,
        encrypt,
    )

KEY = SymmetricKey(enc=bytes(range(32)), mac=bytes(range(32, 64)))
COLLECTIONS = {"c1": "Network", "c2": "Network/Core", "c3": "a", "c4": "a/b/c", "c5": ""}


@atheris.instrument_func
def test_one_input(data: bytes) -> None:
    text = data[:16384].decode("utf-8", errors="replace")

    # A server-supplied value must decrypt or raise the plugin's own error, nothing else.
    for candidate in (text, "2." + text):
        with contextlib.suppress(BitwardenCryptoError):
            decrypt_text(candidate, KEY)

    # Whatever is encrypted comes back, and a flipped bit never does.
    enc_string = encrypt(data, KEY)
    assert decrypt(enc_string, KEY) == data
    # The first base64 character of the IV: all six of its bits are data bits.
    tampered = "2." + ("A" if enc_string[2] != "A" else "B") + enc_string[3:]
    try:
        decrypt(tampered, KEY)
    except BitwardenCryptoError:
        pass
    else:
        raise AssertionError("a modified value was accepted")

    head, separator, tail = text.partition("/")
    valid = bool(separator and head and tail)
    try:
        candidates = split_candidates(text, COLLECTIONS)
    except ValueError:
        assert not valid
    else:
        assert valid
        assert len(candidates) == len(set(candidates))
        lengths = []
        for collection_id, item in candidates:
            assert item, "an item reference is never empty"
            name = COLLECTIONS[collection_id]
            prefixes = [p for p in (name, collection_id) if p and text == f"{p}/{item}"]
            assert prefixes, "every candidate re-joins to the path"
            lengths.append(max(len(p) for p in prefixes))
        assert lengths == sorted(lengths, reverse=True), "longest collection first"

    fdp = atheris.FuzzedDataProvider(data)
    item = "item-" + fdp.ConsumeUnicodeNoSurrogates(64)
    assert ("c1", item) in split_candidates("Network/" + item, COLLECTIONS)
    assert split_candidates("Network/Core/" + item, COLLECTIONS)[0] == ("c2", item)
    assert split_candidates("Missing/" + item, COLLECTIONS) == []


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
