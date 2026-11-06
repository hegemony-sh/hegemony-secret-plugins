#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Check Transit key decoding, key-name grammar and bounded timeout configuration offline."""

import base64
import string
import sys

import atheris

with atheris.instrument_imports(include=["hegemony_secret_vault"]):
    from hegemony_secret_vault.vault_client import (
        VaultError,
        VaultSecretsBackend,
        _decode_data_key,
        _normalize_timeout,
    )


@atheris.instrument_func
def test_one_input(data: bytes) -> None:
    raw = data[:16384]
    try:
        decoded = _decode_data_key(raw)
    except VaultError:
        pass
    else:
        assert len(decoded) == 32
        assert base64.b64decode(raw, validate=True) == decoded
    fdp = atheris.FuzzedDataProvider(data)
    key = fdp.ConsumeBytes(32).ljust(32, b"\0")
    assert _decode_data_key(base64.b64encode(key)) == key
    for size in (0, 1, 31, 33, 64):
        try:
            _decode_data_key(base64.b64encode(b"x" * size))
        except VaultError:
            pass
        else:
            raise AssertionError("accepted a data key with the wrong size")
    text = raw.decode("utf-8", errors="replace")
    ends = string.ascii_letters + string.digits + "_"
    valid = (
        1 <= len(text) <= 128
        and text[0] in ends
        and text[-1] in ends
        and all(c in ends + "-" for c in text)
    )
    try:
        name = VaultSecretsBackend._transit_key_name(text)
    except ValueError:
        assert not valid
    else:
        assert valid and name == text
    try:
        timeout = _normalize_timeout(text)
    except ValueError:
        pass
    else:
        assert isinstance(timeout, int) and timeout > 0
    seconds = fdp.ConsumeIntInRange(1, 100000)
    assert _normalize_timeout(f" {seconds} ") == seconds
    for value in ("0", "-1"):
        try:
            _normalize_timeout(value)
        except ValueError:
            pass
        else:
            raise AssertionError("accepted an unbounded timeout")


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
