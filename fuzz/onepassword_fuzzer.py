#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Fuzz reference splitting and SDK error classification without constructing clients."""

import sys

import atheris

with atheris.instrument_imports(include=["hegemony_secret_1password"]):
    from hegemony_secret_1password.connect_client import _is_not_found, _split_path
    from hegemony_secret_1password.service_account_client import _split_path as split_service_path


@atheris.instrument_func
def test_one_input(data: bytes) -> None:
    text = data[:16384].decode("utf-8", errors="replace")
    vault, separator, item = text.partition("/")
    valid = bool(separator and vault and item)
    for split in (_split_path, split_service_path):
        try:
            parts = split(text)
        except ValueError:
            assert not valid
        else:
            assert valid and parts == (vault, item)
            assert "/".join(parts) == text
    fdp = atheris.FuzzedDataProvider(data)
    vault = "vault-" + str(fdp.ConsumeIntInRange(0, 99))
    item = "item-" + fdp.ConsumeUnicodeNoSurrogates(64)
    assert _split_path(vault + "/" + item) == (vault, item)
    assert split_service_path(vault + "/" + item) == (vault, item)
    # Arbitrary upstream error text must never crash classification.
    assert isinstance(_is_not_found(Exception(text)), bool)
    count = fdp.ConsumeIntInRange(0, 10000)
    assert _is_not_found(Exception(f"Found {count} items")) == (count <= 1)
    status = fdp.ConsumeIntInRange(100, 599)
    error = Exception(f"Received {status}: Found 0 items")
    assert _is_not_found(error) == (status == 404)
    error.status_code = 403
    assert not _is_not_found(error), "explicit authorization failure must not become a lookup miss"


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
