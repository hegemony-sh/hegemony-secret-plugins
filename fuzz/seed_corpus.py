# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Generate deterministic raw UTF-8 seed inputs; no external data or credentials."""

import hashlib
import sys
from pathlib import Path

SOURCES = {
    "onepassword_fuzzer": "hegemony_secret_1password.connect_client,hegemony_secret_1password.service_account_client",
    "vault_inputs_fuzzer": "hegemony_secret_vault.vault_client",
}

SEEDS = {
    "onepassword_fuzzer": [
        "vault/item",
        "vault/item/field",
        "/item",
        "vault/",
        "Found 0 items",
        "Found 2 vaults",
        "Found " + "9" * 5000 + " items",
        "Found " + "0" * 5000 + "1 items",
        "Found " + "٠" * 5000 + "٢ vaults",
        "Received 401: Found 0 items",
        "Received 404",
    ],
    "vault_inputs_fuzzer": [
        "synthetic-key",
        "../invalid",
        "-invalid",
        "" + "A" * 128 + "",
        "" + "A" * 129 + "",
        "0",
        "-1",
        "30",
        "not base64",
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
        "" + "9" * 5000 + "",
    ],
}


def seed_corpus(root: Path) -> None:
    for name, seeds in SEEDS.items():
        directory = root / name
        directory.mkdir(parents=True, exist_ok=True)
        for seed in seeds:
            data = seed.encode("utf-8")
            (directory / hashlib.sha256(data).hexdigest()).write_bytes(data)


if __name__ == "__main__":
    seed_corpus(Path(sys.argv[1]))
