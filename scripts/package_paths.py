# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PACKAGE_DIRS = (
    ROOT / "packages" / "secret_sdk",
    ROOT / "plugins" / "secret_vault",
    ROOT / "plugins" / "secret_1password",
)

PLUGIN_DIRS = PACKAGE_DIRS[1:]
SDK_VERSION_FILE = ROOT / "packages" / "secret_sdk" / "src" / "hegemony_secret_sdk" / "_version.py"
