#!/usr/bin/env python3
"""Build the public Pages artifact without upstream profile-link fields."""

from __future__ import annotations

import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
OUTPUT = ROOT / ".pages-site"
REMOVED_KEYS = {"profile_url", "watchguard_profile_url"}


def strip_profile_links(value):
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if key.casefold() in REMOVED_KEYS:
                continue
            if key.casefold() == "source_host" and "watchguard" in str(item).casefold():
                continue
            cleaned[key] = strip_profile_links(item)
        return cleaned
    if isinstance(value, list):
        return [strip_profile_links(item) for item in value]
    return value


def main() -> None:
    if OUTPUT.exists():
        shutil.rmtree(OUTPUT)
    (OUTPUT / "data").mkdir(parents=True)

    for filename in ("index.html", "app.js", "styles.css"):
        shutil.copy2(SITE / filename, OUTPUT / filename)

    data = json.loads((SITE / "data" / "victims.json").read_text(encoding="utf-8"))
    public_data = strip_profile_links(data)
    (OUTPUT / "data" / "victims.json").write_text(
        json.dumps(public_data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Prepared public Pages artifact at {OUTPUT}")


if __name__ == "__main__":
    main()
