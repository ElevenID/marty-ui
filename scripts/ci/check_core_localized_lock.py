"""Pure proof for the exact Core432 Git-to-local Cargo.lock transition.

The caller separately binds the local Core directory to the verified Core Git
export and checks Cargo metadata's manifest paths under that directory.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import tomllib

CORE_REVISION = "4320b5fa1c6f41231ee0aa2bc57d8008549f67ac"
CORE_SOURCE = ("git+https://github.com/ElevenID/marty-core?rev="
               + CORE_REVISION + "#" + CORE_REVISION)
ALLOWED_UNUSED_PATCHES = {("bls12_381_plus", "0.8.18"),
                          ("elliptic-curve", "0.13.8")}


def require(value: object, code: str) -> None:
    if not value:
        raise ValueError(code)


def verify_localized_lock(original: dict, localized: dict) -> dict:
    """Reject every lock delta except the exact nine Core and two unused patches."""
    require(isinstance(original, dict) and isinstance(localized, dict)
            and set(original) == set(localized) == {"version", "package", "patch"}
            and original["version"] == localized["version"],
            "LOCK_TOP_LEVEL_CHANGED")
    old_packages, new_packages = original["package"], localized["package"]
    require(isinstance(old_packages, list) and isinstance(new_packages, list)
            and len(old_packages) == len(new_packages), "LOCK_PACKAGE_SET_CHANGED")
    expected_packages = []
    core_names = set()
    for row in old_packages:
        require(isinstance(row, dict) and isinstance(row.get("name"), str),
                "LOCK_PACKAGE_SHAPE")
        source = row.get("source", "")
        if "github.com/ElevenID/marty-core" in source:
            require(source == CORE_SOURCE and "checksum" not in row
                    and row["name"] not in core_names, "LOCK_CORE_SOURCE_CHANGED")
            core_names.add(row["name"])
            expected_packages.append({key: value for key, value in row.items()
                                      if key != "source"})
        else:
            expected_packages.append(row)
    require(len(core_names) == 9 and expected_packages == new_packages,
            "LOCK_PACKAGE_DELTA_CHANGED")
    old_patch, new_patch = original["patch"], localized["patch"]
    require(isinstance(old_patch, dict) and isinstance(new_patch, dict)
            and set(old_patch) == set(new_patch) == {"unused"}
            and isinstance(old_patch["unused"], list)
            and isinstance(new_patch["unused"], list)
            and len(old_patch["unused"]) == len(new_patch["unused"]),
            "LOCK_PATCH_SET_CHANGED")
    expected_unused = []
    seen = set()
    for row in old_patch["unused"]:
        require(isinstance(row, dict) and isinstance(row.get("name"), str)
                and isinstance(row.get("version"), str), "LOCK_PATCH_SHAPE")
        key = row["name"], row["version"]
        if key in ALLOWED_UNUSED_PATCHES:
            require(row.get("source") == CORE_SOURCE and key not in seen
                    and "checksum" not in row, "LOCK_CORE_PATCH_SOURCE_CHANGED")
            seen.add(key)
            expected_unused.append({field: value for field, value in row.items()
                                    if field != "source"})
        else:
            expected_unused.append(row)
    require(seen == ALLOWED_UNUSED_PATCHES
            and expected_unused == new_patch["unused"],
            "LOCK_PATCH_DELTA_CHANGED")
    return {"state": "EXACT_CORE432_LOCALIZATION_ONLY", "coreRevision": CORE_REVISION,
            "corePackagesLocalized": len(core_names),
            "unusedCorePatchesLocalized": len(seen),
            "totalPackages": len(old_packages), "totalUnusedPatches": len(expected_unused)}


def verify_files(original: Path, localized: Path) -> dict:
    return verify_localized_lock(tomllib.loads(original.read_text(encoding="utf-8")),
                                 tomllib.loads(localized.read_text(encoding="utf-8")))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("localized", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify_files(args.original, args.localized), sort_keys=True))


if __name__ == "__main__":
    main()
