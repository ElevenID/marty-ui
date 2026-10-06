#!/usr/bin/env python3
"""Check a narrow fast-unit ownership inventory, not runtime execution."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "contracts/python-value-fast-obligations.json"
TEST_DECLARATION = re.compile(
    r"(?m)^[ \t]*#\[(?:tokio::)?test\][ \t]*\r?\n[ \t]*(?:async )?fn ([a-z0-9_]+)\("
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def source(root: Path, path: str) -> str:
    target = root / path
    require(target.is_file(), f"Missing obligation input: {path}")
    return target.read_text(encoding="utf-8")


def declared_tests(text: str) -> set[str]:
    found = TEST_DECLARATION.findall(text)
    require(len(found) == len(set(found)), "Duplicate Rust test declarations")
    return set(found)


def validate(manifest: dict, root: Path = ROOT) -> None:
    require(
        manifest.get("schema") == "marty.python-value-fast-obligations/v1",
        "Unknown schema",
    )
    owner = manifest["owner"]
    require(
        owner["package"] == "marty-response-compat" and owner["target"] == "lib",
        "Wrong fast owner",
    )
    owner_manifest = source(root, owner["cargo_manifest"])
    require(
        'name = "marty-response-compat"' in owner_manifest, "Owner Cargo package drift"
    )
    require(
        "default = []" in owner_manifest
        and 'postgres = ["dep:sqlx"]' in owner_manifest,
        "Owner default feature drift",
    )
    owner_source = source(root, owner["source"])
    require(
        "pub mod python_value;"
        in source(root, "rust/crates/response-compat/src/lib.rs"),
        "Owner module export drift",
    )
    for path in owner["common_inputs"]:
        source(root, path)
    require(
        "contracts/python-text-semantics.json" in owner["common_inputs"],
        "Frozen Unicode input unmapped",
    )
    require(
        "contracts/python-text-semantics.json" in owner_source,
        "Frozen Unicode include removed",
    )

    cases = manifest["cases"]
    names = [case["test"] for case in cases]
    require(
        len(names) == len(set(names)) == 4, "Fast unit obligation count/duplicate drift"
    )
    require(
        {name.removeprefix("python_value::tests::") for name in names}
        == declared_tests(owner_source),
        "Fast unit Rust test discovery/inventory mismatch",
    )
    for case in cases:
        require(
            case["test"].startswith("python_value::tests::"), "Wrong fast test module"
        )
        require(
            case["assertion"].strip()
            and case["inputs"]
            and case["cheapest_proving_layer"] == "pure unit",
            "Fast case obligation incomplete",
        )

    signing = manifest["retained_signing_detail"]
    require(
        signing["package"] == "marty-issuance-service"
        and signing["target"] == "signing_error_detail_contract",
        "Wrong signing owner",
    )
    issuance_manifest = source(root, "rust/services/issuance/Cargo.toml")
    require(
        'name = "signing_error_detail_contract"' in issuance_manifest
        and 'path = "tests/signing_error_detail_contract.rs"' in issuance_manifest,
        "Signing Cargo target drift",
    )
    signing_source = source(root, signing["source"])
    shared_projection = source(root, signing["shared_projection_source"])
    source(root, signing["fixture"])
    require(
        "use marty_response_compat::python_value;" in signing_source,
        "Signing shared owner import drift",
    )
    require(
        "canvas-worker-privacy-reference.json" in signing_source,
        "Signing fixture include drift",
    )
    expected_signing = set(declared_tests(signing_source)) | {
        f"signing_error_detail::{name}" for name in declared_tests(shared_projection)
    }
    require(
        len(signing["tests"]) == len(set(signing["tests"])) == 12,
        "Signing case count/duplicate drift",
    )
    require(
        set(signing["tests"]) == expected_signing,
        "Signing target source/inventory mismatch",
    )

    http = manifest["retained_http"]
    require(
        http["package"] == "marty-issuance-service" and http["target"] == "lib",
        "Wrong HTTP owner",
    )
    http_source = source(root, http["source"])
    module_owner = source(root, http["module_owner"])
    source(root, http["fixture"])
    require(
        "signing_http_response_tests.rs" in module_owner,
        "HTTP test module wiring drift",
    )
    require(
        "signing-response-python-reference.json" in http_source,
        "HTTP fixture include drift",
    )
    require(
        len(http["tests"]) == len(set(http["tests"])) == 7,
        "HTTP case count/duplicate drift",
    )
    require(
        set(http["tests"])
        == {
            f"signing_http_response::tests::{name}"
            for name in declared_tests(http_source)
        },
        "HTTP source/inventory mismatch",
    )


def main() -> int:
    validate(json.loads(INVENTORY.read_text(encoding="utf-8")))
    print(
        "Python-value fast obligations: four unit, 12 signing-detail, seven HTTP owners registered"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
