#!/usr/bin/env python3
"""Check a narrow fast-unit ownership inventory, not runtime execution."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.check_gateway_public_protocol_contract import _without_rust_comments

INVENTORY = ROOT / "contracts/python-value-fast-obligations.json"
ATTRIBUTED_FUNCTION = re.compile(
    r"(?m)^((?:[ \t]*#\[[^\]\n]+\][ \t]*\r?\n)+)[ \t]*(?:async )?fn ([a-z0-9_]+)\("
)
TEST_ATTRIBUTE = re.compile(r"(?m)^[ \t]*#\[(?:tokio::)?test\][ \t]*$")
DISABLING_ATTRIBUTE = re.compile(r"(?m)^[ \t]*#\[(?:ignore\b|cfg(?:_attr)?\b)")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def source(root: Path, path: str) -> str:
    target = root / path
    require(target.is_file(), f"Missing obligation input: {path}")
    return target.read_text(encoding="utf-8")


def declared_tests(text: str) -> set[str]:
    code = _without_rust_comments(text, mask_strings=True)
    found = []
    for attributes, name in ATTRIBUTED_FUNCTION.findall(code):
        if not TEST_ATTRIBUTE.search(attributes):
            continue
        disablers = [
            line.strip()
            for line in attributes.splitlines()
            if DISABLING_ATTRIBUTE.match(line)
        ]
        require(
            all(line == "#[cfg(test)]" for line in disablers),
            f"Conditional or ignored Rust test: {name}",
        )
        found.append(name)
    require(
        len(found) == len(TEST_ATTRIBUTE.findall(code)),
        "Rust test attribute/function ownership drift",
    )
    require(len(found) == len(set(found)), "Duplicate Rust test declarations")
    return set(found)


def active_module_wiring(text: str, pattern: str, markers: tuple[str, ...]) -> bool:
    clean = _without_rust_comments(text)
    code = _without_rust_comments(text, mask_strings=True)
    return any(
        all(marker in code[match.start() : match.end()] for marker in markers)
        for match in re.finditer(pattern, clean)
    )


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
    owner_code = _without_rust_comments(owner_source, mask_strings=True)
    require(
        re.search(r"(?m)^#\[cfg\(test\)\]\s*\r?\nmod tests \{", owner_code) is not None,
        "Fast unit test module feature gate drift",
    )
    owner_lib = _without_rust_comments(
        source(root, "rust/crates/response-compat/src/lib.rs"), mask_strings=True
    )
    require(
        re.search(r"(?m)^pub mod python_value;\s*$", owner_lib) is not None,
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
            and case["oracle_role"].strip()
            and case["cheapest_proving_layer"] == "pure unit",
            "Fast case obligation incomplete",
        )

    signing = manifest["retained_signing_detail"]
    require(signing["oracle_role"].strip(), "Signing oracle role missing")
    require(
        signing["package"] == "marty-issuance-service"
        and signing["target"] == "signing_error_detail_contract",
        "Wrong signing owner",
    )
    issuance_manifest = source(root, "rust/services/issuance/Cargo.toml")
    issuance_targets = tomllib.loads(issuance_manifest).get("test", [])
    require(
        any(
            target.get("name") == "signing_error_detail_contract"
            and target.get("path") == "tests/signing_error_detail_contract.rs"
            and not target.get("required-features")
            for target in issuance_targets
        ),
        "Signing Cargo target feature gate drift",
    )
    require(
        'name = "signing_error_detail_contract"' in issuance_manifest
        and 'path = "tests/signing_error_detail_contract.rs"' in issuance_manifest,
        "Signing Cargo target drift",
    )
    signing_source = source(root, signing["source"])
    shared_projection = source(root, signing["shared_projection_source"])
    source(root, signing["fixture"])
    signing_code = _without_rust_comments(signing_source, mask_strings=True)
    require(
        re.search(r"(?m)^use marty_response_compat::python_value;\s*$", signing_code)
        is not None,
        "Signing shared owner import drift",
    )
    require(
        active_module_wiring(
            signing_source,
            r'(?m)^#\[path = "\.\./src/signing_error_detail\.rs"\]\s*\r?\nmod signing_error_detail;\s*$',
            ("#[path", "mod signing_error_detail;"),
        ),
        "Signing integration source inclusion drift",
    )
    issuance_lib = _without_rust_comments(
        source(root, "rust/services/issuance/src/lib.rs"), mask_strings=True
    )
    require(
        re.search(r"(?m)^mod signing_error_detail;\s*$", issuance_lib) is not None,
        "Signing library module ownership drift",
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
    duplicate = signing["duplicated_execution"]
    require(
        duplicate["test"]
        == "signing_error_detail::scalar_api_remains_a_projection_of_the_shared_owner"
        and duplicate["targets"]
        == [
            "marty-issuance-service::lib",
            "marty-issuance-service::signing_error_detail_contract",
        ],
        "Shared projection duplicate-execution disclosure drift",
    )

    http = manifest["retained_http"]
    require(http["oracle_role"].strip(), "HTTP oracle role missing")
    require(
        http["package"] == "marty-issuance-service" and http["target"] == "lib",
        "Wrong HTTP owner",
    )
    http_source = source(root, http["source"])
    module_owner = source(root, http["module_owner"])
    source(root, http["fixture"])
    require(
        active_module_wiring(
            module_owner,
            r'(?m)^#\[cfg\(test\)\]\s*\r?\n#\[path = "signing_http_response_tests\.rs"\]\s*\r?\npub\(crate\) mod tests;\s*$',
            ("#[cfg(test)]", "#[path", "pub(crate) mod tests;"),
        ),
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
        "Python-value fast obligations: four unit, 12 distinct signing-detail, seven HTTP owners registered"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
