"""Reject production-workspace Core dependencies that restore local key custody."""

import json
import sys
import tomllib
from pathlib import Path


CORE_REVISION = "7f276a427b28ecc43fb2941b60a3884a731401e0"
CORE_REF = "7f276a4"
CORE_SOURCE = (
    "git+https://github.com/ElevenID/marty-core"
    f"?rev={CORE_REF}#{CORE_REVISION}"
)
ISOMDL_REVISION = "784a52943469622873c7ae3200dbc11e89d6bd8e"
ISOMDL_SOURCE = (
    "git+https://github.com/ElevenID/isomdl-elevenid"
    f"?rev={ISOMDL_REVISION}#{ISOMDL_REVISION}"
)
CORE_CRATES = {
    "marty-canonical-digest",
    "marty-crypto",
    "marty-didcomm",
    "marty-emrtd-issuance",
    "marty-iso18013",
    "marty-oid4vci",
    "marty-status",
    "marty-verification",
}
KMS_ONLY_CRATES = {
    "marty-crypto",
    "marty-didcomm",
    "marty-oid4vci",
    "marty-verification",
}
PROBE_CORE_CRATES = CORE_CRATES - {"marty-iso18013", "marty-status"}
FORBIDDEN_FEATURES = {"default", "local-key-operations", "test-fixtures"}


def check(metadata: dict) -> None:
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    core = [
        package
        for package in metadata["packages"]
        if "github.com/ElevenID/marty-core" in (package.get("source") or "")
    ]
    names = [package["name"] for package in core]
    if len(names) != len(CORE_CRATES) or set(names) != CORE_CRATES:
        raise ValueError(f"Marty Core workspace packages changed: {sorted(names)}")

    for package in core:
        name = package["name"]
        if package["version"] != "0.2.0" or package["source"] != CORE_SOURCE:
            raise ValueError(f"{name} is not pinned to the reviewed KMS-only Core revision")
        features = set(nodes[package["id"]]["features"])
        forbidden = features & FORBIDDEN_FEATURES
        if forbidden:
            raise ValueError(f"{name} enables forbidden features: {sorted(forbidden)}")
        if name in KMS_ONLY_CRATES and "kms-only" not in features:
            raise ValueError(f"{name} is missing the kms-only feature")

    isomdl = [package for package in metadata["packages"] if package["name"] == "isomdl"]
    if (
        len(isomdl) != 1
        or isomdl[0]["version"] != "0.3.0"
        or isomdl[0]["source"] != ISOMDL_SOURCE
    ):
        raise ValueError("Expected one reviewed isomdl 0.3.0 package")
    features = set(nodes[isomdl[0]["id"]]["features"])
    if features & {"default", "issuer-local-signing"}:
        raise ValueError("isomdl enables local issuer signing")


def check_standalone_probe_lock(path: Path) -> None:
    packages = tomllib.loads(path.read_text(encoding="utf-8"))["package"]
    core = [
        package
        for package in packages
        if "github.com/ElevenID/marty-core" in package.get("source", "")
    ]
    if {package["name"] for package in core} != PROBE_CORE_CRATES:
        raise ValueError("Standalone feature probe Core package graph changed")
    if any(package["source"] != CORE_SOURCE for package in core):
        raise ValueError("Standalone feature probe is not pinned to reviewed Core")


if __name__ == "__main__":
    try:
        check(json.load(sys.stdin))
        check_standalone_probe_lock(
            Path(__file__).resolve().parents[2]
            / ".github/feature-regression/rust-probe/Cargo.lock"
        )
    except (KeyError, ValueError) as error:
        raise SystemExit(str(error)) from error
