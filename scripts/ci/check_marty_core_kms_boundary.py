"""Reject production-workspace Core dependencies that restore local key custody."""

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

CORE_REVISION = "56f58d7a52f3468d25e0ad9936041d32d9bbf058"
CORE_REF = CORE_REVISION
CORE_SOURCE = (
    "git+https://github.com/ElevenID/marty-core"
    f"?rev={CORE_REF}#{CORE_REVISION}"
)
ISOMDL_REVISION = "1e7ab823e26559dfce2f7e0f1fdf2aa61a936b4f"
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
    "marty-x509-verification",
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
        if package["version"] != "0.2.2" or package["source"] != CORE_SOURCE:
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


def check_production_crypto_tree(tree: str) -> None:
    forbidden = (
        r'ecdsa feature "signing"',
        r'(?:p256|p384|p521|k256) feature "ecdsa"',
        r'jsonwebtoken feature "rust_crypto"',
        r'ed448-goldilocks-plus feature "(?:signing|default|pkcs8)"',
    )
    if any(re.search(pattern, tree) for pattern in forbidden):
        raise ValueError("Production service graph restores local credential signing")


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
        root = Path(__file__).resolve().parents[2]
        command = ["cargo", "tree", "--locked", "--manifest-path", str(root / "rust/Cargo.toml"),
                   "-e", "features,no-dev"]
        for package in ("marty-issuance-service", "marty-verification-service", "marty-flow",
                        "marty-signing-keys", "marty-device-registration", "marty-gateway"):
            command.extend(["-p", package])
        tree = subprocess.run(command, check=True, capture_output=True, text=True, encoding="utf-8").stdout
        check_production_crypto_tree(tree)
        check_standalone_probe_lock(
            Path(__file__).resolve().parents[2]
            / ".github/feature-regression/rust-probe/Cargo.lock"
        )
    except (KeyError, ValueError) as error:
        raise SystemExit(str(error)) from error
