"""Reject production-workspace Core dependencies that restore local key custody."""

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

CORE_REVISION = "2f7770c856410ba0dd34ca1542f55187f535cd1c"
CORE_REF = CORE_REVISION
CORE_SOURCE = (
    "git+https://github.com/ElevenID/marty-core"
    f"?rev={CORE_REF}#{CORE_REVISION}"
)
ISOMDL_REVISION = "fc3aaa2628cd106d4f36f50c957d7f33211f8a5e"
ISOMDL_SOURCE = (
    "git+https://github.com/ElevenID/isomdl-elevenid"
    f"?rev={ISOMDL_REVISION}#{ISOMDL_REVISION}"
)
SSI_REVISION = "63a9bcce3daf6f45d1e38e43cf687738bb02cb53"
SSI_SOURCE = f"git+https://github.com/ElevenID/ssi-elevenid?rev={SSI_REVISION}#{SSI_REVISION}"
LINKED_DATA_REVISION = "6f86efc1579033e14ff2ad7d115ca0857e16a67f"
LINKED_DATA_SOURCE = (
    f"git+https://github.com/ElevenID/ssi-elevenid?rev={LINKED_DATA_REVISION}#{LINKED_DATA_REVISION}"
)
SD_JWT_REVISION = "fbe1e1b2c4bf0d62b0fdf0f47f265ffdaaae1ff2"
SD_JWT_SOURCE = f"git+https://github.com/ElevenID/sd-jwt-rust?rev={SD_JWT_REVISION}#{SD_JWT_REVISION}"
SSI_COMPANION_PACKAGES = {
    "ssi", "ecdsa", "linked-data", "linked-data-derive",
    "did-ethr", "did-ion", "did-jwk", "did-method-key", "did-pkh", "did-tz", "did-web",
}
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


def check_fork_sources(packages: list[dict]) -> None:
    isomdl = [package for package in packages if package["name"] == "isomdl"]
    if (
        len(isomdl) != 1
        or isomdl[0]["version"] != "0.4.0"
        or isomdl[0].get("source") != ISOMDL_SOURCE
    ):
        raise ValueError("Expected one reviewed isomdl 0.4.0 package")

    sd_jwt = [package for package in packages if package["name"] == "sd-jwt-rs"]
    if (
        len(sd_jwt) != 1
        or sd_jwt[0]["version"] != "0.8.0"
        or sd_jwt[0].get("source") != SD_JWT_SOURCE
    ):
        raise ValueError("Expected one reviewed sd-jwt-rs 0.8.0 package")

    for package in packages:
        name = package["name"]
        governed_name = name.startswith("ssi-") or name in SSI_COMPANION_PACKAGES
        fork_source = "github.com/ElevenID/ssi-elevenid" in (package.get("source") or "")
        if not (governed_name or fork_source):
            continue
        expected_source = (
            LINKED_DATA_SOURCE
            if name in {"linked-data", "linked-data-derive"}
            else SSI_SOURCE
        )
        if package.get("source") != expected_source:
            raise ValueError(f"{name} is not pinned to the reviewed SSI graph")


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

    check_fork_sources(metadata["packages"])
    isomdl = [package for package in metadata["packages"] if package["name"] == "isomdl"]
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
    check_fork_sources(packages)


if __name__ == "__main__":
    try:
        metadata = json.load(sys.stdin)
        check(metadata)
        root = Path(__file__).resolve().parents[2]
        command = ["cargo", "tree", "--color", "never", "--locked", "--manifest-path", str(root / "rust/Cargo.toml"),
                   "-e", "features,no-dev"]
        services = root / "rust/services"
        packages = sorted(package["name"] for package in metadata["packages"]
                          if Path(package["manifest_path"]).resolve().is_relative_to(services))
        if not packages:
            raise ValueError("Production service graph is empty")
        for package in packages:
            command.extend(["-p", package])
        tree = subprocess.run(command, check=True, capture_output=True, text=True, encoding="utf-8").stdout
        check_production_crypto_tree(tree)
        check_standalone_probe_lock(
            Path(__file__).resolve().parents[2]
            / ".github/feature-regression/rust-probe/Cargo.lock"
        )
    except (KeyError, ValueError) as error:
        raise SystemExit(str(error)) from error
