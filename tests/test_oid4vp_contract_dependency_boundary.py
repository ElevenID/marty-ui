"""Keep the digest-only contract boundary distinct from credential verification."""

from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]


def test_contract_uses_the_shared_digest_owner_without_a_verifier_dependency() -> None:
    manifest = tomllib.loads(
        (ROOT / "rust/crates/oid4vp-contract/Cargo.toml").read_text(encoding="utf-8")
    )
    dependencies = manifest["dependencies"]
    assert dependencies["marty-canonical-digest"] == {"workspace": True}
    assert "marty-verification" not in dependencies
    assert "marty-crypto" not in dependencies


def test_locked_digest_owner_has_only_json_and_existing_sha2_dependencies() -> None:
    lock = tomllib.loads((ROOT / "rust/Cargo.lock").read_text(encoding="utf-8"))
    owners = [
        item for item in lock["package"] if item["name"] == "marty-canonical-digest"
    ]
    assert len(owners) == 1
    # This guards direct locked inputs, not a complete compiler/runtime graph.
    dependencies = owners[0]["dependencies"]
    assert {item.split(" ")[0] for item in dependencies} == {"serde_json", "sha2"}
    sha2 = [item for item in dependencies if item.split(" ")[0] == "sha2"]
    assert len(sha2) == 1
    selected_versions = (
        [sha2[0].split(" ")[1]]
        if " " in sha2[0]
        else [item["version"] for item in lock["package"] if item["name"] == "sha2"]
    )
    assert len(selected_versions) == 1
    assert selected_versions[0].startswith("0.10.")
