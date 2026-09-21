import json
from pathlib import Path

import pytest

from scripts.check_gateway_public_protocol_contract import (
    DTO_SHAPES,
    _assert_issued_credential_extension_contract,
    _assert_protocol_version,
    _assert_rust_behavior_vectors,
)


LEGACY_PROTOCOL_COMMIT = "76c37dc229b328afe002b911a26624543f814a64"
MERGED_ELEVENID_PROTOCOL_COMMIT = "441a02c24d6e39bdfbe06d2d4d63c1e70a71b6b0"


def test_gateway_public_dto_shape_manifest_is_unique_and_versioned() -> None:
    contract = json.loads(DTO_SHAPES.read_text(encoding="utf-8"))
    assert contract["schema_version"] == 1
    models = contract["models"]
    assert len(models) >= 40
    assert len({model["model"] for model in models}) == len(models)
    assert all(model["schema"].endswith(".json") for model in models)
    assert all(len(model["fields"]) == len(set(model["fields"])) for model in models)


def test_every_gateway_behavior_vector_executes_in_rust() -> None:
    _assert_rust_behavior_vectors()


def test_ci_pins_both_existing_public_contract_and_merged_elevenid_extension() -> None:
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert f"MARTY_PROTOCOL_REF: {LEGACY_PROTOCOL_COMMIT}" in workflow
    assert (
        f"ELEVENID_MARTY_PROTOCOL_REF: {MERGED_ELEVENID_PROTOCOL_COMMIT}" in workflow
    )
    assert "repository: ElevenID/marty-protocol" in workflow
    assert "repository: Marty-Protocol/Marty-Protocol" in workflow
    assert "--issued-credential-extension-only" in workflow


def test_legacy_protocol_version_gate_remains_exact(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "marty-protocol"\nversion = "0.5.0"\n',
        encoding="utf-8",
    )
    conformance = tmp_path / "conformance" / "valid"
    conformance.mkdir(parents=True)
    (conformance / "mip-configuration.json").write_text(
        json.dumps({"mip_version": "0.5.0", "supported_versions": ["0.5.0"]}),
        encoding="utf-8",
    )
    _assert_protocol_version(tmp_path)

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "marty-protocol"\nversion = "0.5.1"\n',
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="MIP version drifted"):
        _assert_protocol_version(tmp_path)


def test_issued_credential_protocol_extensions_are_closed_and_canonical(
    tmp_path: Path,
) -> None:
    schemas = tmp_path / "schemas"
    enums = tmp_path / "enums"
    schemas.mkdir()
    enums.mkdir()
    lifecycle = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "reason": {"type": ["string", "null"], "maxLength": 2000},
            "comments": {"type": ["string", "null"], "maxLength": 4000},
        },
    }
    formats = {
        "type": "string",
        "enum": ["SD_JWT_VC", "VDS_NC"],
        "$defs": {
            "wire_format_mapping": {"VDS_NC": "vds_nc"},
            "values": {"VDS_NC": {"standards": ["ICAO Doc 9303, Part 13"]}},
        },
    }
    (schemas / "issued-credential-lifecycle-request.json").write_text(
        json.dumps(lifecycle), encoding="utf-8"
    )
    (enums / "credential-formats.json").write_text(
        json.dumps(formats), encoding="utf-8"
    )
    _assert_issued_credential_extension_contract(tmp_path)

    lifecycle["properties"]["comments"]["maxLength"] = 3999
    (schemas / "issued-credential-lifecycle-request.json").write_text(
        json.dumps(lifecycle), encoding="utf-8"
    )
    with pytest.raises(AssertionError, match="comments contract drifted"):
        _assert_issued_credential_extension_contract(tmp_path)
