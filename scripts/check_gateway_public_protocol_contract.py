#!/usr/bin/env python3
"""Verify the Rust gateway boundary against the pinned Marty Protocol schemas."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tomllib
from typing import Any

try:
    from scripts.check_generated_protocol_bindings import assert_generated_bindings_current
    from scripts.check_public_protocol_documentation import (
        assert_documented_public_boundary,
    )
except ModuleNotFoundError:  # Direct `python scripts/...` execution.
    from check_generated_protocol_bindings import assert_generated_bindings_current
    from check_public_protocol_documentation import assert_documented_public_boundary


REPO_ROOT = Path(__file__).resolve().parents[1]
DTO_SHAPES = REPO_ROOT / "contracts" / "gateway-public-dto-shapes.json"
DISCOVERY_CONTRACT = REPO_ROOT / "contracts" / "gateway-discovery-behavior.json"
TRUST_CONFIGURATION_UI_PATHS = (
    "ui/src/components/console/trust/TrustProfileWizard.jsx",
    "ui/src/components/console/trust/steps/TrustSourcesStep.jsx",
)
FORBIDDEN_TRUST_CONFIGURATION_TOKENS = {
    "issuer_profile_id",
    "issuer_key_id",
    "kms_key_id",
    "kms_provider",
    "signing_key_reference",
    "signing_service_id",
    "verification_keys",
}
FORBIDDEN_PUBLIC_FIELDS = {
    "auto_generate_artifacts",
    "issuer_algorithm",
    "issuer_certificate_chain_pem",
    "issuer_key_id",
    "issuer_profile_id",
    "key_access_mode",
    "key_binding",
    "key_management",
    "key_name",
    "key_reference",
    "key_version",
    "kms_arn",
    "kms_provider",
    "kms_region",
    "managed_key_id",
    "provider",
    "remote_key_binding",
    "remote_signing_config",
    "resolver_url",
    "service_id",
    "signing_agent_auth",
    "signing_agent_url",
    "signing_key_reference",
    "signing_service_id",
    "transit_mount",
    "universal_resolver_url",
    "verification_method_id",
}
FORBIDDEN_ORGANIZATION_FIELDS = FORBIDDEN_PUBLIC_FIELDS | {
    "plan",
    "plan_expires_at",
    "settings",
}
FORBIDDEN_FLOW_FIELDS = FORBIDDEN_PUBLIC_FIELDS | {
    "access_token",
    "api_key",
    "client_secret",
    "pre-auth_code",
    "pre-authorized_code",
    "pre_auth_code",
    "private_key",
    "private_key_jwk",
    "refresh_token",
    "session_token",
}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _property_names(value: object) -> set[str]:
    if isinstance(value, dict):
        result = set(value.get("properties", {}))
        for child in value.values():
            result.update(_property_names(child))
        return result
    if isinstance(value, list):
        result: set[str] = set()
        for child in value:
            result.update(_property_names(child))
        return result
    return set()


def _assert_protocol_version(protocol_root: Path) -> None:
    metadata = tomllib.loads(
        (protocol_root / "pyproject.toml").read_text(encoding="utf-8")
    )
    protocol_version = metadata["project"]["version"]
    discovery = _load_json(DISCOVERY_CONTRACT)["mip_configuration"]
    if discovery.get("mip_version") != protocol_version:
        raise AssertionError(
            "Rust gateway MIP version drifted from the pinned public contract: "
            f"runtime={discovery.get('mip_version')}, protocol={protocol_version}"
        )
    if discovery.get("supported_versions") != [protocol_version]:
        raise AssertionError(
            "pre-1.0 gateway must advertise only the exact pinned MIP version"
        )
    conformance = _load_json(
        protocol_root / "conformance" / "valid" / "mip-configuration.json"
    )
    if conformance.get("mip_version") != protocol_version or conformance.get(
        "supported_versions"
    ) != [protocol_version]:
        raise AssertionError(
            "public MIP discovery fixture does not declare the pinned release only"
        )


def _assert_trust_ui_boundary() -> None:
    for relative_path in TRUST_CONFIGURATION_UI_PATHS:
        source = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        leaked = FORBIDDEN_TRUST_CONFIGURATION_TOKENS & {
            token for token in FORBIDDEN_TRUST_CONFIGURATION_TOKENS if token in source
        }
        if leaked:
            raise AssertionError(
                f"{relative_path} bypasses the DID-only trust boundary with: {sorted(leaked)}"
            )


def _assert_dto_shapes(protocol_root: Path) -> None:
    manifest = _load_json(DTO_SHAPES)
    if manifest.get("schema_version") != 1:
        raise AssertionError("gateway public DTO shape contract has an unknown version")
    seen: set[str] = set()
    for model in manifest.get("models", []):
        name = model["model"]
        if name in seen:
            raise AssertionError(f"duplicate gateway public DTO shape: {name}")
        seen.add(name)
        schema_path = protocol_root / "schemas" / model["schema"]
        schema = _load_json(schema_path)
        schema_fields = set(schema.get("properties", {}))
        runtime_fields = set(model["fields"])
        if runtime_fields != schema_fields:
            raise AssertionError(
                f"{name} fields drifted from marty-protocol: "
                f"schema_only={sorted(schema_fields - runtime_fields)}, "
                f"runtime_only={sorted(runtime_fields - schema_fields)}"
            )
        schema_required = set(schema.get("required", []))
        runtime_required = set(model["required"])
        if runtime_required != schema_required:
            raise AssertionError(
                f"{name} required fields drifted from marty-protocol: "
                f"schema_only={sorted(schema_required - runtime_required)}, "
                f"runtime_only={sorted(runtime_required - schema_required)}"
            )
        forbidden = FORBIDDEN_PUBLIC_FIELDS
        if model["schema"].startswith("organization"):
            forbidden = FORBIDDEN_ORGANIZATION_FIELDS
        if model["schema"].startswith(
            (
                "flow",
                "issuance",
                "issued-credential",
                "credential-renewal",
                "didcomm",
                "verification-result",
            )
        ):
            forbidden = FORBIDDEN_FLOW_FIELDS
        leaked = forbidden & _property_names(schema)
        if leaked:
            raise AssertionError(
                f"marty-protocol {model['schema']} exposes private state: {sorted(leaked)}"
            )


def _rust_service_source() -> str:
    sources: list[str] = []
    for service in sorted((REPO_ROOT / "rust" / "services").iterdir()):
        if not service.is_dir():
            continue
        for path in sorted(service.rglob("*.rs")):
            sources.append(path.read_text(encoding="utf-8"))
    return "\n".join(sources)


def _assert_rust_behavior_vectors() -> None:
    source = _rust_service_source()
    vectors = sorted((REPO_ROOT / "contracts").glob("gateway-*-behavior.json"))
    vectors.extend(
        REPO_ROOT / "contracts" / name
        for name in (
            "credential-metadata-behavior.json",
            "vc-api-adapter-behavior.json",
        )
    )
    missing = [path.name for path in vectors if path.name not in source]
    if missing:
        raise AssertionError(
            "gateway behavior vectors are not executed by Rust tests: "
            + ", ".join(missing)
        )


def check_contract(protocol_root: Path) -> None:
    _assert_protocol_version(protocol_root)
    assert_generated_bindings_current(protocol_root)
    assert_documented_public_boundary()
    _assert_trust_ui_boundary()
    _assert_dto_shapes(protocol_root)
    _assert_rust_behavior_vectors()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol-root", type=Path, required=True)
    args = parser.parse_args()
    check_contract(args.protocol_root.resolve())
    print("Rust gateway operations match the pinned marty-protocol schemas.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
