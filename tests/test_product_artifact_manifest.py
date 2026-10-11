from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts/check_product_artifact_manifest.py"
SPEC = importlib.util.spec_from_file_location("check_product_artifact_manifest", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
SCHEMA = json.loads((ROOT / "deploy-config/schemas/product-artifact-manifest.schema.json").read_text(encoding="utf-8"))
DIGEST = "sha256:" + "a" * 64


@pytest.fixture
def manifest():
    return {
        "schema": "marty.product-artifact/v1",
        "product": "headless-edge-verification",
        "support_state": "preview",
        "capabilities": ["offline-verification"],
        "platform": {"os": "linux", "architecture": "amd64"},
        "artifact": {"uri": f"ghcr.io/elevenid/edge@{DIGEST}", "digest": DIGEST},
        "source": {"repository": "https://github.com/ElevenID/marty-ui", "commit": "b" * 40},
        "license": {"expression": "Apache-2.0", "notice": {"uri": "https://example.test/NOTICE", "digest": DIGEST}},
        "sbom": {"uri": "https://example.test/sbom.json", "digest": DIGEST},
        "provenance": {"uri": "https://example.test/provenance.json", "digest": DIGEST},
        "signature": {"uri": "https://example.test/signature.json", "digest": DIGEST},
        "compatibility": {"schemas": ["test-schema-v1"], "protocols": []},
        "dependencies": [{"name": "trust-bundle", "scope": "runtime", "source": "https://example.test/trust-bundle"}],
        "extensions": [],
        "installation": {"channel": "https://example.test/releases", "guide": "https://example.test/install"},
        "qualification": {"state": "unqualified", "evidence": []},
    }


def test_preview_candidate_is_structurally_valid(manifest):
    MODULE.validate_manifest(manifest, SCHEMA)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m.update(support_state="supported"),
        lambda m: m["artifact"].update(uri="ghcr.io/elevenid/edge:latest"),
        lambda m: m["artifact"].update(uri="ghcr.io/elevenid/edge@sha256:" + "c" * 64),
        lambda m: m["sbom"].update(uri="http://example.test/sbom.json"),
        lambda m: m.pop("signature"),
        lambda m: m["source"].update(commit="main"),
        lambda m: m["license"].update(expression=""),
        lambda m: m["dependencies"].append({"name": "canvas", "scope": "optional-extension", "source": "https://example.test/canvas"}),
        lambda m: m["extensions"].append("canvas"),
        lambda m: m["platform"].update(unexpected="arm64"),
        lambda m: m["capabilities"].append("offline-verification"),
    ],
)
def test_incomplete_or_mutable_manifest_fails_closed(manifest, mutate):
    invalid = copy.deepcopy(manifest)
    mutate(invalid)
    with pytest.raises(ValueError):
        MODULE.validate_manifest(invalid, SCHEMA)


def test_qualified_descriptor_requires_evidence(manifest):
    manifest["support_state"] = "supported"
    manifest["qualification"]["state"] = "qualified"
    with pytest.raises(ValueError, match="evidence"):
        MODULE.validate_manifest(manifest, SCHEMA)
    manifest["qualification"]["evidence"] = ["https://example.test/qualification/run-1"]
    MODULE.validate_manifest(manifest, SCHEMA)


def test_declared_extension_matches_optional_dependency(manifest):
    manifest["extensions"] = ["canvas"]
    manifest["dependencies"].append({"name": "canvas", "scope": "optional-extension", "source": "https://example.test/canvas"})
    MODULE.validate_manifest(manifest, SCHEMA)


@pytest.mark.parametrize("uri", [
    "https://user:pass@example.test/source",
    "https://@example.test/source",
    "https://example.test:bad/source",
    "https://example.test:99999/source",
    "https://example..test/source",
    "https://example.test/source#fragment",
    "https://example.test/source\n",
])
@pytest.mark.parametrize("field", ["source", "dependency", "channel", "guide", "evidence"])
def test_all_https_references_reject_malformed_or_credentialed_authorities(manifest, field, uri):
    if field == "source":
        manifest["source"]["repository"] = uri
    elif field == "dependency":
        manifest["dependencies"][0]["source"] = uri
    elif field in ("channel", "guide"):
        manifest["installation"][field] = uri
    else:
        manifest["qualification"]["evidence"] = [uri]
    with pytest.raises(ValueError):
        MODULE.validate_manifest(manifest, SCHEMA)


@pytest.mark.parametrize("path", ["../edge", "a/../edge", "./edge", "a//edge", "a/./edge", "/edge", "edge/"])
def test_oci_path_must_be_canonical(manifest, path):
    manifest["artifact"]["uri"] = f"ghcr.io/{path}@{DIGEST}"
    with pytest.raises(ValueError, match="artifact"):
        MODULE.validate_manifest(manifest, SCHEMA)
