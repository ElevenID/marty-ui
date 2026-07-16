from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "build_stack_manifest.py"
SPEC = importlib.util.spec_from_file_location("build_stack_manifest", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


@pytest.fixture
def stack_lock():
    return {
        "schema": "marty.stack-lock/v1",
        "release": "marty-ui@1.2.3",
        "components": [
            {
                "name": "marty-core",
                "repository": "ElevenID/marty-core",
                "version": "0.2.0",
                "commit": "a" * 40,
                "artifacts": [
                    {
                        "type": "crate",
                        "uri": "https://static.crates.io/crates/marty-core/marty-core-0.2.0.crate",
                        "digest": "sha256:" + "b" * 64,
                        "sbom": "https://github.com/ElevenID/marty-core/releases/download/v0.2.0/sbom.cdx.json",
                        "provenance": "https://github.com/ElevenID/marty-core/attestations/1",
                    }
                ],
            }
        ],
    }


def test_builds_public_v1_manifest(stack_lock):
    manifest = MODULE.build_manifest(stack_lock, generated_at="2026-07-16T00:00:00+00:00")
    assert manifest["schema"] == "marty.stack/v1"
    assert manifest["components"][0]["commit"] == "a" * 40


@pytest.mark.parametrize("field,value", [("commit", "main"), ("version", ""), ("repository", "marty-core")])
def test_rejects_mutable_or_incomplete_component_identity(stack_lock, field, value):
    invalid = copy.deepcopy(stack_lock)
    invalid["components"][0][field] = value
    with pytest.raises(ValueError):
        MODULE.validate_lock(invalid)


def test_rejects_tag_only_oci_reference(stack_lock):
    invalid = copy.deepcopy(stack_lock)
    invalid["components"][0]["artifacts"][0]["digest"] = "latest"
    with pytest.raises(ValueError, match="digest"):
        MODULE.validate_lock(invalid)
