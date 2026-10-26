"""Adversarial contract/ownership cases for the real-image offline export probe."""

import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("gateway_export", ROOT / "scripts/check_gateway_openapi_export.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
REVISION = "a" * 40


def document():
    schemas = json.loads((ROOT / "contracts/api-key-http-schemas.json").read_text(encoding="utf-8"))
    return {
        "openapi": "3.1.0", "info": {"title": "Fixture", "version": "fixture"},
        "x-marty-protocol-revision": REVISION,
        "components": {"schemas": schemas, "securitySchemes": {
            "apiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "Marty API key"},
        }},
        "paths": {
            "/v1/api-keys": {
                "get": {"operationId": "list_keys", "responses": {"200": {"description": "List"}}},
                "post": {"operationId": "create_key", "responses": {"201": {"description": "Created"}},
                         "requestBody": {"content": {"application/json": {"schema": {
                             "$ref": "#/components/schemas/runtime__api_key_create_request"}}}}},
            },
            "/v1/api-keys/{key_id}": {"delete": {"operationId": "retire_key",
                "parameters": [{"name": "key_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Revoked"}}}},
        },
    }


def test_contract_coverage_does_not_claim_undocumented_operations_are_typed():
    report = MODULE.validate_document(document(), "fixture", REVISION)
    assert report["operations"] == report["request_schema_not_marked_documented"] == report["response_schema_not_marked_documented"] == 3


@pytest.mark.parametrize("mutation", ["dangling", "external", "duplicate_id", "oauth", "wrong_revision"])
def test_rejects_unusable_or_misleading_exported_contracts(mutation):
    value = copy.deepcopy(document())
    if mutation in {"dangling", "external"}:
        ref = "#/components/schemas/missing" if mutation == "dangling" else "https://untrusted.invalid/schema.json"
        value["components"]["schemas"]["runtime__api_key_response"]["properties"]["id"] = {"$ref": ref}
    elif mutation == "duplicate_id":
        value["paths"]["/v1/api-keys"]["post"]["operationId"] = "list_keys"
    elif mutation == "oauth":
        value["components"]["securitySchemes"]["bearerAuth"]["bearerFormat"] = "OAuth2 access token"
    else:
        value["x-marty-protocol-revision"] = "b" * 40
    with pytest.raises(ValueError):
        MODULE.validate_document(value, "fixture", REVISION)


@pytest.mark.parametrize("failure", ["foreign_label", "unlabeled", "daemon_unavailable"])
def test_cleanup_preserves_unowned_or_uninspectable_containers(monkeypatch, failure):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if failure == "daemon_unavailable":
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"Cannot connect to Docker daemon")
        labels = None if failure == "unlabeled" else {"io.marty.contract-export-probe": "another-owner"}
        data = [{"Config": {"Labels": labels}}]
        return SimpleNamespace(returncode=0, stdout=json.dumps(data).encode(), stderr=b"")

    monkeypatch.setattr(MODULE.subprocess, "run", run)
    with pytest.raises(ValueError):
        MODULE.cleanup_owned("unique-probe", "expected-owner")
    assert len(calls) == 1
    assert not any("stop" in call or "rm" in call for call in calls)
