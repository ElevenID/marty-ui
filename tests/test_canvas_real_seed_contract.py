"""Freeze the current Canvas gateway seed requests before the Rust port."""

from __future__ import annotations

import asyncio
import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import seed_canvas_real as seed  # noqa: E402


def config(**overrides: object) -> seed.ConnectorSeedConfig:
    values = {
        "issuance_base_url": "http://localhost:8000",
        "issuance_api_key": "test-gateway-key",
        "internal_issuance_base_url": "http://issuance:8008",
        "internal_issuance_api_key": "test-issuance-key",
        "organization_id": "org-1",
        "canvas_account_id": "account-1",
        "credential_template_id": "ct-1",
        "application_template_id": "at-1",
        "display_name": "Canvas Demo",
        "canvas_base_url": "https://canvas.example",
        "lti_tool_base_url": "https://marty.example",
        "lti_client_id": "client-1",
        "lti_deployment_id": "deployment-1",
        "probe_after_upsert": True,
        "program_binding_seed_enabled": True,
        "program_binding_display_name": "Program Demo",
        "program_binding_evidence_type": "canvas.quiz_score",
        "program_binding_delivery_mode": "wallet_plus_canvas_mirror",
        "program_binding_auto_approve": True,
        "program_binding_direct_issue": False,
        "program_binding_score_threshold": 80,
        "open_badge_scenario_enabled": True,
        "demo_application_seed_enabled": False,
        "demo_evidence_event_enabled": False,
        "demo_wallet_claim_enabled": False,
        "demo_mirror_publish_enabled": False,
        "signing_keys_internal_base_url": "http://signing-keys:8000",
        "signing_keys_internal_api_key": "test-signing-key",
    }
    values.update(overrides)
    return seed.ConnectorSeedConfig(**values)


def capture(monkeypatch) -> dict:
    operations = []
    responses = []

    def request(method, url, *, payload=None, headers=None, timeout=20):
        operations.append({"method": method, "url": url, "payload": payload})
        return responses.pop(0)

    monkeypatch.setattr(seed, "_json_request", request)
    cfg = config()
    responses.extend([[], {"id": "platform-1"}, {"platform": {"id": "platform-1"}}])
    platform_create = seed._upsert_canvas_platform(cfg)
    responses.extend([
        [{"id": "platform-1", "organization_id": "org-1", "canvas_account_id": "account-1", "lti_issuer": "https://canvas.example", "lti_jwks_json": {"keys": []}}],
        {"id": "platform-1"},
        {"platform": {"id": "platform-1"}},
    ])
    platform_update = seed._upsert_canvas_platform(cfg)
    scope = {"course_id": "42", "quiz_id": "9"}
    responses.extend([[], {"id": "binding-1"}])
    binding_create = seed._upsert_canvas_program_binding(cfg, {"id": "platform-1"}, scope)
    cfg.program_binding_evidence_type = "canvas.course_completion"
    cfg.program_binding_delivery_mode = "wallet_only"
    responses.extend([
        [{"id": "binding-1", "credential_template_id": "ct-1", "canvas_scope": scope}],
        {"id": "binding-1"},
    ])
    binding_update = seed._upsert_canvas_program_binding(cfg, {"id": "platform-1"}, scope)
    assert not responses
    return {
        "operations": operations,
        "actions": [platform_create["action"], platform_update["action"], binding_create["action"], binding_update["action"]],
        "scope": seed._canvas_demo_scope(course_id=42, quiz_id=9, assignment_id=0),
        "remote_signing": seed._canvas_open_badge_remote_signing_config(cfg),
    }


def test_frozen_gateway_seed_behavior(monkeypatch) -> None:
    contract = json.loads((ROOT / "contracts/canvas-real-seed-behavior-v1.json").read_text())
    assert capture(monkeypatch) == contract["gateway_seed"]


def capture_database(monkeypatch, *, remote_columns: bool, scope: dict) -> dict:
    writes = []
    transaction = {"begun": False, "committed": False, "disposed": False}

    class Connection:
        async def scalar(self, query, params):
            if "to_regclass" in query:
                return True
            assert "information_schema.columns" in query
            return remote_columns

        async def execute(self, query, params):
            assert "ON CONFLICT (id) DO UPDATE" in query
            values = dict(params)
            for key in (
                "claims", "selective_disclosure_fields", "zk_predicate_claims",
                "derived_attributes", "display_style", "validity_rules",
                "issuer_requirements", "supported_formats", "wallet_configs",
                "remote_signing_config", "form_fields", "evidence_requirements",
                "claim_collection_rules", "required_checks", "auto_approval_rules",
                "ui_config", "notification_config",
            ):
                if key in values:
                    values[key] = json.loads(values[key])
            writes.append({
                "table": "credential_templates" if "credential_template_service.credential_templates" in query else "application_templates",
                "has_remote_signing_columns": "remote_signing_config, version" in query,
                "payload": values,
            })

    class Transaction:
        async def __aenter__(self):
            transaction["begun"] = True
            return Connection()

        async def __aexit__(self, error_type, _error, _traceback):
            transaction["committed"] = error_type is None

    class Engine:
        def begin(self):
            return Transaction()

        async def dispose(self):
            transaction["disposed"] = True

    sqlalchemy = types.ModuleType("sqlalchemy")
    sqlalchemy.text = lambda sql: sql
    ext = types.ModuleType("sqlalchemy.ext")
    ext_asyncio = types.ModuleType("sqlalchemy.ext.asyncio")
    ext_asyncio.create_async_engine = lambda *_args, **_kwargs: Engine()
    monkeypatch.setitem(sys.modules, "sqlalchemy", sqlalchemy)
    monkeypatch.setitem(sys.modules, "sqlalchemy.ext", ext)
    monkeypatch.setitem(sys.modules, "sqlalchemy.ext.asyncio", ext_asyncio)
    asyncio.run(seed._seed_canvas_open_badge_templates_async(config(), canvas_scope=scope))
    return {"writes": writes, "transaction": transaction}


def test_frozen_badge_template_database_behavior(monkeypatch) -> None:
    contract = json.loads((ROOT / "contracts/canvas-real-seed-behavior-v1.json").read_text())
    assert capture_database(monkeypatch, remote_columns=False, scope={}) == contract["database_seed"]["modern_schema"]
    assert capture_database(monkeypatch, remote_columns=True, scope={"course_id": "42", "quiz_id": "9"}) == contract["database_seed"]["legacy_remote_columns"]
