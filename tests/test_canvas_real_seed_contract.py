"""Freeze the current Canvas gateway seed requests before the Rust port."""

from __future__ import annotations

import json
import sys
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
