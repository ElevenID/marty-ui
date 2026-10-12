"""Freeze the current Canvas gateway seed requests before the Rust port."""

from __future__ import annotations

import asyncio
import base64
import hashlib
from dataclasses import asdict
import json
import sys
import types
from datetime import date as real_date
from pathlib import Path
from urllib.error import HTTPError

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


def canvas_config(**overrides: object) -> seed.CanvasSeedConfig:
    values = {
        "enabled": True,
        "api_base_url": "http://canvas:8088",
        "browser_base_url": "https://canvas.example",
        "admin_token": "test-canvas-token",
        "admin_email": "admin@example.com",
        "admin_password": "test-admin-password",
        "account_id": "1",
        "container_name": "marty-canvas-real",
        "course_name": "Marty Course",
        "course_code": "MARTY-101",
        "course_sis_id": "marty-course",
        "learner_name": "Test Learner",
        "learner_email": "learner@example.com",
        "learner_password": "test-learner-password",
        "launch_seed_enabled": True,
        "launch_module_name": "Credential Launch",
        "launch_item_title": "Launch Credential",
        "launch_assignment_name": "Credential Assignment",
        "quiz_seed_enabled": True,
        "quiz_title": "Credential Quiz",
        "quiz_description": "Quiz description",
        "quiz_passing_score_percent": 92,
        "quiz_points_possible": 100,
    }
    values.update(overrides)
    return seed.CanvasSeedConfig(**values)


def capture_canvas_core_rest(monkeypatch) -> dict:
    operations = []
    responses = []

    def request(method, url, *, payload=None, headers=None, timeout=20):
        operations.append({"method": method, "url": url, "payload": payload, "form": None})
        return responses.pop(0)

    def form_request(method, url, *, form, headers=None, timeout=20):
        operations.append({"method": method, "url": url, "payload": None, "form": form})
        return responses.pop(0)

    monkeypatch.setattr(seed, "_json_request", request)
    monkeypatch.setattr(seed, "_form_request", form_request)
    cfg = canvas_config()
    responses.extend([
        [],
        {"id": 42, "name": cfg.course_name, "course_code": cfg.course_code},
        [],
        [{"id": 77, "name": cfg.learner_name, "login_id": cfg.learner_email}],
        [],
        {"id": 88, "user_id": 77},
    ])
    course = seed._ensure_canvas_course(cfg)
    learner = seed._ensure_canvas_user(cfg)
    enrollment = seed._ensure_canvas_enrollment(cfg, course["id"], learner["id"])
    responses.extend([
        [{"id": 42, "sis_course_id": cfg.course_sis_id}],
        [{"id": 77, "login_id": cfg.learner_email}],
        [{"id": 88, "user_id": 77}],
    ])
    existing_course = seed._ensure_canvas_course(cfg)
    existing_learner = seed._ensure_canvas_user(cfg)
    existing_enrollment = seed._ensure_canvas_enrollment(cfg, 42, 77)
    assert not responses
    return {
        "operations": operations,
        "created": {"course": course, "learner": learner, "enrollment": enrollment},
        "existing": {
            "course": existing_course,
            "learner": existing_learner,
            "enrollment": existing_enrollment,
        },
    }


def test_frozen_canvas_core_rest(monkeypatch) -> None:
    contract = json.loads((ROOT / "contracts/canvas-real-seed-behavior-v1.json").read_text())
    assert capture_canvas_core_rest(monkeypatch) == contract["canvas_core_rest"]


def capture_canvas_launch_surface_rest(monkeypatch) -> dict:
    operations = []
    responses = []

    def request(method, url, *, payload=None, headers=None, timeout=20):
        operations.append({"method": method, "url": url, "payload": payload, "form": None})
        return responses.pop(0)

    def form_request(method, url, *, form, headers=None, timeout=20):
        operations.append({"method": method, "url": url, "payload": None, "form": form})
        return responses.pop(0)

    monkeypatch.setattr(seed, "_json_request", request)
    monkeypatch.setattr(seed, "_form_request", form_request)
    cfg = canvas_config()
    launch_url = "https://marty.example/launch"
    responses.extend([
        [], {"id": 10, "name": cfg.launch_module_name},
        [], {"id": 11, "title": cfg.launch_item_title, "url": launch_url, "published": True},
        [], {"id": 12, "title": cfg.quiz_title},
        [], {"id": 13, "title": cfg.quiz_title},
        [], {"id": 14, "name": cfg.launch_assignment_name},
        [{"id": 10, "name": cfg.launch_module_name}],
        [{"id": 11, "title": cfg.launch_item_title, "url": "https://stale.example/launch", "published": False}],
        {"id": 11, "title": cfg.launch_item_title, "url": launch_url, "published": True},
        [{"id": 12, "title": cfg.quiz_title}],
        [{"id": 13, "title": cfg.quiz_title}],
        [{"id": 14, "name": cfg.launch_assignment_name}],
        {"id": 14, "name": cfg.launch_assignment_name},
    ])
    created = {
        "module": seed._ensure_canvas_module(cfg, 42),
        "tool_item": seed._ensure_canvas_module_external_tool_item(cfg, 42, 10, launch_url, 99),
        "quiz": seed._ensure_canvas_quiz(cfg, 42),
        "quiz_item": seed._ensure_canvas_module_quiz_item(cfg, 42, 10, 12),
        "assignment": seed._ensure_canvas_external_tool_assignment(cfg, 42, launch_url),
    }
    existing = {
        "module": seed._ensure_canvas_module(cfg, 42),
        "tool_item": seed._ensure_canvas_module_external_tool_item(cfg, 42, 10, launch_url, 99),
        "quiz": seed._ensure_canvas_quiz(cfg, 42),
        "quiz_item": seed._ensure_canvas_module_quiz_item(cfg, 42, 10, 12),
        "assignment": seed._ensure_canvas_external_tool_assignment(cfg, 42, launch_url),
    }
    assert not responses
    return {"operations": operations, "created": created, "existing": existing}


def test_frozen_canvas_launch_surface_rest(monkeypatch) -> None:
    contract = json.loads((ROOT / "contracts/canvas-real-seed-behavior-v1.json").read_text())
    assert capture_canvas_launch_surface_rest(monkeypatch) == contract["canvas_launch_surface_rest"]


def capture_canvas_module_item_retries(monkeypatch) -> dict:
    forms = []
    responses = [422, 400, {"id": 13}]

    def form_request(method, url, *, form, headers=None, timeout=20):
        forms.append(form)
        response = responses.pop(0)
        if isinstance(response, int):
            raise HTTPError(url, response, "incompatible module item form", None, None)
        return response

    monkeypatch.setattr(seed, "_form_request", form_request)
    cfg = canvas_config()
    result = seed._create_canvas_module_item_with_retries(
        cfg,
        "http://canvas:8088/api/v1/courses/42/modules/10/items",
        {
            "module_item[title]": cfg.quiz_title,
            "module_item[type]": "Quiz",
            "module_item[content_id]": "12",
            "module_item[published]": "true",
            "module_item[completion_requirement][type]": "must_submit",
        },
    )
    assert not responses
    return {"forms": forms, "result": result}


def test_frozen_canvas_module_item_retries(monkeypatch) -> None:
    contract = json.loads((ROOT / "contracts/canvas-real-seed-behavior-v1.json").read_text())
    assert capture_canvas_module_item_retries(monkeypatch) == contract["canvas_module_item_retries"]


def capture_canvas_rails_lti(monkeypatch) -> dict:
    operations = []
    rails_scripts = []

    def run(command, *, input=None, text=True, capture_output=True, check=False, timeout=None):
        assert text and capture_output and not check
        if command[:2] == ["docker", "ps"]:
            return types.SimpleNamespace(returncode=0, stdout="stack_marty-canvas-real\n", stderr="")
        assert command[:2] == ["docker", "exec"]
        encoded_env = next((part for part in command if part.startswith("CANVAS_LTI_SETUP_B64=")), None)
        if encoded_env:
            payload = json.loads(base64.b64decode(encoded_env.split("=", 1)[1]))
            rails_scripts.append(input)
            operations.append({
                "command": [part if not part.startswith("CANVAS_LTI_SETUP_B64=") else "CANVAS_LTI_SETUP_B64=<payload>" for part in command],
                "payload": payload,
                "script_sha256": hashlib.sha256(input.encode()).hexdigest(),
                "timeout": timeout,
            })
            if "public_host" in payload:
                output = {"public_domain": {"action": "updated", "host": payload["public_host"], "accounts": [{"id": 1}]}}
            else:
                output = {"developer_key": {"id": 5, "action": "created", "name": "client-1", "global_id": "client-1"}}
                if "course_id" in payload:
                    output["external_tool"] = {"id": 99, "action": "created", "name": "Canvas Demo"}
            return types.SimpleNamespace(returncode=0, stdout=seed.CANVAS_RAILS_RESULT_PREFIX + json.dumps(output) + "\n", stderr="")
        raise AssertionError(command)

    monkeypatch.setattr(seed.subprocess, "run", run)
    cfg = canvas_config()
    connector = config()
    key = seed._ensure_canvas_developer_key(cfg, connector, "platform-1")
    domain = seed._ensure_canvas_public_domain(cfg)
    tool = seed._ensure_canvas_external_tool(cfg, connector, "platform-1", 42, key["key"])
    assert len(set(rails_scripts)) == 1
    return {"operations": operations, "developer_key": key, "public_domain": domain, "external_tool": tool}


def test_frozen_canvas_rails_lti(monkeypatch) -> None:
    contract = json.loads((ROOT / "contracts/canvas-real-seed-behavior-v1.json").read_text())
    assert capture_canvas_rails_lti(monkeypatch) == contract["canvas_rails_lti"]


def capture_canvas_admin_bootstrap(monkeypatch) -> dict:
    cfg = canvas_config()

    def scenario(initially_exists: bool, mint: bool) -> dict:
        operations = []
        checks = 0

        def run(command, *, input=None, text=True, capture_output=True, check=False, timeout=None):
            nonlocal checks
            assert text and capture_output and not check
            if command[:2] == ["docker", "ps"]:
                return types.SimpleNamespace(returncode=0, stdout="stack_marty-canvas-real\n", stderr="")
            assert command[:2] == ["docker", "exec"]
            sanitized = [
                part if not part.startswith("CANVAS_ADMIN_TOKEN_SETUP_B64=") else "CANVAS_ADMIN_TOKEN_SETUP_B64=<payload>"
                for part in command
            ]
            operation = {"command": sanitized, "input": input, "timeout": timeout}
            if input and "require \"base64\"" in input:
                operation["script_sha256"] = hashlib.sha256(input.encode()).hexdigest()
                operation["input"] = "<token-script>"
                encoded = next(part.split("=", 1)[1] for part in command if part.startswith("CANVAS_ADMIN_TOKEN_SETUP_B64="))
                operation["payload"] = json.loads(base64.b64decode(encoded))
            operations.append(operation)
            if "CANVAS_ADMIN_EMAIL=" in " ".join(command):
                checks += 1
                answer = "yes" if initially_exists or checks > 1 else "no"
                return types.SimpleNamespace(returncode=0, stdout=answer + "\n", stderr="")
            if "db:load_initial_data" in command[-1]:
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")
            return types.SimpleNamespace(returncode=0, stdout=seed.CANVAS_RAILS_TOKEN_PREFIX + "test-admin-token\n", stderr="")

        monkeypatch.setattr(seed.subprocess, "run", run)
        value = seed._mint_canvas_admin_token(cfg) if mint else seed._ensure_canvas_initial_data(cfg)
        return {"operations": operations, "result": value}

    return {"initial_data": scenario(False, False), "mint_token": scenario(True, True)}


def test_frozen_canvas_admin_bootstrap(monkeypatch) -> None:
    contract = json.loads((ROOT / "contracts/canvas-real-seed-behavior-v1.json").read_text())
    assert capture_canvas_admin_bootstrap(monkeypatch) == contract["canvas_admin_bootstrap"]


def capture_canvas_cli_config(monkeypatch) -> dict:
    captured = {}
    environment = {
        "MARTY_API_KEY": "test-gateway-key",
        "ISSUANCE_INTERNAL_API_BASE_URL": "http://issuance:8008",
        "ISSUANCE_API_KEY": "test-issuance-key",
    }
    monkeypatch.setattr(seed.os, "environ", environment)
    monkeypatch.setattr(seed, "_load_dotenv", lambda _path: None)
    monkeypatch.setattr(seed.sys, "argv", ["seed_canvas_real.py", "--skip-canvas-lms-seed", "--probe-after-upsert"])
    monkeypatch.setattr(seed, "_seed_canvas_open_badge_templates", lambda *_args, **_kwargs: None)

    def upsert(cfg):
        captured["connector"] = asdict(cfg)
        return {"action": "created", "platform": {"id": "platform-1", "lti_client_id": cfg.lti_client_id, "lti_deployment_id": cfg.lti_deployment_id}}

    def demo_application(_connector, canvas, *, canvas_seed):
        captured["canvas"] = asdict(canvas)
        assert canvas_seed is None
        return {"id": "application-1", "status": "pending"}

    monkeypatch.setattr(seed, "_upsert_canvas_platform", upsert)
    monkeypatch.setattr(seed, "_refresh_canvas_platform_jwks", lambda *_args: {"platform": {"id": "platform-1", "lti_jwks_json": {"keys": []}}})
    monkeypatch.setattr(seed, "_upsert_canvas_program_binding", lambda *_args, **_kwargs: {"action": "created", "binding": {"id": "binding-1"}})
    monkeypatch.setattr(seed, "_resolve_issuer_context_summary", lambda *_args: None)
    monkeypatch.setattr(seed, "_create_canvas_demo_application", demo_application)
    assert seed.main() == 0
    return captured


def test_frozen_canvas_cli_config(monkeypatch, capsys) -> None:
    contract = json.loads((ROOT / "contracts/canvas-real-seed-behavior-v1.json").read_text())
    assert capture_canvas_cli_config(monkeypatch) == contract["canvas_cli_config"]
    capsys.readouterr()


def capture_canvas_transition(monkeypatch) -> dict:
    queries = []
    application = {"application_id": "application-1", "application_status": "approved", "issuance_transaction_id": "tx-1", "credential_type": "OpenBadgeCredential", "credential_template_id": "ct-1", "transaction_status": "issued", "issuer_profile_id": "profile-1", "issuer_mode": "org_managed", "issuer_did_override": "did:web:marty.example", "signing_service_id": "managed-openbao-transit", "delivery_mode": "wallet_plus_canvas_mirror", "credential_payload_format": "vc+sd-jwt", "has_pre_auth_code": True}
    fact = {"provider": "canvas", "fact_type": "canvas.quiz_score", "scope": {}, "assertion": {"score_percent": 92}, "verification": {"status": "verified"}, "created_at": "2025-04-05T00:00:00Z"}
    issued = {"id": "credential-1", "subject_did": "did:example:learner", "issuer_did": "did:web:marty.example", "revocation_profile_id": "rev-1", "status_list_entries": [], "status": "active", "issued_at": "2025-04-05T00:00:00Z", "expires_at": None}
    delivery = {"id": "delivery-1", "delivery_target": "canvas_credentials", "delivery_mode": "wallet_plus_canvas_mirror", "status": "delivered", "external_credential_id": "badge-1", "external_issuer_id": None, "last_error": None, "metadata": {"provider": "canvas_credentials_api"}, "updated_at": "2025-04-05T00:00:00Z"}

    class Result:
        def __init__(self, value):
            self.value = value
        def mappings(self):
            return self
        def first(self):
            return self.value
        def all(self):
            return self.value

    class Connection:
        async def execute(self, query, params):
            sql = str(query)
            queries.append({"query": " ".join(sql.split()), "params": params})
            if "FROM issuance_service.applications a" in sql:
                return Result(application)
            if "FROM issuance_service.evidence_facts" in sql:
                return Result(fact)
            if "FROM issuance_service.issued_credentials" in sql:
                return Result(issued)
            if "FROM issuance_service.credential_delivery_records" in sql:
                return Result([delivery])
            raise AssertionError(sql)
        async def scalar(self, query, params):
            queries.append({"query": " ".join(str(query).split()), "params": params})
            return 1

    class Transaction:
        async def __aenter__(self):
            return Connection()
        async def __aexit__(self, *_args):
            return None

    class Engine:
        def begin(self):
            return Transaction()
        async def dispose(self):
            return None

    sqlalchemy = types.ModuleType("sqlalchemy")
    sqlalchemy.text = lambda sql: sql
    ext = types.ModuleType("sqlalchemy.ext")
    ext_asyncio = types.ModuleType("sqlalchemy.ext.asyncio")
    ext_asyncio.create_async_engine = lambda *_args, **_kwargs: Engine()
    monkeypatch.setitem(sys.modules, "sqlalchemy", sqlalchemy)
    monkeypatch.setitem(sys.modules, "sqlalchemy.ext", ext)
    monkeypatch.setitem(sys.modules, "sqlalchemy.ext.asyncio", ext_asyncio)
    monkeypatch.setattr(seed, "_resolve_database_url", lambda: "postgresql+asyncpg://localhost/test")
    summary = asyncio.run(seed._lookup_canvas_demo_transition_async("application-1"))
    return {"summary": summary, "queries": queries}


def test_frozen_canvas_transition(monkeypatch) -> None:
    contract = json.loads((ROOT / "contracts/canvas-real-seed-behavior-v1.json").read_text())
    assert capture_canvas_transition(monkeypatch) == contract["canvas_transition"]


def capture_canvas_lms_summary(monkeypatch) -> dict:
    cfg = canvas_config()
    monkeypatch.setattr(seed, "_ensure_canvas_public_domain", lambda *_args: {"action": "updated", "domain": "canvas.example", "accounts": []})
    monkeypatch.setattr(seed, "_ensure_canvas_course", lambda *_args: {"id": 42, "name": cfg.course_name, "course_code": cfg.course_code, "sis_course_id": cfg.course_sis_id})
    monkeypatch.setattr(seed, "_ensure_canvas_user", lambda *_args: {"id": 77, "name": cfg.learner_name, "login_id": cfg.learner_email})
    monkeypatch.setattr(seed, "_ensure_canvas_enrollment", lambda *_args, **_kwargs: {"id": 88, "user_id": 77})
    monkeypatch.setattr(seed, "_ensure_canvas_developer_key", lambda *_args: {"action": "created", "key": {"id": 5, "name": "client-1", "global_id": "client-1", "owner_binding_account_id": 1, "owner_binding_workflow_state": "on", "requested_binding_account_id": 1, "requested_binding_workflow_state": "on"}})
    monkeypatch.setattr(seed, "_ensure_canvas_external_tool", lambda *_args, **_kwargs: {"action": "created", "tool": {"id": 99, "name": "Canvas Demo", "deployment_id": "deployment-1"}})
    monkeypatch.setattr(seed, "_ensure_canvas_module", lambda *_args, **_kwargs: {"action": "created", "module": {"id": 10, "name": cfg.launch_module_name}})
    monkeypatch.setattr(seed, "_ensure_canvas_module_external_tool_item", lambda *_args, **_kwargs: {"action": "created", "item": {"id": 11, "title": cfg.launch_item_title, "html_url": "https://canvas.example/items/11"}})
    monkeypatch.setattr(seed, "_ensure_canvas_quiz", lambda *_args, **_kwargs: {"action": "created", "quiz": {"id": 12, "title": cfg.quiz_title, "html_url": "https://canvas.example/quizzes/12"}})
    monkeypatch.setattr(seed, "_ensure_canvas_module_quiz_item", lambda *_args, **_kwargs: {"action": "created", "item": {"id": 13, "title": cfg.quiz_title, "html_url": "https://canvas.example/items/13"}})
    monkeypatch.setattr(seed, "_ensure_canvas_external_tool_assignment", lambda *_args, **_kwargs: {"action": "created", "assignment": {"id": 14, "name": cfg.launch_assignment_name, "html_url": "https://canvas.example/assignments/14"}})
    complete = seed._seed_canvas_lms_objects(cfg, config(), "platform-1")
    def fail_assignment(*_args, **_kwargs):
        raise HTTPError("https://canvas.example", 422, "unsupported", None, None)
    monkeypatch.setattr(seed, "_ensure_canvas_external_tool_assignment", fail_assignment)
    assignment_error = seed._seed_canvas_lms_objects(cfg, config(), "platform-1")
    monkeypatch.setattr(seed, "_ensure_canvas_external_tool_assignment", lambda *_args, **_kwargs: {"action": "created", "assignment": {"id": 14, "name": cfg.launch_assignment_name, "html_url": "https://canvas.example/assignments/14"}})
    monkeypatch.setattr(seed, "_ensure_canvas_quiz", fail_assignment)
    quiz_error = seed._seed_canvas_lms_objects(cfg, config(), "platform-1")
    return {"complete": complete, "assignment_error": assignment_error, "quiz_error": quiz_error}


def test_frozen_canvas_lms_summary(monkeypatch) -> None:
    contract = json.loads((ROOT / "contracts/canvas-real-seed-behavior-v1.json").read_text())
    assert capture_canvas_lms_summary(monkeypatch) == contract["canvas_lms_summary"]


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


def capture_demo_evidence(monkeypatch) -> dict:
    operations = []

    class FixedDate:
        @staticmethod
        def today():
            return real_date(2025, 4, 5)

    class FixedUuid:
        hex = "abc12345" + "0" * 24

    def request(method, url, *, payload=None, headers=None, timeout=20):
        operations.append({"method": method, "url": url, "payload": payload, "timeout": timeout})
        return {"id": "application-1"}

    def signed_request(method, url, *, payload, secret, headers=None, timeout=20):
        assert secret == "test-shared-secret"
        operations.append({"method": method, "url": url, "payload": payload, "signed": True, "timeout": timeout})
        return {"id": "event-1"}

    monkeypatch.setattr(seed, "date", FixedDate)
    monkeypatch.setattr(seed.uuid, "uuid4", lambda: FixedUuid())
    monkeypatch.setattr(seed, "_json_request", request)
    monkeypatch.setattr(seed, "_signed_json_request", signed_request)
    monkeypatch.setitem(seed.os.environ, "CANVAS_CREDENTIALS_SHARED_SECRET", "test-shared-secret")
    canvas_seed = {
        "course": {"id": 42, "name": "Canvas Course"},
        "quiz": {"id": 9, "title": "Canvas Quiz"},
        "learner": {"id": 77},
        "enrollment": {"id": 88},
    }
    canvas = seed.CanvasSeedConfig(
        enabled=True, api_base_url="http://localhost:8088", browser_base_url="https://canvas.example",
        admin_token="test-admin-token", admin_email="admin@example.com", admin_password="test-password",
        account_id="1", container_name="test-canvas", course_name="Fallback Course",
        course_code="TEST", course_sis_id="test", learner_name="First Last",
        learner_email="learner@example.com", learner_password="test-password", launch_seed_enabled=True,
        launch_module_name="Module", launch_item_title="Launch", launch_assignment_name="Assignment",
        quiz_seed_enabled=True, quiz_title="Fallback Quiz", quiz_description="Demo", quiz_passing_score_percent=92,
        quiz_points_possible=100,
    )
    cfg = config()
    app = seed._create_canvas_demo_application(cfg, canvas, canvas_seed=canvas_seed)
    event = seed._emit_canvas_demo_ags_score_event(cfg, canvas, canvas_seed=canvas_seed, application=app)
    assert event == {"id": "event-1"}
    return {"operations": operations}


def test_frozen_demo_application_and_ags_event(monkeypatch) -> None:
    contract = json.loads((ROOT / "contracts/canvas-real-seed-behavior-v1.json").read_text())
    assert capture_demo_evidence(monkeypatch) == contract["demo_evidence"]


def capture_signed_ags_wire(monkeypatch) -> dict:
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            return b'{"ok":true}'

    def open_request(request, timeout):
        captured.update({
            "method": request.get_method(),
            "url": request.full_url,
            "body": request.data.decode("utf-8"),
            "headers": {key.lower(): value for key, value in request.header_items()},
            "timeout": timeout,
        })
        return Response()

    monkeypatch.setattr(seed, "urlopen", open_request)
    monkeypatch.setattr(seed.time, "time", lambda: 1743811200)
    assert seed._signed_json_request(
        "POST", "https://gateway.example/ags", payload={"z": 2, "a": {"y": 2, "x": 1}},
        secret="test-shared-secret",
    ) == {"ok": True}
    return captured


def test_frozen_signed_ags_wire(monkeypatch) -> None:
    contract = json.loads((ROOT / "contracts/canvas-real-seed-behavior-v1.json").read_text())
    assert capture_signed_ags_wire(monkeypatch) == contract["signed_ags_wire"]


def capture_wallet_claim(monkeypatch) -> dict:
    operations = []
    proofs = []
    responses = [
        {"grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code": {"pre-authorized_code": "offer-code"}}},
        {"access_token": "test-access-token", "c_nonce": "test-nonce"},
        {"credential": "header.payload.signature", "notification_id": "notify-1"},
    ]

    def json_request(method, url, *, payload=None, headers=None, timeout=20):
        operations.append({"method": method, "url": url, "payload": payload, "headers": headers, "timeout": timeout})
        return responses.pop(0)

    def form_request(method, url, *, form, headers=None, timeout=20):
        operations.append({"method": method, "url": url, "form": form, "headers": headers, "timeout": timeout})
        return responses.pop(0)

    marty_rs = types.ModuleType("marty_rs")

    def proof(audience, nonce):
        proofs.append({"audience": audience, "nonce": nonce})
        return "signed-proof"

    marty_rs.oid4vci_create_proof_jwt = proof
    monkeypatch.setitem(sys.modules, "marty_rs", marty_rs)
    monkeypatch.setattr(seed, "_json_request", json_request)
    monkeypatch.setattr(seed, "_form_request", form_request)
    monkeypatch.setitem(seed.os.environ, "PUBLIC_API_URL", "https://marty.example/")
    result = seed._claim_canvas_demo_wallet_credential(config(), transaction_id="tx-1")
    assert not responses
    return {"operations": operations, "proofs": proofs, "result": result}


def test_frozen_wallet_claim(monkeypatch) -> None:
    contract = json.loads((ROOT / "contracts/canvas-real-seed-behavior-v1.json").read_text())
    assert capture_wallet_claim(monkeypatch) == contract["wallet_claim"]


def capture_mirror_and_issuer_context(monkeypatch) -> dict:
    operations = []
    responses = [
        {"processed_count": 1, "publish": {"delivered_count": 1}},
        {"issuer_profile_id": "profile-1", "issuer_did": "did:web:marty.example", "signing_service_id": "managed-openbao-transit", "signing_key_reference": "key-ref", "verification_method_id": "did:web:marty.example#key-ref", "ignored": True},
    ]

    def request(method, url, *, payload=None, headers=None, timeout=20):
        operations.append({"method": method, "url": url, "payload": payload, "headers": headers, "timeout": timeout})
        return responses.pop(0)

    monkeypatch.setattr(seed, "_json_request", request)
    cfg = config()
    mirror = seed._run_canvas_demo_mirror_publish(cfg)
    context = seed._resolve_issuer_context_summary(cfg)
    assert not responses
    return {"operations": operations, "mirror": mirror, "issuer_context": context}


def test_frozen_mirror_and_issuer_context(monkeypatch) -> None:
    contract = json.loads((ROOT / "contracts/canvas-real-seed-behavior-v1.json").read_text())
    assert capture_mirror_and_issuer_context(monkeypatch) == contract["mirror_and_issuer_context"]
