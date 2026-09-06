from __future__ import annotations

import json
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "contracts" / "issuance-canvas-sync-worker.json"


def contract() -> dict:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def yaml_document(path: str) -> dict:
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def test_contract_freezes_every_whole_worker_capability() -> None:
    frozen = contract()
    generation_fence = frozen["persistence"]["jobs"]["native_internal_generation_fence"]
    assert generation_fence["field"] == "result.target_config_version"
    assert (
        generation_fence["visibility"] == "excluded by the public job result allowlist"
    )
    assert (
        "no other result or state differences are ignored"
        in generation_fence["comparison"]
    )

    assert frozen["schema"] == "marty.issuance-canvas-sync-worker/v1"
    assert frozen["provenance"]["repository"] == "ElevenID/marty-credentials"
    assert len(frozen["provenance"]["snapshot_commit"]) == 40
    assert frozen["provenance"]["snapshot_commit"] == (
        "cbda2ac7e3376b858c1e8d5d010a304474c659cf"
    )
    assert set(frozen["provenance"]["sources"]) == {
        "python/marty_credentials/native_backend.py",
        "services/issuance/canvas_worker.py",
        "services/issuance/application/canvas_evidence_revisions.py",
        "services/issuance/application/canvas_feature_flags.py",
        "services/issuance/application/canvas_sync_jobs.py",
        "services/issuance/application/canvas_sync_service.py",
        "services/issuance/application/canvas_lti_services.py",
        "services/issuance/application/canvas_oauth.py",
        "services/issuance/application/evidence_policy.py",
        "services/issuance/domain/entities.py",
        "services/issuance/domain/ports.py",
        "services/issuance/infrastructure/api/canvas_routes.py",
        "services/issuance/infrastructure/api/signing_context.py",
        "services/issuance/infrastructure/adapters/postgres_repository.py",
        "services/issuance/infrastructure/migrations/versions/20260714_1000_portable_canvas_connections.py",
        "services/issuance/infrastructure/models.py",
        "services/issuance/infrastructure/security/encryption.py",
    }
    assert len(frozen["provenance"]["oracle_tests"]) == 8
    for object_id in list(frozen["provenance"]["sources"].values()) + list(
        frozen["provenance"]["oracle_tests"].values()
    ):
        assert len(object_id) == 40
        int(object_id, 16)

    required_sections = {
        "semantic_boundary",
        "legacy_python_wiring",
        "deployment_wiring",
        "configuration",
        "cycle",
        "scheduling_and_leasing",
        "heartbeats",
        "shutdown",
        "target_validation",
        "processor_dispatch",
        "job_outcomes",
        "retry_and_backoff",
        "provider_io",
        "origin_and_network_security",
        "lti_signing",
        "integration_secret_compatibility",
        "application_reconciliation",
        "atomic_evidence_and_correction_review",
        "background_roster_reconciliation",
        "issued_drift",
        "oauth_revocation",
        "persistence",
        "durable_result_privacy",
        "executable_fixtures",
        "existing_rust_components",
        "migration_gates",
    }
    assert required_sections.issubset(frozen)

    assert frozen["cycle"]["ordering"] == [
        "write scheduling heartbeat",
        "process due OAuth revocations",
        "enqueue due sync targets",
        "lease ready jobs",
        "write processing-or-idle heartbeat",
        "start all leased jobs concurrently",
        "await all outcomes without sibling cancellation",
        "write idle heartbeat",
        "return bounded counters",
    ]
    assert set(frozen["heartbeats"]["worker_phases"]) == {
        "scheduling",
        "oauth_revocation",
        "processing",
        "idle",
    }
    assert frozen["shutdown"]["cancellation_propagates"] is True
    assert frozen["scheduling_and_leasing"]["stale_outcome"].startswith("discard")


def test_deployment_wiring_matches_the_frozen_process_and_defaults() -> None:
    frozen = contract()
    legacy = frozen["legacy_python_wiring"]
    compose_contract = frozen["deployment_wiring"]["compose"]
    worker_defaults = frozen["configuration"]["worker"]
    processor_defaults = frozen["configuration"]["processor"]
    expected_processor = legacy["processor_import"]

    assert legacy["normative_for_replacement"] is False
    assert (
        "any internal module or command layout"
        in frozen["semantic_boundary"]["replacement_rule"]
    )
    assert "loader_syntax" not in frozen["processor_dispatch"]
    assert legacy["processor_loader"]["replacement_rule"].startswith(
        "The Rust worker links its processor directly"
    )
    assert legacy["database_adapter"] == {
        "default_url": "postgresql://marty:marty_dev@postgres:5432/marty_credentials",
        "postgresql_scheme_rewrite": "postgresql+asyncpg",
        "sqlalchemy_pool_pre_ping": True,
        "sqlalchemy_pool_size": 5,
        "sqlalchemy_max_overflow": 5,
        "sqlalchemy_hide_parameters": True,
        "replacement_rule": (
            "These are Python/SQLAlchemy implementation details, not required Rust "
            "driver configuration."
        ),
    }
    database = frozen["configuration"]["database"]
    assert set(database) == {
        "input",
        "deployed_url_acceptance",
        "pooling",
        "connectivity",
        "parameter_redaction",
    }
    assert "ORM-specific scheme" in database["deployed_url_acceptance"]
    assert database["pooling"].startswith("bounded")

    for path in ("docker-compose.base.yml", "docker-compose.selfhost.prod.yml"):
        services = yaml_document(path)["services"]
        worker = services["canvas-sync-worker"]
        issuance = services["issuance"]
        assert "issuance.canvas_worker" in str(worker["command"])
        assert "canvas_worker" not in str(issuance.get("command", ""))
        assert worker["healthcheck"] == {"disable": True}
        assert "ports" not in worker
        assert worker["image"] == issuance["image"]
        assert set(compose_contract["startup_dependencies"]) == set(
            worker["depends_on"]
        )
        assert all(
            dependency["condition"] == "service_completed_successfully"
            for dependency in worker["depends_on"].values()
        )
        environment = worker["environment"]
        assert expected_processor in environment["CANVAS_SYNC_PROCESSOR"]
        for name, spec in worker_defaults.items():
            if name == "CANVAS_SYNC_WORKER_ID":
                continue
            assert f":-{spec['default']:g}}}" in environment[name]
        for name in (
            "CANVAS_BACKGROUND_ROSTER_BATCH_SIZE",
            "CANVAS_BACKGROUND_ROSTER_MAX_SIZE",
        ):
            assert f":-{processor_defaults[name]['default']}}}" in environment[name]

    config = yaml_document("k8s/oracle/01-configmap.yaml")["data"]
    assert config["CANVAS_SYNC_PROCESSOR"] == expected_processor
    for name, spec in worker_defaults.items():
        if name == "CANVAS_SYNC_WORKER_ID":
            continue
        assert float(config[name]) == float(spec["default"])
    for name in (
        "CANVAS_BACKGROUND_ROSTER_BATCH_SIZE",
        "CANVAS_BACKGROUND_ROSTER_MAX_SIZE",
    ):
        assert int(config[name]) == processor_defaults[name]["default"]


def test_kubernetes_wiring_and_migration_order_are_frozen_separately() -> None:
    frozen = contract()
    kubernetes_contract = frozen["deployment_wiring"]["kubernetes"]
    documents = list(
        yaml.safe_load_all(
            (ROOT / "k8s/oracle/07-microservices.yaml").read_text(encoding="utf-8")
        )
    )
    deployment = next(
        item
        for item in documents
        if item
        and item.get("kind") == "Deployment"
        and item.get("metadata", {}).get("name") == kubernetes_contract["deployment"]
    )
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    assert container["command"] == kubernetes_contract["legacy_command"]
    assert container["args"] == kubernetes_contract["legacy_args"]
    assert "ports" not in container
    assert container["envFrom"] == [
        {"configMapRef": {"name": kubernetes_contract["config_source"]}}
    ]
    secret_environment = {
        item["name"]: item["valueFrom"]["secretKeyRef"]["key"]
        for item in container["env"]
        if "valueFrom" in item
    }
    assert secret_environment == kubernetes_contract["secret_environment"]
    literal_environment = {
        item["name"]: item["value"] for item in container["env"] if "value" in item
    }
    assert literal_environment == kubernetes_contract["literal_environment"]

    migration = yaml_document("k8s/oracle/06a-issuance-migrations.yaml")
    assert migration["kind"] == "Job"
    assert migration["metadata"]["name"] == "issuance-migrations"
    deploy = (ROOT / "scripts/deploy-kubernetes.sh").read_text(encoding="utf-8")
    apply_migration = deploy.index(
        'apply_manifest "${K8S_DIR}/06a-issuance-migrations.yaml"'
    )
    wait_migration = deploy.index("condition=complete job/issuance-migrations")
    apply_services = deploy.index('apply_manifest "${K8S_DIR}/07-microservices.yaml"')
    assert apply_migration < wait_migration < apply_services


def test_state_error_and_persistence_sets_are_closed() -> None:
    frozen = contract()

    assert frozen["job_outcomes"]["states"] == [
        "queued",
        "leased",
        "retry",
        "succeeded",
        "dead_letter",
        "cancelled",
    ]
    validation_errors = {
        item["code"]: item["retryable"]
        for item in frozen["target_validation"]["errors"]
    }
    assert validation_errors == {
        "canvas_sync_target_incomplete": False,
        "canvas_sync_target_contains_secret": False,
        "canvas_sync_target_scope_invalid": False,
        "canvas_sync_target_inactive": False,
        "canvas_sync_target_config_stale": False,
        "canvas_sync_target_application_missing": False,
        "canvas_sync_target_application_invalid": False,
        "canvas_sync_target_candidate_missing": False,
        "canvas_sync_target_candidate_invalid": False,
    }
    assert set(frozen["processor_dispatch"]["supported_target_types"]) == {
        "learner_application",
        "issued_drift",
        "background_roster",
    }
    assert frozen["processor_dispatch"]["unsupported_target_types"] == [
        "award_candidate"
    ]
    assert frozen["persistence"]["targets"]["types"] == [
        "learner_application",
        "background_roster",
        "award_candidate",
        "issued_drift",
    ]
    assert frozen["persistence"]["jobs"]["active_unique_index"].endswith(
        "queued, leased, retry"
    )
    assert frozen["job_outcomes"]["dead_letter"] == "disable target"


def test_complete_processor_outcome_set_is_closed() -> None:
    outcomes = contract()["processor_dispatch"]["stable_outcomes"]
    by_code = {item["code"]: item["retryable"] for item in outcomes}
    assert len(by_code) == len(outcomes)
    assert by_code == {
        "canvas_sync_processor_unavailable": True,
        "canvas_sync_processor_contract_invalid": False,
        "canvas_background_signing_forbidden": False,
        "canvas_requirements_invalid": False,
        "canvas_application_template_unavailable": False,
        "canvas_lti_identity_missing": False,
        "canvas_platform_reconfigured": True,
        "canvas_application_unavailable": False,
        "canvas_rate_limited": True,
        "canvas_roster_configuration_invalid": False,
        "canvas_roster_oauth_unavailable": True,
        "canvas_nrps_roster_unavailable": True,
        "canvas_roster_collection_too_large": False,
        "canvas_sync_resources_unavailable": False,
        "canvas_authoritative_read_failed": "provider-defined",
        "canvas_sync_target_type_unsupported": False,
        "canvas_authoritative_reads_failed": True,
    }
    required_sources = {
        "dispatch",
        "application",
        "roster",
        "processor",
        "roster-provider",
    }
    assert required_sources.issubset({item["source"] for item in outcomes})


def test_atomic_evidence_and_correction_review_lifecycle_is_complete() -> None:
    lifecycle = contract()["atomic_evidence_and_correction_review"]

    assert lifecycle["transaction_lock"] == "tenant-owned application row FOR UPDATE"
    assert lifecycle["single_transaction"] == [
        "read previous current heads",
        "append or reuse immutable evidence revision",
        "advance head only when the observation is newer",
        "read current heads",
        "lock the one open correction review",
        "evaluate previous and current policy in the canonical Rust policy kernel",
        "create, update, recover, or mark the review",
        "append audit events",
    ]
    assert lifecycle["one_open_review"]["database_rule"].startswith(
        "unique partial index"
    )
    assert (
        lifecycle["review_creation"]["event"]
        == (lifecycle["audit_events"]["review_created"])
    )
    assert lifecycle["automatic_recovery"]["action"] == "evidence_recovered"
    assert lifecycle["automatic_recovery"]["credential_lifecycle_change"] == "none"
    assert lifecycle["manual_resolution"]["actions"] == [
        "dismiss",
        "suspend",
        "revoke",
    ]
    assert lifecycle["manual_resolution"]["lifecycle_before_finalize"] is True
    assert lifecycle["recovery_during_manual_claim"][
        "failed_manual_handler"
    ].startswith("release claim")
    assert lifecycle["rollback"].startswith("any persistence")


def test_language_neutral_backoff_lease_and_cursor_fixtures_are_exact() -> None:
    fixtures = contract()["executable_fixtures"]

    for case in fixtures["job_backoff"]:
        exponent = min(max(case["attempt_count"] - 1, 0), 10)
        base = min(3600, 15 * (2**exponent))
        assert base == case["base_seconds"]
        assert base // 3 == case["maximum_jitter_seconds"]

    for case in fixtures["lease_renewal_interval"]:
        interval = max(10.0, min(30.0, case["lease_seconds"] / 3))
        assert interval == case["interval_seconds"]

    for case in fixtures["cursor"]:
        cursor = case["cursor"]
        size = case["size"]
        if cursor < 0 or cursor >= size:
            cursor = 0
        assert cursor == case["normalized_cursor"]
        processed = min(case["batch_size"], max(0, size - cursor))
        next_cursor = cursor + processed
        if next_cursor >= size:
            next_cursor = 0
        assert next_cursor == case["next_cursor"]


def test_scheduler_and_postgres_race_fixtures_are_closed() -> None:
    fixtures = contract()["executable_fixtures"]

    scheduler = {case["name"]: case for case in fixtures["scheduler_conflict"]}
    assert set(scheduler) == {
        "due_without_active_job",
        "due_with_active_job",
        "not_due",
        "disabled",
    }
    assert scheduler["due_without_active_job"]["inserted_jobs"] == 1
    assert scheduler["due_without_active_job"]["scheduled_counter"] == 1
    assert scheduler["due_with_active_job"]["inserted_jobs"] == 0
    assert scheduler["due_with_active_job"]["scheduled_counter"] == 0
    for name in ("due_without_active_job", "due_with_active_job"):
        case = scheduler[name]
        assert case["last_enqueued_at_effect"] == "set to now"
        assert case["next_run_offset_seconds"] == max(60, case["schedule_seconds"])
    for name in ("not_due", "disabled"):
        assert scheduler[name]["last_enqueued_at_effect"] == "unchanged"
        assert scheduler[name]["next_run_offset_seconds"] is None

    transition = contract()["scheduling_and_leasing"]["due_schedule_transition"]
    assert transition["next_run_at"].startswith("now + max(60 seconds")
    assert "including an active-job insert conflict" in transition["last_enqueued_at"]
    assert transition["scheduled_counter"].endswith(
        "an active-job conflict contributes zero"
    )

    recovery = {case["name"]: case for case in fixtures["postgres_lease_recovery"]}
    assert set(recovery) == {
        "expired_nonfinal",
        "expired_final",
        "concurrent_reclaimer_skip_locked",
        "final_attempt_completion_race",
    }
    assert recovery["expired_nonfinal"]["state"] == "retry"
    assert recovery["expired_nonfinal"]["target_enabled"] is True
    assert recovery["expired_final"]["state"] == "dead_letter"
    assert recovery["expired_final"]["target_enabled"] is False
    assert recovery["concurrent_reclaimer_skip_locked"]["winners"] == 1
    assert recovery["final_attempt_completion_race"]["terminal_winners"] == 1
    assert recovery["final_attempt_completion_race"]["stale_writes"] == 0

    renewal = {case["name"]: case for case in fixtures["renewal_fence"]}
    assert set(renewal) == {
        "current_generation",
        "wrong_owner",
        "expired",
        "reclaimed_generation",
        "terminal",
    }
    assert renewal["current_generation"]["updated"] is True
    assert all(
        case["updated"] is False
        for name, case in renewal.items()
        if name != "current_generation"
    )


def test_shutdown_retry_after_and_log_redaction_fixtures_are_closed() -> None:
    frozen = contract()
    fixtures = frozen["executable_fixtures"]

    shutdown = {case["event"]: case for case in fixtures["shutdown"]}
    assert set(shutdown) == {
        "stop_before_cycle",
        "stop_during_poll",
        "task_cancelled",
        "cycle_exception",
    }
    assert all(case["dispose_engine"] is True for case in shutdown.values())
    assert shutdown["task_cancelled"]["propagate_cancellation"] is True
    assert shutdown["task_cancelled"]["lease_task_cancelled_and_awaited"] is True
    assert shutdown["cycle_exception"]["next_cycle"] is True

    def retry_after_seconds(value: str, now: str) -> int | None:
        try:
            seconds = int(value)
        except ValueError:
            try:
                parsed = parsedate_to_datetime(value)
            except (TypeError, ValueError, OverflowError):
                return None
            current = datetime.fromisoformat(now.replace("Z", "+00:00"))
            parsed = parsed.astimezone(UTC)
            seconds = int((parsed - current).total_seconds())
        return min(86400, max(0, seconds))

    retry_cases = fixtures["retry_after"]
    assert {case["value"] for case in retry_cases} == {
        "120",
        "-4",
        "999999",
        "Mon, 31 Aug 2026 12:02:00 GMT",
        "malformed",
    }
    for case in retry_cases:
        assert retry_after_seconds(case["value"], case["now"]) == case["seconds"]

    privacy = frozen["durable_result_privacy"]
    assert privacy["current_python_logging_gap"].startswith(
        "logger.exception emits exception messages and tracebacks"
    )
    assert privacy["required_security_hardening"].startswith(
        "replace or sanitize exception logging"
    )
    allowed_logs = set(privacy["log_allowlist"])
    forbidden_kinds = set(privacy["log_forbidden"])
    assert {
        "OAuth token",
        "client secret",
        "integration-secret plaintext",
        "integration-secret ciphertext",
        "provider response body",
        "provider payload",
        "exception message from an unexpected provider failure",
    } == forbidden_kinds
    for case in fixtures["log_redaction"]:
        assert set(case["log_fields"]).issubset(allowed_logs)
        projected = json.dumps(
            {
                "summary": case["persisted_summary"],
                "log_fields": case["log_fields"],
            }
        )
        assert case["input_secret"] not in projected
        assert all(
            fragment not in projected for fragment in case["forbidden_substrings"]
        )


def test_network_signing_secret_and_existing_rust_contracts_are_explicit() -> None:
    frozen = contract()
    network = frozen["origin_and_network_security"]
    signing = frozen["lti_signing"]
    secret = frozen["integration_secret_compatibility"]
    existing = frozen["existing_rust_components"]

    assert network["private_origin_allowlist"]["environment"] == (
        "CANVAS_PRIVATE_ORIGIN_ALLOWLIST"
    )
    assert network["self_managed_origin_allowlist"]["environment"] == (
        "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST"
    )
    assert (
        network["self_managed_origin_allowlist"]["independent_from_private_allowlist"]
        is True
    )
    assert network["production_dns_failure"] == "fail closed before request"
    assert "Host and TLS SNI" in network["dns_rebinding_control"]

    assert signing["selection"] == "organization-scoped issuer DID only"
    assert "SIGNING_KEYS_INTERNAL_URL" in signing["required_environment"]
    assert (
        "SIGNING_KEYS_INTERNAL_API_KEY or ISSUANCE_API_KEY"
        in signing["required_environment"]
    )
    assert signing["resolution"]["algorithm"] == "RS256"
    assert signing["sign_request"].startswith("DID-mediated")
    assert signing["readiness"].startswith("sign and locally verify")
    access = signing["signing_service_access"]
    assert access["current_python_response_detail"] == (
        "text detail is sliced to 500 characters; JSON string or object detail is "
        "not bounded"
    )
    assert access["required_security_hardening"].startswith(
        "bound serialized JSON and text response detail"
    )

    assert secret["master_key"] == "standard base64 encoding of exactly 32 bytes"
    assert secret["cipher"] == "AES-256-GCM"
    assert secret["stored_format"] == (
        "standard-base64(nonce[12] || ciphertext || tag[16])"
    )
    assert secret["associated_data"] == "empty"
    assert secret["cross_language"].startswith("Rust must decrypt existing Python")
    assert secret["read_projection"].startswith("plaintext returned only")

    assert len(existing["snapshot_commit"]) == 40
    assert set(existing["reuse_required"]) == {
        "rust/services/issuance/src/canvas_oauth.rs",
        "rust/services/issuance/src/canvas_oauth_http.rs",
        "rust/services/issuance/src/canvas_oauth_postgres.rs",
        "rust/services/issuance/src/integration_secret.rs",
        "rust/services/issuance/src/canvas_readiness.rs",
        "rust/services/issuance/src/canvas_readiness_runtime.rs",
    }
    assert "do not introduce a second" in existing["rule"]
    differences = existing["oauth_differences_to_resolve"]
    assert set(differences) == {
        "legacy_python_retry",
        "current_rust_disconnect_retry",
        "legacy_python_cleanup",
        "current_rust_postgres_cleanup",
        "required_resolution",
    }
    assert "stronger atomic tenant-scoped cleanup" in differences["required_resolution"]


def test_durable_result_fixture_enforces_privacy_projection() -> None:
    frozen = contract()
    privacy = frozen["durable_result_privacy"]
    fixture = frozen["executable_fixtures"]["result_sanitization"]
    allowed = set(privacy["allowed_keys"])
    sanitized: dict[str, object] = {}
    for key, value in fixture["input"].items():
        if key not in allowed:
            continue
        if isinstance(value, bool) or value is None:
            sanitized[key] = value
        elif isinstance(value, int):
            sanitized[key] = max(0, value)
        elif isinstance(value, str):
            sanitized[key] = value[: privacy["string_max_characters"]]
    assert sanitized == fixture["output"]
    assert "provider_payload" not in sanitized
    assert "requirements_checked" not in sanitized


def test_migration_gate_forbids_an_early_python_deletion() -> None:
    frozen = contract()
    gates = frozen["migration_gates"]

    assert len(gates["legacy_oracle_gaps"]) >= 10
    assert (
        "whole-worker differential parity including mutation and failure cases"
        in gates["python_deletion_requires"]
    )
    assert (
        "all Compose, self-host, and Kubernetes consumers routed to Rust"
        in gates["python_deletion_requires"]
    )
    assert "beta-only acceptance and soak" in gates["python_deletion_requires"]
    assert any(
        "bound JSON string/object signing-service error detail" in gap
        for gap in gates["legacy_oracle_gaps"]
    )
    assert any(
        "logger.exception message/traceback leakage" in gap
        for gap in gates["legacy_oracle_gaps"]
    )
    assert frozen["semantic_boundary"]["headless"] is True
    assert frozen["deployment_wiring"]["compose"]["profiles"] == [
        "base",
        "selfhost-production",
    ]
    assert frozen["deployment_wiring"]["kubernetes"]["deployment"] == (
        "canvas-sync-worker"
    )
