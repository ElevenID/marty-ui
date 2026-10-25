from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile

import pytest


def _load_audit_module():
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "beta_org_console_audit.py"
    spec = importlib.util.spec_from_file_location("beta_org_console_audit", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _cleanup_fixture():
    return {
        "created_api_keys": [{"id": "owned-key", "organization_id": "org-fixture"}],
        "cleanup_actions": [{"type": "revoke_api_key", "id": "owned-key",
                             "organization_id": "org-fixture", "status": "204", "ok": "true"}],
    }


def _required_steps():
    # Report-contract fixtures only; actual ES256 response bytes are exercised
    # by the native signing-capability suite and Python/CLI adapter test.
    steps = [
        {"label": "auth-probe", "body_excerpt": "Dashboard"},
        {"label": "post-org-probe", "body_excerpt": "Dashboard"},
        {"label": "kms-service-configured", "body_excerpt": "Key management", "signing_configuration": {
            "organization_id": "org-fixture", "run_id": "fixture-run", "default_service_id": "service-fixture",
        }},
        {"label": "issuer-identity-active", "body_excerpt": "Issuer identity"},
        {
            "label": "verifier-issuer-identity-active",
            "body_excerpt": "OID4VP request-signing identity",
        },
        {"label": "compliance-profile-available", "body_excerpt": "Compliance profile"},
        {"label": "trust-profile-active", "body_excerpt": "Trust profile"},
        {"label": "revocation-profile-activated", "body_excerpt": "Revocation profile"},
        {"label": "credential-template-activated", "body_excerpt": "Credential template"},
        {"label": "application-template-activated", "body_excerpt": "Application template"},
        {"label": "presentation-policy-active", "body_excerpt": "Presentation policy"},
        {"label": "deployment-profile-active", "body_excerpt": "Deployment profile"},
        {"label": "issuance-flow-active", "body_excerpt": "Issuance flow"},
        {"label": "verification-flow-active", "body_excerpt": "Verification flow"},
        {
            "label": "api-key-created",
            "body_excerpt": "API Keys",
            "api_key_secret_screenshot_redacted": True,
        },
        {"label": "resource-inventory-verified", "body_excerpt": "Inventory"},
        {
            "label": "unauthorized-administration-denied",
            "body_excerpt": "Administration denied",
        },
    ]
    for index, (purpose, identity_label, proof_label) in enumerate([
        ("vc_jwt_issuer", "issuer-identity-active", "issuer-signing-capability-verified"),
        ("oid4vp_request_signing", "verifier-issuer-identity-active", "verifier-signing-capability-verified"),
    ]):
        identity = {"issuer_did": "did:web:issuer.unit.invalid:fixture", "key_purpose": purpose,
                    "credential_format": "SD_JWT_VC", "algorithm": "ES256", "status": "active"}
        next(step for step in steps if step["label"] == identity_label)["issuer_identity"] = identity
        proof = {"schema": "marty.signing-capability/v1", "verified": True,
                 "scope": "EXACT_PUBLIC_SERVICE_SIGNING_CAPABILITY_ONLY",
                 "organization_id": "org-fixture", "run_id": "fixture-run", "service_id": "service-fixture",
                 **{key: value for key, value in identity.items() if key != "status"}}
        proof.update({key: str(index + 1) * 64 for key in (
            "challenge_sha256", "key_binding_sha256", "public_key_sha256", "signature_sha256",
            "service_response_sha256", "identity_response_sha256", "signing_response_sha256",
        )})
        steps.append({"label": proof_label, "signing_capability": proof})
    return steps


@pytest.mark.parametrize("record_video_env", [None, "0", "1"])
@pytest.mark.parametrize("setup_failure", [False, True])
def test_main_honors_recorder_video_mode_and_keeps_required_trace(
    monkeypatch, tmp_path: Path, record_video_env: str | None, setup_failure: bool,
) -> None:
    audit = _load_audit_module()
    events = []
    contexts = []
    trace_options = []
    artifact_dir = tmp_path / "attempt"
    functional = record_video_env == "0"

    class Trace:
        def start(self, **options):
            events.append("trace-started")
            trace_options.append(options)

        def stop(self, *, path):
            events.append("trace-stopped")
            with ZipFile(path, "w") as archive:
                archive.writestr("test.trace", '{"type":"synthetic-trace"}\n')

    class Video:
        def path(self):
            events.append("video-finalized")
            video = artifact_dir / "raw.webm"
            video.write_bytes(b"\x1a\x45\xdf\xa3synthetic-video")
            return str(video)

    class Page:
        @property
        def video(self):
            events.append("video-requested")
            return Video()

    class Context:
        tracing = Trace()

        def new_page(self):
            return Page()

        def close(self):
            events.append("context-closed")

    class Browser:
        def new_context(self, **options):
            contexts.append(options)
            return Context()

        def close(self):
            events.append("browser-closed")

    class Playwright:
        def __enter__(self):
            return SimpleNamespace(chromium=SimpleNamespace(launch=lambda **_options: Browser()))

        def __exit__(self, *_args):
            return False

    class FixtureAudit(audit.Audit):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.steps = _required_steps()
            self.created_api_keys = _cleanup_fixture()["created_api_keys"]

        def attach_events(self):
            pass

        def snapshot(self, label, *_args, **_kwargs):
            if label == "audit-exception":
                self.steps.append({"label": label})

        def cleanup_created_api_keys(self):
            events.append("cleanup")
            self.cleanup_actions = _cleanup_fixture()["cleanup_actions"]

    monkeypatch.setattr(audit, "Audit", FixtureAudit)
    monkeypatch.setattr(audit, "sync_playwright", Playwright)
    monkeypatch.setattr(audit, "load_env_file", lambda _path: {})
    monkeypatch.setattr(audit, "load_signing_inputs", lambda: {})
    monkeypatch.setattr(audit, "start_recorder_capture", lambda **_kwargs: None)
    monkeypatch.setattr(audit, "require_created_organization", lambda *_args: "org-fixture")
    monkeypatch.setattr(audit, "fetch_json_from_page", lambda *_args: {})
    for name in [
        "log_in", "create_org", "create_key_service_if_possible", "create_issuer_identity",
        "create_trust_profile", "create_revocation_profile", "create_credential_template",
        "create_application_template", "create_policy_and_deployment", "create_flow",
        "create_api_key", "verify_issuer_signing_capabilities", "verify_resource_inventory", "verify_unauthorized_administration_denied",
    ]:
        monkeypatch.setattr(audit, name, lambda *_args, step=name: events.append(step))
    if setup_failure:
        def failed_registration(*_args):
            events.append("create_key_service_if_possible")
            raise ValueError("fixture registration rejected synthetic-test-password")
        monkeypatch.setattr(audit, "create_key_service_if_possible", failed_registration)
    monkeypatch.setattr(audit.sys, "argv", ["beta_org_console_audit.py", "--record-video"])
    monkeypatch.setenv("TEST_VENDOR_EMAIL", "operator@example.test")
    monkeypatch.setenv("TEST_VENDOR_PASSWORD", "synthetic-test-password")
    monkeypatch.setenv("DEMO_ARTIFACT_DIR", str(artifact_dir))
    if record_video_env is None:
        monkeypatch.delenv("RECORD_VIDEO", raising=False)
    else:
        monkeypatch.setenv("RECORD_VIDEO", record_video_env)

    if setup_failure:
        with pytest.raises(RuntimeError, match="fixture registration rejected") as failure:
            audit.main()
        assert "synthetic-test-password" not in str(failure.value)
        assert "synthetic-test-password" not in (artifact_dir / "report.json").read_text()
        report = json.loads((artifact_dir / "report.json").read_text())
        assert report["releaseReady"] is False
        assert report["release_checks"]["status"] == "blocked"
        assert report["trace_coverage"]["status"] == "NOT_STARTED_SETUP_FAILED"
        assert "trace-started" not in events
        assert not (artifact_dir / "mip-primitives-management-trace.zip").exists()
        assert "cleanup" in events and "browser-closed" in events
        if functional:
            assert "video-requested" not in events
        return

    assert audit.main() == 0
    report = json.loads((artifact_dir / "report.json").read_text())
    assert report["releaseReady"] is True
    assert contexts[0]["ignore_https_errors"] is False
    assert all(report["behaviorAssertions"].values())
    assert events.index("create_key_service_if_possible") < events.index("trace-started") < events.index("create_issuer_identity")
    assert events.index("verify_issuer_signing_capabilities") < events.index("verify_resource_inventory")
    assert report["trace_coverage"]["omitted"] == ["authentication", "organization-creation", "kms-service-registration", "api-key-creation"]
    assert events.index("trace-stopped") < events.index("create_api_key")
    assert all(options["snapshots"] is False and options["sources"] is False for options in trace_options)
    assert events.index("verify_resource_inventory") < events.index("cleanup")
    assert events.index("verify_unauthorized_administration_denied") < events.index("cleanup")
    assert events.index("context-closed") < events.index("browser-closed")
    assert (artifact_dir / "mip-primitives-management-trace.zip").is_file()
    if functional:
        assert "record_video_dir" not in contexts[0]
        assert "record_video_size" not in contexts[0]
        assert "video-requested" not in events
        assert "video-finalized" not in events
        assert not list(artifact_dir.glob("*.webm"))
        assert report["functional_rerun"] is True
        assert report["capture_quality"]["status"] == "NOT_CAPTURED"
        assert report["recording"] is None
        assert report["trace"] == "mip-primitives-management-trace.zip"
        assert trace_options == [{"screenshots": False, "snapshots": False, "sources": False}]
    else:
        assert contexts[0]["record_video_dir"] == str(artifact_dir)
        assert "video-finalized" in events
        assert (artifact_dir / "mip-primitives-management.webm").is_file()
        assert report["recording"] == {
            "video": "mip-primitives-management.webm",
            "trace": "mip-primitives-management-trace.zip",
        }


def test_signing_service_audit_uses_the_selected_remote_service() -> None:
    audit = _load_audit_module()
    services = [
        {"id": "first", "name": "First", "status": "configured"},
        {"id": "remote", "name": "Selected", "status": "configured"},
    ]
    assert audit.selected_signing_service({
        "services": services,
        "default_service_id": "remote",
    }) == services[1]
    assert audit.selected_signing_service({
        "hsm_enabled": True,
        "hsm_settings": {"key_reference": "legacy"},
    }) is None
    assert audit.selected_signing_service({
        "services": services,
        "default_service_id": "missing",
    }) is None
    assert audit.selected_signing_service({
        "services": [{"id": "remote", "status": "disabled"}],
        "default_service_id": "remote",
    }) is None
    assert audit.selected_signing_service({
        "services": [{"id": "remote", "status": "unavailable"}],
        "default_service_id": "remote",
    }) is None


def test_release_checks_block_audit_log_501() -> None:
    audit = _load_audit_module()

    report = {
        "steps": _required_steps(),
        **_cleanup_fixture(),
        "bad_responses": [
            {
                "status": 501,
                "url": "https://beta.elevenidllc.com/v1/organizations/org-1/audit-events?limit=5",
                "error_code": "audit_log_unavailable",
                "message_id": "msg-audit-1",
            }
        ],
        "failed_requests": [],
        "page_errors": [],
    }

    checks = audit.evaluate_release_checks(report)

    assert checks["status"] == "blocked"
    assert checks["degraded"] == []
    assert checks["blockers"][0]["code"] == "audit_log_unavailable"
    assert checks["blockers"][0]["message_id"] == "msg-audit-1"


def test_release_checks_block_core_console_regressions() -> None:
    audit = _load_audit_module()

    report = {
        "steps": [
            {
                "label": "audit-exception",
                "body_excerpt": "Audit stopped",
            },
            {
                "label": "api-key-created",
                "body_excerpt": "Loading console...",
                "api_key_secret_screenshot_redacted": False,
            }
        ],
        "bad_responses": [
            {
                "status": 503,
                "url": "https://beta.elevenidllc.com/v1/organizations/mine",
                "message_id": "msg-org-503",
            }
        ],
        "failed_requests": [],
        "page_errors": ["boom"],
        "probe": "https://beta.elevenidllc.com/v1/trust-profiles?organization_id=null /console/org/setup-wizard Opening login mk_test_rawsecret",
    }

    checks = audit.evaluate_release_checks(report)
    blocker_codes = {entry["code"] for entry in checks["blockers"]}

    assert checks["status"] == "blocked"
    assert {
        "null_organization_request",
        "old_setup_wizard",
        "login_interstitial",
        "raw_secret_in_report",
        "api_key_screenshot_not_redacted",
        "terminal_loading_state",
        "service_503",
        "page_error",
        "audit_exception",
        "audit_coverage_incomplete",
    }.issubset(blocker_codes)


def test_release_checks_block_incomplete_audit_even_without_errors() -> None:
    audit = _load_audit_module()

    checks = audit.evaluate_release_checks({
        "steps": [{"label": "auth-probe", "body_excerpt": "Dashboard"}],
        "bad_responses": [],
        "failed_requests": [],
        "page_errors": [],
    })

    assert checks["status"] == "blocked"
    assert checks["blockers"][0]["code"] == "audit_coverage_incomplete"
    assert "resource-inventory-verified" in checks["blockers"][0]["missing_steps"]


def test_release_checks_accept_typed_plan_entitlement_response() -> None:
    audit = _load_audit_module()

    checks = audit.evaluate_release_checks({
        "steps": _required_steps(),
        **_cleanup_fixture(),
        "bad_responses": [
            {
                "status": 403,
                "url": "https://beta.elevenidllc.com/v1/policy-sets?organization_id=org-1",
                "error_code": "plan_feature_unavailable",
            }
        ],
        "failed_requests": [],
        "page_errors": [],
    })

    assert checks["status"] == "pass"
    assert checks["observations"]["expected_entitlement_responses"] == [
        {
            "status": 403,
            "url": "https://beta.elevenidllc.com/v1/policy-sets?organization_id=org-1",
            "error_code": "plan_feature_unavailable",
        }
    ]


def test_release_checks_accept_only_exact_cross_org_admin_denials() -> None:
    audit = _load_audit_module()
    denied = [
        {
            "status": 403,
            "url": f"https://beta.elevenidllc.com{path}?organization_id={audit.CROSS_ORG_SENTINEL}",
            "message_id": f"denied-{index}",
        }
        for index, path in enumerate(sorted(audit.CROSS_ORG_ADMIN_PATHS))
    ]

    checks = audit.evaluate_release_checks({
        "steps": _required_steps(),
        **_cleanup_fixture(),
        "bad_responses": denied,
        "failed_requests": [],
        "page_errors": [],
    })

    assert checks["status"] == "pass"
    assert checks["observations"]["expected_cross_org_admin_denials"] == denied
    assert not audit.is_expected_cross_org_admin_denial({
        "status": 403,
        "url": f"https://beta.elevenidllc.com/v1/api-keys?organization_id={audit.CROSS_ORG_SENTINEL}",
    })
    assert not audit.is_expected_cross_org_admin_denial({
        "status": 403,
        "url": "https://beta.elevenidllc.com/v1/trust-profiles?organization_id=another-org",
    })


def test_organization_management_behavior_assertions_require_exact_steps() -> None:
    audit = _load_audit_module()
    report = {"steps": _required_steps()}

    assert audit.organization_management_behavior_assertions(report) == {
        "configure_organization": True,
        "configure_issuer_profiles": True,
        "configure_trust_and_mip_primitives": True,
        "unauthorized_administration_denied": True,
    }

    report["steps"] = [
        step for step in report["steps"]
        if step["label"] != "unauthorized-administration-denied"
    ]
    assert audit.organization_management_behavior_assertions(report)[
        "unauthorized_administration_denied"
    ] is False


def test_external_recorder_artifact_dir_is_supported(monkeypatch, tmp_path: Path) -> None:
    audit = _load_audit_module()
    artifact_dir = tmp_path / "fresh-recording"
    monkeypatch.setenv("DEMO_ARTIFACT_DIR", str(artifact_dir))

    assert audit.resolve_artifact_dir("ignored-run-id") == artifact_dir.resolve()
    assert audit.report_artifact_path(artifact_dir / "report.json", artifact_dir) == "report.json"

    source = (Path(__file__).resolve().parents[1] / "scripts" / "beta_org_console_audit.py").read_text(
        encoding="utf-8"
    )
    assert 'os.environ.get("BETA_ORIGIN")' in source


@pytest.mark.parametrize(
    "override_status, expected_label",
    [
        (None, "unauthorized-administration-denied"),
        (200, "unauthorized-administration-not-denied"),
    ],
)
def test_cross_org_admin_probe_fails_closed(
    monkeypatch,
    override_status: int | None,
    expected_label: str,
) -> None:
    audit = _load_audit_module()

    class FakeAudit:
        page = object()

        def __init__(self) -> None:
            self.snapshots = []

        def snapshot(self, label, note, extra) -> None:
            self.snapshots.append({"label": label, "note": note, "extra": extra})

    first_path = sorted(audit.CROSS_ORG_ADMIN_PATHS)[0]

    def fetch_probe(_page, path, organization_id):
        assert organization_id == audit.CROSS_ORG_SENTINEL
        status = override_status if path == first_path and override_status is not None else 403
        return {"status": status}

    monkeypatch.setattr(audit, "fetch_org_collection", fetch_probe)
    fake_audit = FakeAudit()

    audit.verify_unauthorized_administration_denied(fake_audit)

    assert [snapshot["label"] for snapshot in fake_audit.snapshots] == [expected_label]
    assert set(fake_audit.snapshots[0]["extra"]["statuses"]) == audit.CROSS_ORG_ADMIN_PATHS


def test_release_checks_block_unexplained_failed_request() -> None:
    audit = _load_audit_module()

    checks = audit.evaluate_release_checks({
        "steps": _required_steps(),
        **_cleanup_fixture(),
        "bad_responses": [],
        "failed_requests": [
            {
                "method": "POST",
                "url": "https://beta.elevenidllc.com/v1/deployment-profiles",
                "failure": "net::ERR_ABORTED",
            }
        ],
        "page_errors": [],
    })

    assert checks["status"] == "blocked"
    assert checks["blockers"][0]["code"] == "unexpected_failed_request"


def test_release_checks_accept_navigation_cancelled_org_reads() -> None:
    audit = _load_audit_module()
    cancelled = {
        "method": "GET",
        "url": "https://beta.elevenidllc.com/v1/credential-templates?organization_id=org-1",
        "failure": "net::ERR_ABORTED",
        "resource_type": "fetch",
    }

    checks = audit.evaluate_release_checks({
        "steps": _required_steps(),
        **_cleanup_fixture(),
        "bad_responses": [],
        "failed_requests": [cancelled],
        "page_errors": [],
    })

    assert checks["status"] == "pass"
    assert checks["observations"]["expected_navigation_aborts"] == [cancelled]


def test_release_checks_block_cancelled_document_navigation() -> None:
    audit = _load_audit_module()

    checks = audit.evaluate_release_checks({
        "steps": _required_steps(),
        **_cleanup_fixture(),
        "bad_responses": [],
        "failed_requests": [
            {
                "method": "GET",
                "url": "https://beta.elevenidllc.com/console/org/templates",
                "failure": "net::ERR_ABORTED",
                "resource_type": "document",
            }
        ],
        "page_errors": [],
    })

    assert checks["status"] == "blocked"
    assert checks["blockers"][0]["code"] == "unexpected_failed_request"


def test_collection_items_supports_public_issuer_identity_envelope() -> None:
    audit = _load_audit_module()
    identity = {
        "issuer_did": "did:web:beta.example:orgs:audit",
        "key_purpose": "vc_jwt_issuer",
        "credential_format": "SD_JWT_VC",
        "algorithm": "ES256",
        "status": "active",
    }

    assert audit.collection_items({"body": {"identities": [identity]}}) == [identity]
    assert audit.find_issuer_identity(
        {"body": {"identities": [identity]}},
        identity["issuer_did"],
    ) == identity


def test_beta_audit_uses_only_public_issuer_identity_route() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "beta_org_console_audit.py"
    ).read_text(encoding="utf-8")

    assert '"/v1/signing-keys/issuer-identities"' in source
    assert '"/v1/signing-keys/issuer-profiles"' not in source
    assert "credential.issuer_did" in source
    assert "credential.issuer_profile_id" not in source


def test_beta_audit_adds_trust_by_public_issuer_did() -> None:
    audit = _load_audit_module()
    identity = {
        "issuer_did": "did:web:beta.example:orgs:audit-production-flow-20260813010101",
        "key_purpose": "vc_jwt_issuer",
        "credential_format": "SD_JWT_VC",
        "algorithm": "ES256",
        "status": "active",
    }

    assert audit.find_audit_issuer_identity(
        {"body": {"identities": [identity]}},
        "20260813010101",
    ) == identity

    source = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "beta_org_console_audit.py"
    ).read_text(encoding="utf-8")
    assert "wizard.trustProfile.issuerDid" in source
    assert "wizard.trustProfile.addIssuer" in source
    assert "wizard.trustProfile.existingIssuerProfile" not in source
    assert "wizard.trustProfile.useIssuerProfile" not in source


def _passing_inventory_report(organization_id: str) -> dict:
    return {
        "release_checks": {"status": "pass"},
        "steps": [
            {
                "label": "resource-inventory-verified",
                "organization_id": organization_id,
                "inventory": [
                    {
                        "resource_type": "verifier_issuer_identity",
                        "id": "did:web:beta.example:orgs:audit",
                        "status": "active",
                    },
                    {
                        "resource_type": "credential_template",
                        "id": "10000000-0000-0000-0000-000000000010",
                        "status": "ACTIVE",
                    },
                    {
                        "resource_type": "presentation_policy",
                        "id": "10000000-0000-0000-0000-000000000020",
                        "status": "active",
                    },
                ],
            }
        ],
    }


def test_beta_audit_exports_verified_lifecycle_resources_for_later_steps(tmp_path: Path) -> None:
    audit = _load_audit_module()
    organization_id = "a60371ca-7250-4a51-9598-f8e972044f31"
    github_env = tmp_path / "github-env"
    github_env.write_text("EXISTING=value\n", encoding="utf-8")

    exported = audit.export_audit_lifecycle_environment(
        _passing_inventory_report(organization_id),
        github_env,
    )

    assert exported == {
        "BETA_AUDIT_ORG_ID": organization_id,
        "BETA_AUDIT_TEMPLATE_ID": "10000000-0000-0000-0000-000000000010",
        "BETA_AUDIT_POLICY_ID": "10000000-0000-0000-0000-000000000020",
        "BETA_AUDIT_VERIFIER_DID": "did:web:beta.example:orgs:audit",
    }
    assert github_env.read_text(encoding="utf-8").splitlines() == [
        "EXISTING=value",
        f"BETA_AUDIT_ORG_ID={organization_id}",
        "BETA_AUDIT_TEMPLATE_ID=10000000-0000-0000-0000-000000000010",
        "BETA_AUDIT_POLICY_ID=10000000-0000-0000-0000-000000000020",
        "BETA_AUDIT_VERIFIER_DID=did:web:beta.example:orgs:audit",
    ]


@pytest.mark.parametrize(
    "report, message",
    [
        (
            {
                "release_checks": {"status": "blocked"},
                "steps": [],
            },
            "non-passing audit",
        ),
        (
            {
                "release_checks": {"status": "pass"},
                "steps": [],
            },
            "exactly one verified inventory",
        ),
        (
            _passing_inventory_report("not-a-uuid"),
            "BETA_AUDIT_ORG_ID must be a UUID",
        ),
        (
            {
                "release_checks": {"status": "pass"},
                "steps": [
                    {
                        "label": "resource-inventory-verified",
                        "organization_id": "a60371ca-7250-4a51-9598-f8e972044f31",
                    },
                    {
                        "label": "resource-inventory-verified",
                        "organization_id": "d028f6d7-522d-4362-99c0-c70833f0962a",
                    },
                ],
            },
            "exactly one verified inventory",
        ),
    ],
)
def test_beta_audit_refuses_unverified_organization_exports(
    report: dict,
    message: str,
) -> None:
    audit = _load_audit_module()

    with pytest.raises(ValueError, match=message):
        audit.verified_audit_lifecycle_environment(report)


@pytest.mark.parametrize(
    "mutation, message",
    [
        (
            lambda inventory: inventory.pop(1),
            "exactly one active BETA_AUDIT_TEMPLATE_ID",
        ),
        (
            lambda inventory: inventory.append(dict(inventory[1])),
            "exactly one active BETA_AUDIT_TEMPLATE_ID",
        ),
        (
            lambda inventory: inventory[2].update(status="draft"),
            "exactly one active BETA_AUDIT_POLICY_ID",
        ),
        (
            lambda inventory: inventory[2].update(id="not-a-uuid"),
            "BETA_AUDIT_POLICY_ID must be a UUID",
        ),
        (
            lambda inventory: inventory.pop(0),
            "exactly one active BETA_AUDIT_VERIFIER_DID",
        ),
        (
            lambda inventory: inventory[0].update(id="not-a-did"),
            "BETA_AUDIT_VERIFIER_DID must be a DID",
        ),
    ],
)
def test_beta_audit_refuses_unverified_lifecycle_resource_exports(
    mutation,
    message: str,
) -> None:
    audit = _load_audit_module()
    report = _passing_inventory_report("a60371ca-7250-4a51-9598-f8e972044f31")
    mutation(report["steps"][0]["inventory"])

    with pytest.raises(ValueError, match=message):
        audit.verified_audit_lifecycle_environment(report)


def test_beta_audit_provisions_public_oid4vp_request_signing_identity() -> None:
    audit = _load_audit_module()

    class FakePage:
        def __init__(self) -> None:
            self.payload = None
            self.script = ""

        def evaluate(self, script: str, payload: dict) -> dict:
            self.script = script
            self.payload = payload
            return {"status": 200, "ok": True, "created": True, "error": None}

    page = FakePage()
    result = audit.provision_verifier_issuer_identity(
        page,
        "a60371ca-7250-4a51-9598-f8e972044f31",
        "did:web:beta.elevenidllc.com:orgs:audit-production-flow",
        "20260814112250",
    )

    assert result == {"status": 200, "ok": True, "created": True, "error": None}
    assert page.payload == {
        "organization_id": "a60371ca-7250-4a51-9598-f8e972044f31",
        "issuer_did": "did:web:beta.elevenidllc.com:orgs:audit-production-flow",
        "idempotency_key": "beta-audit-oid4vp-20260814112250",
    }
    assert "'oid4vp_request_signing'" in page.script
    assert "'SD_JWT_VC'" in page.script
    assert "'ES256'" in page.script
    assert "signing_service_id" not in page.script
    assert "signing_key_reference" not in page.script


def test_beta_audit_waits_for_the_exact_verifier_identity_tuple(monkeypatch) -> None:
    audit = _load_audit_module()
    issuer_did = "did:web:beta.elevenidllc.com:orgs:audit-production-flow"
    issuance_identity = {
        "issuer_did": issuer_did,
        "key_purpose": "vc_jwt_issuer",
        "credential_format": "SD_JWT_VC",
        "algorithm": "ES256",
        "status": "active",
    }
    verifier_identity = {
        "issuer_did": issuer_did,
        "key_purpose": "oid4vp_request_signing",
        "credential_format": "SD_JWT_VC",
        "algorithm": "ES256",
        "status": "active",
    }
    probe = {"body": {"identities": [issuance_identity, verifier_identity]}}
    monkeypatch.setattr(audit, "fetch_org_collection", lambda *_args: probe)

    identity, observed_probe = audit.wait_for_issuer_identity(
        object(),
        "a60371ca-7250-4a51-9598-f8e972044f31",
        issuer_did,
        key_purpose="oid4vp_request_signing",
        credential_format="SD_JWT_VC",
        algorithm="ES256",
    )

    assert identity == verifier_identity
    assert observed_probe == probe


@pytest.mark.parametrize("change", ["missing", "failed", "foreign-org", "foreign-key", "contradictory", "unowned", "unknown-status", "pending"])
def test_run_owned_key_cleanup_cannot_be_missing_failed_or_substituted(change):
    audit = _load_audit_module()
    report = {"steps": _required_steps(), **_cleanup_fixture()}
    action = report["cleanup_actions"][0]
    if change == "missing":
        report.pop("cleanup_actions")
    elif change == "failed":
        action.update(status="500", ok="false")
    elif change == "foreign-org":
        action["organization_id"] = "another-organization"
    elif change == "foreign-key":
        action["id"] = "another-key"
    elif change == "contradictory":
        report["cleanup_actions"].append({**action, "ok": "false", "status": "500"})
    elif change == "unowned":
        report["created_api_keys"] = []
    elif change == "unknown-status":
        action["status"] = "404"
    elif change == "pending":
        action["status"] = "202"
    checks = audit.evaluate_release_checks(report)
    assert checks["status"] == "blocked"
    assert "owned_api_key_cleanup_unverified" in {item["code"] for item in checks["blockers"]}


def test_exact_owned_key_cleanup_succeeds_but_partial_cleanup_does_not():
    audit = _load_audit_module()
    report = {"steps": _required_steps(), **_cleanup_fixture()}
    assert audit.owned_api_key_cleanup_proven(report)
    assert audit.evaluate_release_checks(report)["status"] == "pass"
    report["created_api_keys"].append({"id": "second-owned-key", "organization_id": "org-fixture"})
    assert not audit.owned_api_key_cleanup_proven(report)


@pytest.mark.parametrize("origin", ["https://beta.elevenidllc.com.attacker.invalid", "https://attacker.invalid/?beta.elevenidllc.com", "http://beta.elevenidllc.com", "https://beta.elevenidllc.com/path"])
def test_d10_rejects_lookalike_or_noncanonical_origin_before_signer_or_browser(monkeypatch, origin):
    audit = _load_audit_module()
    monkeypatch.setattr(audit, "load_env_file", lambda _path: {})
    monkeypatch.setattr(audit.sys, "argv", ["beta_org_console_audit.py", "--base-url", origin])
    monkeypatch.setattr(audit, "load_signing_inputs", lambda: pytest.fail("signer cannot be inspected for an unapproved origin"))
    monkeypatch.setattr(audit, "sync_playwright", lambda: pytest.fail("browser cannot start for an unapproved origin"))
    assert audit.main() == 2


def test_d10_recording_refuses_missing_recorder_child_client():
    audit = _load_audit_module()
    with pytest.raises(ValueError, match="recorder-owned live Python capture"):
        audit.start_recorder_capture(required=True)


def test_d10_uses_only_exact_acknowledged_inputs_for_feature_actions():
    audit = _load_audit_module()
    signing = {"endpoint": "https://kms.internal.company", "mount": "transit", "namespace": "",
               "key_reference": "existing-key", "ca_cert_file": "/run/secrets/customer-ca", "validator_sha256": "a" * 64}
    scenario = {"runId": "20261021200000-1234abcd", "recordVideo": False, "recordingPauseMs": 1300,
                "signing": {"endpoint": signing["endpoint"], "mount": "transit", "namespace": "", "keyReference": "existing-key",
                            "caCertFile": "/run/secrets/customer-ca", "validatorSha256": "a" * 64}}
    capture = SimpleNamespace(inputs={"origin": "https://beta.elevenidllc.com", "scenario": scenario})
    assert audit.bound_recorder_inputs(capture, signing, False, 1300) is scenario
    scenario["signing"]["keyReference"] = "substituted-key"
    with pytest.raises(ValueError, match="differ from recorder-acknowledged"):
        audit.bound_recorder_inputs(capture, signing, False, 1300)
