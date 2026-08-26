from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def _load_audit_module():
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "beta_org_console_audit.py"
    spec = importlib.util.spec_from_file_location("beta_org_console_audit", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _required_steps():
    return [
        {"label": "auth-probe", "body_excerpt": "Dashboard"},
        {"label": "post-org-probe", "body_excerpt": "Dashboard"},
        {"label": "kms-service-configured", "body_excerpt": "Key management"},
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


def test_release_checks_block_audit_log_501() -> None:
    audit = _load_audit_module()

    report = {
        "steps": _required_steps(),
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
