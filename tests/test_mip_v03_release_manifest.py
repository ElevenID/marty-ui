from __future__ import annotations

import re
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _text(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_beta_lifecycle_workflow_is_fail_closed_and_canonical() -> None:
    workflow = _text(".github/workflows/e2e-tests.yml")
    credential_login = _text("tests/scripts/verify-beta-credential-login.js")

    assert "environment: beta-lifecycle" in workflow
    assert "types: [beta-deployed]" in workflow
    assert "Require deployed MIP 0.3.1 contract" in workflow
    assert "probe-beta-membership-badge.js" in workflow
    assert "verify-beta-waltid-acceptance.js" not in workflow
    assert "audit-beta-org-credential-paths.js" in workflow
    assert "audit-beta-credential-lifecycle.js" in workflow
    assert "beta_org_console_audit.py" in workflow
    assert "release-context.json" in workflow
    assert "MARTY_TEST_WALLET_ORIGIN" in credential_login
    assert "WALTID_WALLET_ORIGIN" not in credential_login
    assert "anthropic/marty-authenticator" not in workflow
    assert "test.skip" not in workflow
    assert "continue-on-error" not in workflow


def test_wallet_conformance_is_the_only_release_ready_promotion_gate() -> None:
    workflow = _text(".github/workflows/wallet-conformance.yml")
    requirements = json.loads(_text("deploy-config/catalog/wallet-conformance-requirements.json"))

    assert "environment: wallet-conformance" in workflow
    assert "ref: ${{ env.MARTY_UI_SHA }}" in workflow
    assert "build-ready-manifest-$RELEASE_VERSION" in workflow
    assert "mip-03-beta-credential-lifecycle" in workflow
    assert "promote_release_evidence.py" in workflow
    assert "Require successful source workflow runs" in workflow
    assert 'verify_run "$CD_RUN_ID" "CD"' in workflow
    assert 'verify_run "$BETA_LIFECYCLE_RUN_ID" "MIP 0.3 Beta Credential Lifecycle"' in workflow
    assert '--cd-run-id "$CD_RUN_ID"' in workflow
    assert '--promotion-run-id "$GITHUB_RUN_ID"' in workflow
    assert "check_spruceid_metadata.py" in workflow
    assert "wallet-conformance-evidence.json" in workflow
    assert "verify_wallet_attachments.py" in workflow
    assert "wallet-attachment-verification.json" in workflow
    assert "--proto-redir '=https'" in workflow
    assert "release-ready-manifest-${{ inputs.release_version }}" in workflow
    assert "continue-on-error" not in workflow
    assert requirements["mip_version"] == "0.3.1"
    assert requirements["sprucekit_login"]["wallet_id"] == "wr-spruce-001"
    assert "request_unmodified" in requirements["sprucekit_login"]["required_checks"]


def test_waltid_browser_wallet_images_are_versioned_and_digest_pinned() -> None:
    compose = _text("docker-compose.profile.waltid.yml")
    catalog = json.loads(_text("deploy-config/catalog/wallet-test-images.json"))

    image_pattern = re.compile(r"docker\.io/waltid/[\w-]+:[\w.-]+@sha256:[0-9a-f]{64}")
    configured_images = {
        catalog["waltid"]["wallet_api_image"],
        catalog["waltid"]["web_wallet_image"],
    }
    assert len(configured_images) == 2
    assert all(image_pattern.fullmatch(image) for image in configured_images)
    assert all(image in compose for image in configured_images)
    assert catalog["waltid"]["advertised"] is False
    assert catalog["waltid"]["required_capabilities"] == []
    assert "adapter_required_capabilities" not in catalog["waltid"]
    assert catalog["waltid"]["unsupported_capabilities"] == [
        "oid4vci_issuance",
        "oid4vp_dcql_verification",
        "credential_login",
    ]
    assert "proofs" in catalog["waltid"]["issuance_blocker"]
    assert "DCQL" in catalog["waltid"]["oid4vp_blocker"]


def test_beta_gate_uses_pinned_marty_browser_wallet_for_dcql() -> None:
    workflow = _text(".github/workflows/e2e-tests.yml")
    catalog = json.loads(_text("deploy-config/catalog/wallet-test-images.json"))

    assert catalog["marty_test_wallet"]["test_only"] is True
    assert catalog["marty_test_wallet"]["revision_variable"] == "MARTY_CORE_REF"
    assert catalog["marty_test_wallet"]["required_capabilities"] == [
        "oid4vci_issuance",
        "oid4vp_dcql_verification",
        "credential_login",
    ]
    assert "ref: ${{ env.MARTY_CORE_REF }}" in workflow
    assert "test -f marty-core/Cargo.lock" in workflow
    assert "test -f marty-core/vendor/core2-0.4.0/Cargo.toml" in workflow
    assert "test -f marty-core/marty-test-wallet/Cargo.toml" in workflow
    assert "cargo metadata --locked --no-deps --format-version 1" in workflow
    assert "cargo build --locked --manifest-path marty-core/Cargo.toml -p marty-test-wallet" in workflow
    assert "WALTID_PRESENTATION_JSON_ADAPTER" not in workflow


def test_cd_reads_wallet_images_from_the_catalog() -> None:
    workflow = _text(".github/workflows/cd.yml")

    assert "deploy-config/catalog/wallet-test-images.json" in workflow
    assert "WALTID_WALLET_API_IMAGE" in workflow
    assert "WALTID_WEB_WALLET_IMAGE" in workflow


def test_cd_requires_successful_ci_for_coordinated_source_revisions() -> None:
    workflow = _text(".github/workflows/cd.yml")

    assert "Require successful coordinated source CI" in workflow
    assert 'verify_source_ci Marty-Protocol/Marty-Protocol "$MARTY_PROTOCOL_REF" CI' in workflow
    assert 'verify_source_ci ElevenID/marty-credentials "$MARTY_CREDENTIALS_REF" CI' in workflow
    assert 'verify_source_ci ElevenID/marty-core "$MARTY_CORE_REF" "MIP Release Wallet"' in workflow
    assert '--commit "$revision"' in workflow


def test_beta_contract_probe_fails_on_mixed_or_legacy_routes() -> None:
    probe = _text("tests/scripts/probe-beta-membership-badge.js")

    assert "probe.mipVersion === '0.3.1'" in probe
    assert "probe.status === 404" in probe
    assert "if (!releaseReady) process.exitCode = 1" in probe
    assert "ALLOW_LEGACY" not in probe
    assert "legacy-diagnostic" not in probe


def test_cd_manifest_pins_all_coordinated_repositories() -> None:
    workflow = _text(".github/workflows/cd.yml")

    assert "MARTY_CREDENTIALS_REF must be an exact 40-character commit SHA" in workflow
    assert "MARTY_PROTOCOL_REF must be an exact 40-character commit SHA" in workflow
    assert "repository: Marty-Protocol/Marty-Protocol" in workflow
    assert "uv run pytest tests/ -v" in workflow
    assert "uv run python scripts/codegen.py --check" in workflow
    assert "name: Build Atomic Release Manifest" in workflow
    assert "marty_protocol: $marty_protocol_sha" in workflow
    assert "marty_credentials: $marty_credentials_sha" in workflow
    assert "mixed_versions_supported: false" in workflow
    assert "needs: [determine-tag, release-manifest]" in workflow


def test_cd_runs_tests_for_every_pinned_first_party_repository() -> None:
    workflow = _text(".github/workflows/cd.yml")

    assert "verify-coordinated-js:" in workflow
    assert "verify-credentials-service:" in workflow
    assert "verify-core:" in workflow
    assert "Require successful Marty UI source CI" in workflow
    assert "Test Marty CLI clean-break client" in workflow
    assert "Test and build Marty Blog" in workflow
    assert "Test and build Marty Subscriptions" in workflow
    assert "Run issuance service tests" in workflow
    assert "Test Marty Core workspace" in workflow
    assert "verify-coordinated-js, verify-credentials-service, verify-core" in workflow


def test_cd_requires_a_marked_beta_copy_rehearsal_before_build_ready() -> None:
    workflow = _text(".github/workflows/cd.yml")

    assert "name: Rehearse One-Way Migration" in workflow
    assert "environment: beta-migration-rehearsal" in workflow
    assert "MIGRATION_REHEARSAL_DATABASE_URL" in workflow
    assert "MIGRATION_REHEARSAL_DATABASE_MARKER" in workflow
    assert "MIGRATION_REHEARSAL_SNAPSHOT_ID" in workflow
    assert "MIGRATION_REHEARSAL_PUBLIC_API_URL" in workflow
    assert 'if [[ "$DATABASE_URL" != *"$DATABASE_MARKER"* ]]' in workflow
    assert "REHEARSAL_MODE: beta-copy" in workflow
    assert "ephemeral-schema" not in workflow
    assert "127.0.0.1:5432/mip_rehearsal" not in workflow
    assert "snapshot_id:" in workflow
    assert "public_origin:" in workflow
    assert "MARTY_KMS_BOOTSTRAP_ENABLED=false" in workflow
    assert "/app/run_all_migrations.py --verify-only" in workflow
    assert "name: Publish Build-Ready Manifest" in workflow
    assert "image_digests:" in workflow
    assert 'status: "passed"' in workflow
    assert "build_ready: true" in workflow
    assert "release_ready: false" in workflow


def test_beta_gate_records_strict_spruce_metadata_evidence() -> None:
    workflow = _text(".github/workflows/e2e-tests.yml")
    probe = _text("scripts/check_spruceid_metadata.py")

    assert "Require SpruceKit-compatible issuer metadata" in workflow
    assert "spruce-metadata.json" in workflow
    assert "| tee" not in workflow
    assert "credential_configurations_supported" in probe
    assert "marty.example" in probe
    assert "verify=False" not in probe


def test_beta_gate_binds_browser_evidence_to_the_running_cd_release() -> None:
    workflow = _text(".github/workflows/e2e-tests.yml")
    cd = _text(".github/workflows/cd.yml")
    service_dockerfile = _text("services/Dockerfile.prod")
    ui_dockerfile = _text("docker/ui.Dockerfile")

    assert "Bind lifecycle to the successful CD build" in workflow
    assert "Require the selected release to be running on beta" in workflow
    assert 'gh run download "$CD_RUN_ID"' in workflow
    assert "/.well-known/marty-release" in workflow
    assert "/marty-ui-release.json" in workflow
    assert "cd_run_id: $cd_run_id" in workflow
    assert "release_version: $release_version" in workflow
    assert "MARTY_RELEASE_VERSION=${{ needs.determine-tag.outputs.version }}" in cd
    assert "MARTY_UI_SHA=${{ github.sha }}" in cd
    assert "ARG MARTY_RELEASE_VERSION=development" in service_dockerfile
    assert "dist-final/marty-ui-release.json" in ui_dockerfile


def test_beta_gate_requires_canonical_mip_discovery_shape() -> None:
    workflow = _text(".github/workflows/e2e-tests.yml")
    implementation = _text("services/gateway/mip_configuration.py")

    assert "mip_configuration_endpoint" in workflow
    assert "supported_compliance_profiles" in workflow
    assert "Array.isArray(body?.active_compliance_profiles)" in workflow
    forbidden = workflow.split("const forbidden =", 1)[1].split(";", 1)[0]
    assert "active_compliance_profiles" not in forbidden
    assert "mip_configuration_endpoint" in implementation
    assert '"supported_versions": ["0.3.1"]' in implementation
    assert '"active_compliance_profiles"' in implementation
    assert '"wallet_facing_endpoints"' not in implementation
