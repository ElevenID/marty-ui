from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _text(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_beta_lifecycle_workflow_is_fail_closed_and_canonical() -> None:
    workflow = _text(".github/workflows/e2e-tests.yml")

    assert "environment: beta-lifecycle" in workflow
    assert "types: [beta-deployed]" in workflow
    assert "Require deployed MIP 0.3 contract" in workflow
    assert "probe-beta-membership-badge.js" in workflow
    assert "verify-beta-waltid-acceptance.js" in workflow
    assert "audit-beta-org-credential-paths.js" in workflow
    assert "anthropic/marty-authenticator" not in workflow
    assert "test.skip" not in workflow
    assert "continue-on-error" not in workflow


def test_waltid_browser_wallet_images_are_versioned_and_digest_pinned() -> None:
    compose = _text("docker-compose.profile.waltid.yml")

    image_pattern = re.compile(r"docker\.io/waltid/[\w-]+:0\.5\.0@sha256:[0-9a-f]{64}")
    assert len(image_pattern.findall(compose)) == 2
    assert ":stable" not in compose
    assert "waltid-demo-wallet" not in compose


def test_beta_contract_probe_fails_on_mixed_or_legacy_routes() -> None:
    probe = _text("tests/scripts/probe-beta-membership-badge.js")

    assert "probe.mipVersion === '0.3.0'" in probe
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


def test_cd_rehearses_migrations_only_against_an_explicit_copy() -> None:
    workflow = _text(".github/workflows/cd.yml")

    assert "name: Rehearse One-Way Migration Against Beta Copy" in workflow
    assert "environment: beta-migration-rehearsal" in workflow
    assert "MIGRATION_REHEARSAL_DATABASE_URL" in workflow
    assert "MIGRATION_REHEARSAL_DATABASE_MARKER" in workflow
    assert 'if [[ "$DATABASE_URL" != *"$DATABASE_MARKER"* ]]' in workflow
    assert "MARTY_KMS_BOOTSTRAP_ENABLED=false" in workflow
    assert "/app/run_all_migrations.py --verify-only" in workflow
    assert "name: Publish Rehearsed Release Manifest" in workflow
    assert "image_digests:" in workflow
    assert 'migration_rehearsal: "passed"' in workflow
    assert "release_ready: true" in workflow
