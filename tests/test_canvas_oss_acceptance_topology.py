from __future__ import annotations

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_oss_acceptance_does_not_synthesize_canvas_platform_metadata() -> None:
    nginx = (ROOT / "nginx-tunnel.conf.template").read_text(encoding="utf-8")
    canvas_block = nginx.split("# Real Canvas LMS test environment", 1)[1]
    assert "location = /.well-known/openid-configuration" not in canvas_block
    assert 'return 200 \'{"issuer"' not in canvas_block


def test_oss_acceptance_starts_no_bridge_plugin_or_competing_tunnel() -> None:
    compose = (ROOT / "docker-compose.canvas-oss-acceptance.yml").read_text(encoding="utf-8")
    assert "issuance-canvas-localhost-bridge" not in compose
    assert "canvas-localhost-bridge" not in compose
    assert "\n  cloudflared:" not in compose
    assert "readystack/canvas" not in compose
    assert "rails runner" not in compose.lower()
    assert "/usr/src/app:/usr/src/app" not in compose
    assert "image: postgres:14-alpine" not in compose
    assert "image: redis:7-alpine" not in compose
    assert "image: axllent/mailpit:v1.27" not in compose
    assert "image: nginx:1.27-alpine" not in compose
    for variable in (
        "CANVAS_OSS_POSTGRES_IMAGE",
        "CANVAS_OSS_REDIS_IMAGE",
        "CANVAS_OSS_MAILPIT_IMAGE",
        "CANVAS_OSS_EDGE_IMAGE",
    ):
        assert variable in compose


def test_full_workflow_never_uses_legacy_synthetic_demo_recorder() -> None:
    workflow = (ROOT / ".github/workflows/canvas-oss-portability.yml").read_text(encoding="utf-8")
    assert "record-canvas-employer-demo" not in workflow
    assert "seed_canvas_real" not in workflow
    assert "--profile contract run --rm --no-deps canvas-contract" in workflow
    assert "CANVAS_PORTABILITY_ATTESTATION_PATH" in workflow


def test_instructor_deep_linking_requires_the_stock_canvas_assignment_ui() -> None:
    driver = (ROOT / "tests/scripts/run-canvas-oss-standard-contract.js").read_text(
        encoding="utf-8"
    )
    implementation = driver.split("async function performInstructorDeepLinking", 1)[1].split(
        "async function launchStaffResource", 1
    )[0]
    assert "runDeepLinkingViaAssignmentUi" in implementation
    assert "runDeepLinkingViaSessionless" not in driver


def test_instructor_resource_launch_requires_the_stock_canvas_assignment_ui() -> None:
    driver = (ROOT / "tests/scripts/run-canvas-oss-standard-contract.js").read_text(
        encoding="utf-8"
    )
    implementation = driver.split("async function launchStaffResource", 1)[1].split(
        "function validateReadinessSnapshot", 1
    )[0]
    assert "/assignments`" in implementation
    assert "getByRole('link', { name: assignmentName, exact: true })" in implementation
    assert "waitForEvent('page'" in implementation
    assert "sessionless" not in driver.lower()


def test_learner_launch_requires_the_stock_canvas_assignment_ui() -> None:
    driver = (ROOT / "tests/scripts/run-canvas-oss-standard-contract.js").read_text(
        encoding="utf-8"
    )
    implementation = driver.split("async function launchLearnerResource", 1)[1].split(
        "async function reloadLearnerExperience", 1
    )[0]
    assert "/assignments`" in implementation
    assert "getByRole('link', { name: assignmentName, exact: true })" in implementation
    assert "sessionlessLaunch" not in implementation
    assert "waitForEvent('page'" in implementation


def test_live_contract_races_approval_and_requires_one_claim_transaction() -> None:
    driver = (ROOT / "tests/scripts/run-canvas-oss-standard-contract.js").read_text(
        encoding="utf-8"
    )
    assert "const concurrentApprovals = await Promise.all([" in driver
    assert "new Set(reservedTransactionIds).size === 1" in driver
    assert "duplicate_canvas_claim_transaction" in driver


def test_browser_contract_and_continuity_monitor_are_compose_only() -> None:
    compose = (ROOT / "docker-compose.canvas-oss-acceptance.yml").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/canvas-oss-portability.yml").read_text(encoding="utf-8")
    dockerfile = (ROOT / "tests/Dockerfile.canvas-oss-contract").read_text(encoding="utf-8")
    driver = (ROOT / "tests/scripts/run-canvas-oss-standard-contract.js").read_text(encoding="utf-8")

    assert "\n  canvas-contract:\n" in compose
    assert "\n  canvas-continuity-monitor:\n" in compose
    assert "profiles: [contract]" in compose
    assert "profiles: [monitor]" in compose
    assert "init: true" in compose
    assert "shm_size: 1gb" in compose
    assert compose.count("pull_policy: never") >= 2
    assert "tests/Dockerfile.canvas-oss-contract" in compose
    assert "CANVAS_OSS_ADMIN_PASSWORD_FILE: /run/secrets/canvas_admin_password" in compose
    assert "CANVAS_OSS_MARTY_API_KEY_FILE: /run/secrets/canvas_marty_api_key" in compose
    assert "CANVAS_OSS_ADMIN_PASSWORD:" not in compose
    assert "CANVAS_OSS_MARTY_API_KEY:" not in compose
    assert "POSTGRES_PASSWORD:" not in compose
    assert "POSTGRES_PASSWORD_FILE: /run/secrets/canvas_postgres_password" in compose
    assert "FROM ${CANVAS_OSS_PLAYWRIGHT_IMAGE}" in dockerfile
    assert "tests/canvas-oss-contract/package.json" in dockerfile
    assert "npm audit --audit-level=high" in dockerfile
    assert 'io.elevenid.canvas-oss.execution-boundary="docker-compose-one-shot"' in dockerfile
    assert "docker compose --project-name canvas-oss-portability" in workflow
    assert "--profile contract run --rm --no-deps canvas-contract" in workflow
    assert "--profile monitor up --detach --no-deps canvas-continuity-monitor" in workflow
    assert 'test "$actual_contract_image_id" = "$CANVAS_OSS_CONTRACT_IMAGE_ID"' in workflow
    assert "npm ci" not in workflow
    assert "npx playwright install" not in workflow
    assert 'node "$driver"' not in workflow
    assert "beta-monitor.pid" not in workflow
    assert "canvas_oss_beta_lifecycle.py monitor" not in workflow
    assert "requireComposeExecutionBoundary" in driver
    assert "requireSecretFile('CANVAS_OSS_ADMIN_PASSWORD')" in driver


def test_contract_driver_base_and_compose_boundary_are_locked() -> None:
    import json

    lock = json.loads((ROOT / "deploy-config/catalog/canvas-oss.lock.json").read_text(encoding="utf-8"))
    driver = lock["contract_driver"]
    topology = lock["acceptance_topology"]
    assert driver["base_image"] == (
        "mcr.microsoft.com/playwright:v1.56.0-jammy@"
        "sha256:8901203e4be3245885e0c0c58a3098d21a0892e17525bb32ce66ae37033434af"
    )
    assert driver["compose_service"] == "canvas-contract"
    assert driver["monitor_service"] == "canvas-continuity-monitor"
    assert driver["execution_boundary"] == "docker_compose_one_shot"
    assert driver["secret_transport"] == "compose_secret_files"
    assert driver["host_browser_processes"] is False
    assert topology["host_runtime_processes"] is False


def test_contract_package_lock_is_included_in_clean_checkouts() -> None:
    lock = ROOT / "tests/canvas-oss-contract/package-lock.json"
    assert lock.is_file()
    ignored = subprocess.run(
        ["git", "check-ignore", "--no-index", "--quiet", str(lock.relative_to(ROOT))],
        cwd=ROOT,
        check=False,
    )
    assert ignored.returncode == 1, "The contract package lock is ignored; clean CI checkouts cannot build the driver."


def test_workflow_requires_deployed_beta_capability_and_has_no_impossible_redeploy_switch() -> None:
    workflow = (ROOT / ".github/workflows/canvas-oss-portability.yml").read_text(encoding="utf-8")
    assert "check_canvas_beta_capabilities.py" in workflow
    assert "beta-capability-preflight.json" in workflow
    assert "redeploy_beta_before_run" not in workflow
    assert "beta_release_artifact_dir" not in workflow
    assert "deploy-canvas-oss-beta.ps1" not in workflow
    assert "deadline_epoch - $(date +%s) - 1200" in workflow
    assert "timeout --signal=TERM --kill-after=30s" in workflow
    assert 'gh attestation verify "oci://$image"' in workflow
    assert "--signer-workflow github.com/ElevenID/marty-ui/.github/workflows/canvas-oss-image.yml" in workflow
    assert "--source-ref refs/heads/main" in workflow


def test_canvas_image_publication_is_reviewed_and_default_branch_bound() -> None:
    workflow = (ROOT / ".github/workflows/canvas-oss-image.yml").read_text(encoding="utf-8")
    assert "environment: canvas-oss-image-publish" in workflow
    assert 'test "$GITHUB_REF" = "refs/heads/main"' in workflow
    assert 'test "$GITHUB_EVENT_NAME" = "workflow_dispatch"' in workflow
    for field in (
        "harness_repository",
        "harness_ref",
        "harness_head_sha",
        "publisher_workflow",
        "publisher_run_id",
    ):
        assert field in workflow


def test_canvas_workflows_pin_third_party_actions_to_full_commits() -> None:
    for relative in (
        ".github/workflows/canvas-oss-image.yml",
        ".github/workflows/canvas-oss-portability.yml",
        ".github/workflows/hosted-canvas-contract.yml",
    ):
        workflow = (ROOT / relative).read_text(encoding="utf-8")
        uses = [line.split("uses:", 1)[1].strip().split(" #", 1)[0] for line in workflow.splitlines() if "uses:" in line]
        assert uses
        for action in uses:
            assert "@" in action
            assert len(action.rsplit("@", 1)[1]) == 40


def test_canvas_image_build_converts_upstream_base_tag_to_reviewed_digest() -> None:
    lock = json.loads((ROOT / "deploy-config/catalog/canvas-oss.lock.json").read_text(encoding="utf-8"))
    policy = json.loads((ROOT / "docker/canvas-oss/source-policy.json").read_text(encoding="utf-8"))
    base = lock["image"]["base_image"]
    source = f"docker-image://docker.io/{base['reference']}"
    assert policy == {
        "rules": [
            {
                "action": "CONVERT",
                "selector": {"identifier": source},
                "updates": {"identifier": f"{source}@{base['linux_amd64_digest']}"},
            }
        ]
    }
    workflow = (ROOT / ".github/workflows/canvas-oss-image.yml").read_text(encoding="utf-8")
    assert "EXPERIMENTAL_BUILDKIT_SOURCE_POLICY" in workflow


def test_failure_retention_removes_containers_and_restores_prior_beta_canvas() -> None:
    workflow = (ROOT / ".github/workflows/canvas-oss-portability.yml").read_text(encoding="utf-8")
    retain = workflow.split('if [[ "$CURRENT_JOB_STATUS" = "failure"', 1)[1].split("else", 1)[0]
    assert "down --remove-orphans" in retain
    assert "down --volumes" not in retain
    assert "canvas_oss_beta_lifecycle.py restore" in retain
    assert 'rm -rf "$CANVAS_OSS_CONFIG_DIR"' in workflow


def test_runner_setup_is_explicit_ephemeral_and_fail_closed() -> None:
    setup = (ROOT / "scripts/setup-canvas-oss-runner.ps1").read_text(encoding="utf-8")
    register = (ROOT / "scripts/register-canvas-oss-runner.ps1").read_text(encoding="utf-8")
    preflight = (ROOT / "scripts/check_canvas_oss_runner.py").read_text(encoding="utf-8")
    docs = (ROOT / "docs/CANVAS_OSS_PORTABILITY_PIPELINE.md").read_text(encoding="utf-8")

    assert "InstallUbuntuIfMissing" in setup
    assert "RunnerArchiveSha256" in setup
    assert '[Convert]::ToBase64String' in setup
    assert '(Get-WslText @("--list", "--quiet")) -split' in setup
    assert "--ephemeral" in register
    assert "registration-token" in register
    assert '"self-hosted", "linux", "x64", "canvas-oss-wsl2"' in register
    for tool in ("gh", "jq", "node", "python3"):
        assert f'"{tool}"' in preflight
    assert "/var/run/docker.sock" in preflight
    assert "zero self-hosted runners" in docs
    assert "not ready to run it yet" in docs
    assert "all remain Docker Compose services" in docs
    assert "no second Docker daemon" in docs


def test_self_managed_origin_allowlist_is_wired_separately() -> None:
    for relative in (
        ".env.example",
        ".env.production.example",
        "docker-compose.base.yml",
        "docker-compose.selfhost.prod.yml",
        "k8s/oracle/01-configmap.yaml",
    ):
        content = (ROOT / relative).read_text(encoding="utf-8")
        assert "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST" in content
        assert "CANVAS_PRIVATE_ORIGIN_ALLOWLIST" in content


def test_coordinated_cd_requires_compose_migration_contract_for_pinned_credentials() -> None:
    workflow = (ROOT / ".github/workflows/cd.yml").read_text(encoding="utf-8")
    job = workflow.split("  verify-credentials-service:", 1)[1].split(
        "\n  verify-core:", 1
    )[0]

    assert "repository: ElevenID/marty-credentials" in job
    assert "ref: ${{ env.MARTY_CREDENTIALS_REF }}" in job
    assert "CANVAS_MIGRATION_SOURCE_REVISION: ${{ vars.MARTY_CREDENTIALS_REF }}" in job
    assert 'test "$(git rev-parse HEAD)" = "$CANVAS_MIGRATION_SOURCE_REVISION"' in job
    assert "docker-compose.canvas-migration-contract.yml config --quiet" in job
    assert "build --pull migration-contract" in job
    assert "up --force-recreate --abort-on-container-exit" in job
    assert "--exit-code-from migration-contract migration-contract" in job
    assert "contract-result.json" in job
    assert "'.source_revision'" in job
    assert (
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in job
    )
    assert "down --volumes --remove-orphans" in job
    assert "continue-on-error" not in job
