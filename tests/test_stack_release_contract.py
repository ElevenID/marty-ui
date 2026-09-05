from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FULL_SHA_ACTION = re.compile(r"^\s*(?:-\s*)?uses:\s*[^\s]+@[0-9a-f]{40}\s*$")
GH_RUN_DOWNLOAD = re.compile(r"gh run download\b(?:[^\n]*\\\n)*[^\n]*")


def _text(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_stack_lock_bytes_are_platform_stable() -> None:
    assert "release/stack-lock*.json text eol=lf" in _text(".gitattributes")


def test_every_workflow_run_download_binds_the_repository_explicitly() -> None:
    commands: list[tuple[Path, str]] = []
    for workflow_path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        workflow = workflow_path.read_text(encoding="utf-8")
        commands.extend(
            (workflow_path, match.group(0))
            for match in GH_RUN_DOWNLOAD.finditer(workflow)
        )

    assert commands
    for workflow_path, command in commands:
        assert '--repo "$GITHUB_REPOSITORY"' in command, workflow_path


def test_stack_release_consumes_only_immutable_public_components() -> None:
    workflow = _text(".github/workflows/cd.yml")

    required_components = {
        "marty-api-core",
        "marty-blog",
        "marty-cli",
        "marty-common",
        "marty-core-python",
        "marty-verification-python",
        "marty-iso18013-python",
        "marty-integration-tests",
    }
    for component in required_components:
        assert f'select(.name == "{component}")' in workflow

    assert "gh attestation verify" in workflow
    assert 'docker pull "$uri@$digest"' in workflow
    assert "repository: ElevenID/marty-integration-tests" not in workflow
    assert '--history integration-history' in workflow
    assert '--expected-commit "$INTEGRATION_COMMIT"' in workflow
    assert 'read-tree "$INTEGRATION_COMMIT"' in workflow
    integration_stage = workflow.split(
        "- name: Stage the exact verified integration harness source", 1
    )[1].split("- uses: actions/upload-artifact@", 1)[0]
    assert 'select(.name == "marty-integration-tests") | .version' in integration_stage
    assert '[[ "$version" =~ ^[0-9]+\\.[0-9]+\\.[0-9]+$ ]]' in integration_stage
    assert 'source_ref="refs/tags/v${version}"' in integration_stage
    assert '--source-ref "$source_ref" --deny-self-hosted-runners' in integration_stage
    assert "refs/heads/main" not in integration_stage
    assert "stack-release-integration-source-${{ github.run_id }}" in workflow
    assert "scripts/extract_verified_source.py" in workflow
    assert "--expected-sha256 \"$INTEGRATION_DIGEST\"" in workflow
    assert "API_CORE_URI: ${{ needs.validate-stack.outputs.api_core_uri }}" in workflow
    assert (
        "API_CORE_DIGEST: ${{ needs.validate-stack.outputs.api_core_digest }}"
        in workflow
    )
    assert "npm install --global /tmp/marty-api-core.tgz /tmp/marty-cli.tgz" in workflow
    assert 'any(.assets[]; .name == "stack-manifest.json")' in workflow
    assert "No previous public stack release" in workflow
    assert "marty-subscriptions" not in workflow
    assert "runs-on: self-hosted" not in workflow
    assert "runs-on: ubuntu-latest" in workflow


def test_ci_verifies_the_pinned_mdoc_binding_evidence_contract() -> None:
    workflow = _text(".github/workflows/ci.yml")

    assert 'select(.name == "marty-core-python")' in workflow
    assert 'select(.type == "python") | .uri' in workflow
    assert 'select(.type == "python") | .digest' in workflow
    assert "sha256sum --check --strict" in workflow
    assert '"$marty_rs_wheel" "$verification_wheel" "$iso18013_wheel"' in workflow
    assert "Verify released mdoc binding evidence contract" in workflow
    assert "from marty_rs import _marty_rs" in workflow
    assert "import marty_verification" in workflow
    assert "import marty_iso18013" in workflow
    assert "_marty_rs.MdocDocumentVerificationEvidence" in workflow
    assert '"issuer_certificate_sha256"' in workflow
    assert '"valid_at_verification_time"' in workflow
    assert "result.document_evidence == []" in workflow
    assert "result.revocation_checked is False" in workflow
    assert "result.not_revoked is None" in workflow


def test_ci_and_stack_lock_pin_the_same_marty_common_release() -> None:
    workflow_text = _text(".github/workflows/ci.yml")
    workflow = yaml.safe_load(workflow_text)
    lock = json.loads(_text("release/stack-lock.json"))
    common = next(
        component
        for component in lock["components"]
        if component["name"] == "marty-common"
    )
    artifact = next(item for item in common["artifacts"] if item["type"] == "python")

    assert common["version"] == "0.2.16"
    assert common["commit"] == "36bb2aac65759edc2ccdce120e16a61391a7ce32"
    assert workflow["env"]["MARTY_COMMON_URI"] == artifact["uri"]
    assert workflow["env"]["MARTY_COMMON_DIGEST"] == artifact["digest"]
    assert 'marty_common_wheel="$RUNNER_TEMP/${MARTY_COMMON_URI##*/}"' in workflow_text
    assert "marty_common-0.2.4" not in workflow_text


def test_ci_and_stack_lock_pin_the_same_npm_releases() -> None:
    workflow = yaml.safe_load(_text(".github/workflows/ci.yml"))
    lock = json.loads(_text("release/stack-lock.json"))
    components = {component["name"]: component for component in lock["components"]}

    for component_name, env_prefix in (
        ("marty-api-core", "MARTY_API_CORE"),
        ("marty-blog", "MARTY_BLOG"),
    ):
        artifact = next(
            item
            for item in components[component_name]["artifacts"]
            if item["type"] == "npm"
        )
        assert workflow["env"][f"{env_prefix}_URI"] == artifact["uri"]
        assert workflow["env"][f"{env_prefix}_DIGEST"] == artifact["digest"]

    blog = components["marty-blog"]
    assert blog["version"] == "0.1.9"
    assert blog["commit"] == "587274a4e1d4281f8fa4d71cea212141759f0435"
    assert blog["artifacts"][0]["digest"] == (
        "sha256:1dda635bd284d9cb254e3c2c51fc09890cfae21b48a4c2095985621ad86cb358"
    )


def test_cli_and_api_core_use_the_same_monorepo_release() -> None:
    lock = json.loads(_text("release/stack-lock.json"))
    components = {component["name"]: component for component in lock["components"]}

    api_core = components["marty-api-core"]
    cli = components["marty-cli"]
    assert api_core["repository"] == cli["repository"] == "ElevenID/marty-cli"
    assert api_core["version"] == cli["version"]
    assert api_core["commit"] == cli["commit"]


def test_stack_artifacts_use_immutable_sha256_digests() -> None:
    lock = json.loads(_text("release/stack-lock.json"))

    for component in lock["components"]:
        for artifact in component["artifacts"]:
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"]), (
                f"{component['name']} has an invalid artifact digest"
            )


def test_ui_package_locks_match_stack_npm_artifacts() -> None:
    lock = json.loads(_text("release/stack-lock.json"))
    components = {component["name"]: component for component in lock["components"]}
    package = json.loads(_text("ui/package.json"))
    package_lock = json.loads(_text("ui/package-lock.json"))
    bun_lock = _text("ui/bun.lock")

    for component_name, package_name in (
        ("marty-api-core", "@elevenid/marty-api-core"),
        ("marty-blog", "@elevenid/marty-blog"),
    ):
        component = components[component_name]
        artifact = next(
            item for item in component["artifacts"] if item["type"] == "npm"
        )
        uri = artifact["uri"]

        assert package["dependencies"][package_name] == uri
        locked_package = package_lock["packages"][f"node_modules/{package_name}"]
        assert locked_package["version"] == component["version"]
        assert locked_package["resolved"] == uri
        assert f'"{package_name}": "{uri}"' in bun_lock
        assert f'"{package_name}": ["{package_name}@{uri}"' in bun_lock


def test_stack_release_publishes_signed_evidence() -> None:
    workflow = _text(".github/workflows/cd.yml")

    assert "stack-manifest.json" in workflow
    assert "cosign sign --yes" in workflow
    assert "cosign sign-blob --yes" in workflow
    assert "for attempt in 1 2 3 4" in workflow
    assert 'rm -f "${file}.sigstore.json"' in workflow
    assert 'if [ "$signed" != true ]' in workflow
    assert "Failed to sign $file after 4 attempts" in workflow
    assert "actions/attest-build-provenance" in workflow
    assert "sbom: true" in workflow
    assert "SHA256SUMS" in workflow
    assert "softprops/action-gh-release" not in workflow
    assert 'gh release create "$TAG" --verify-tag --generate-notes "${assets[@]}"' in workflow
    assert "assets=(stack-manifest.json release-transaction.json" in workflow
    assert 'release_id="$(gh api' in workflow
    assert 'echo "id=$release_id" >> "$GITHUB_OUTPUT"' in workflow
    assert "pytest tests/oss_stack" in workflow


def test_beta_lifecycle_binds_the_deployed_sha_to_stack_release_evidence() -> None:
    workflow = _text(".github/workflows/e2e-tests.yml")
    document = yaml.safe_load(workflow)
    inputs = document[True]["workflow_dispatch"]["inputs"]
    permissions = document["permissions"]

    assert inputs["marty_ui_release_sha"]["required"] is True
    assert inputs["stack_release_run_id"]["required"] is True
    assert "cd_run_id" not in inputs
    assert inputs["beta_source_id"]["required"] is True
    assert inputs["marty_protocol_sha"]["required"] is True
    assert permissions["actions"] == "read"
    assert permissions["attestations"] == "read"
    assert permissions["contents"] == "read"
    assert "ref: ${{ env.MARTY_UI_RELEASE_SHA }}" not in workflow
    assert 'test "$(git rev-parse HEAD)" = "$EVIDENCE_TOOLING_SHA"' in workflow
    assert 'git cat-file -e "$MARTY_UI_RELEASE_SHA^{commit}"' in workflow
    assert "BETA_SOURCE_ID must be a full 40-character source-snapshot ID" in workflow
    assert '-p marty-release-evidence --bin validate-stack-release-run --' in workflow
    assert '"$STACK_RELEASE_RUN_ID" "$RELEASE_VERSION" "$MARTY_UI_RELEASE_SHA" <<<"$run"' in workflow
    assert 'gh release download "v$RELEASE_VERSION"' in workflow
    assert "--pattern stack-manifest.json" in workflow
    assert "sha256sum --check --ignore-missing SHA256SUMS" in workflow
    assert (
        "gh attestation verify tests/artifacts/build-evidence/stack-manifest.json"
        in workflow
    )
    assert '.schema == "marty.stack/v1"' in workflow
    assert '.repository == "ElevenID/marty-core"' in workflow
    assert '--arg source_id "$BETA_SOURCE_ID"' in workflow
    assert "beta_source_id: $beta_source_id" in workflow
    assert "marty_protocol_sha: $marty_protocol_sha" in workflow
    assert "evidence_tooling_sha: $evidence_tooling_sha" in workflow
    assert "stack_manifest_sha256: $stack_manifest_sha256" in workflow
    assert "MARTY_PROTOCOL_SHA must be a full 40-character commit SHA" in workflow
    assert "CI must pin exactly one full MARTY_PROTOCOL_REF" not in workflow
    assert "test -f marty-core/Cargo.lock" in workflow
    assert "test -f marty-core/marty-test-wallet/Cargo.toml" in workflow
    assert "cargo metadata --locked --no-deps" in workflow
    assert "vendor/core2" not in workflow
    assert "${{ vars.MARTY_CORE_REF }}" not in workflow
    assert "${{ vars.MARTY_PROTOCOL_REF }}" not in workflow
    assert 'workflowName\' <<<"$run")" = "CD"' not in workflow
    assert "build-ready-manifest-$RELEASE_VERSION" not in workflow


def test_every_rust_toolchain_action_pins_the_workspace_toolchain() -> None:
    action = "dtolnay/rust-toolchain@6c977a6ca4077a0ceb28ffbe03f59d46e9ac8772"
    matched_steps: list[tuple[str, dict[str, object]]] = []

    for workflow_path in sorted((ROOT / ".github/workflows").glob("*.yml")):
        workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        for job in workflow.get("jobs", {}).values():
            for step in job.get("steps", []):
                if step.get("uses") == action:
                    matched_steps.append((workflow_path.name, step))

    assert matched_steps
    for workflow_name, step in matched_steps:
        assert step.get("with", {}).get("toolchain") == "1.95.0", workflow_name


def test_both_acceptance_lanes_use_the_same_rust_release_run_validator() -> None:
    for path in (".github/workflows/e2e-tests.yml", ".github/workflows/wallet-conformance.yml"):
        workflow = _text(path)
        assert 'gh api "repos/$GITHUB_REPOSITORY/actions/runs/$STACK_RELEASE_RUN_ID"' in workflow
        assert "cargo run --locked --quiet --manifest-path rust/Cargo.toml" in workflow
        assert "-p marty-release-evidence --bin validate-stack-release-run --" in workflow
        assert workflow.index("toolchain: 1.95.0") < workflow.index("--bin validate-stack-release-run")
        assert '.headBranch\' <<<"$stack_run")' not in workflow
        assert '.event\' <<<"$run")" = "push"' not in workflow
        assert "gh attestation verify" in workflow


def test_wallet_promotion_uses_signed_stack_and_distinct_release_source_lineage() -> (
    None
):
    workflow = _text(".github/workflows/wallet-conformance.yml")
    document = yaml.safe_load(workflow)
    inputs = document[True]["workflow_dispatch"]["inputs"]
    permissions = document["permissions"]

    assert inputs["stack_release_run_id"]["required"] is True
    assert inputs["beta_lifecycle_run_id"]["required"] is True
    assert "cd_run_id" not in inputs
    assert "marty_ui_sha" not in inputs
    assert permissions["actions"] == "read"
    assert permissions["attestations"] == "read"
    assert permissions["contents"] == "read"
    assert '-p marty-release-evidence --bin validate-stack-release-run --' in workflow
    assert '"$STACK_RELEASE_RUN_ID" "$RELEASE_VERSION" <<<"$stack_run"' in workflow
    assert 'gh release download "v$RELEASE_VERSION"' in workflow
    assert "--pattern stack-manifest.json" in workflow
    assert "sha256sum --check --strict stack-manifest.SHA256" in workflow
    assert "gh attestation verify stack-evidence/stack-manifest.json" in workflow
    assert "ref: ${{ steps.source_runs.outputs.tooling_sha }}" in workflow
    assert "--stack-manifest-sha256" in workflow
    assert "--marty-ui-release-sha" in workflow
    assert "--stack-release-run-id" in workflow
    assert "--build-manifest" not in workflow
    assert '"CD"' not in workflow


def test_beta_lifecycle_installs_each_playwright_browser_revision() -> None:
    workflow = _text(".github/workflows/e2e-tests.yml")

    assert "playwright==1.56.0" in workflow
    assert "-python-1.56.0" in workflow
    assert "npx playwright install --with-deps chromium" in workflow
    assert "python -m playwright install chromium" in workflow


def test_stack_release_ui_smoke_checks_real_homepage_content() -> None:
    workflow = _text(".github/workflows/cd.yml")

    assert "Smoke-test UI image" in workflow
    assert "UI image contains the default Nginx homepage" in workflow
    assert "UI image homepage is missing ElevenID content" in workflow
    assert "grep --quiet 'Welcome to nginx'" in workflow
    assert "grep --quiet 'ElevenID'" in workflow


def test_public_ui_build_requires_a_prerendered_root_page() -> None:
    dockerfile = _text("docker/ui.Dockerfile")
    vite_config = _text("ui/vite.config.ts")

    assert "test -s dist-final/index.html" in dockerfile
    assert "grep -q 'ElevenID' dist-final/index.html" in dockerfile
    assert "! grep -q 'Welcome to nginx' dist-final/index.html" in dockerfile
    assert "route.outputPath = PRERENDERED_ROOT_STAGING_PATH" in vite_config
    assert "promotePrerenderedRootPlugin()" in vite_config
    assert "unlinkSync(stagedPath)" in vite_config


def test_stack_release_allows_only_successful_one_shot_exits() -> None:
    workflow = _text(".github/workflows/cd.yml")

    assert (
        "docker compose --env-file .env.stack ps --status exited --services" in workflow
    )
    assert '$0 != "migrations"' in workflow
    assert '$0 != "issuance-migrations"' in workflow
    assert '$0 != "revocation-profile-migrations"' in workflow
    assert "grep -v '^migrations$' || true" not in workflow


def test_deletion_release_uses_the_reviewed_integration_suite_and_rust_candidate_overlay() -> (
    None
):
    workflow = _text(".github/workflows/cd.yml")

    assert (
        "COMPOSE_FILE: docker-compose.yml:docker-compose.rust-revocation.yml"
        in workflow
    )
    assert "repository: ElevenID/marty-integration-tests" not in workflow
    assert "scripts/extract_verified_source.py" in workflow

    lock = json.loads(_text("release/stack-lock.json"))
    integration = next(
        component
        for component in lock["components"]
        if component["name"] == "marty-integration-tests"
    )
    assert integration["version"] == "1.2.79"
    assert integration["commit"] == "7d24c73c1ef7e7dfb7e5cf119c6552321e58fa71"
    assert integration["artifacts"][0]["digest"] == (
        "sha256:622e878e47a9c8239160bc2e38fe2423d6fe9843de18e6c953433ccd32a905b7"
    )

    issuance = next(
        component
        for component in lock["components"]
        if component["name"] == "marty-credentials-issuance"
    )
    assert issuance["version"] == "0.1.72"
    assert issuance["commit"] == "85b128a85426b3f5aeaf6f948ba5dfa2836e95d8"
    assert issuance["artifacts"][0]["digest"] == (
        "sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176"
    )


def test_verifier_release_lineage_is_eligible_and_evidence_bounded() -> None:
    lock = json.loads(_text("release/stack-lock.json"))
    components = {component["name"]: component for component in lock["components"]}

    assert lock["release"] == "marty-ui@1.1.216"
    assert lock["release_state"] == "eligible"
    assert components["marty-credentials-issuance"]["version"] == "0.1.72"
    assert components["marty-integration-tests"]["version"] == "1.2.79"

    documents = (
        _text("docs/CONSOLIDATED_RUST_MIGRATION_ROADMAP.md"),
        _text("docs/rust-migrations/verification-image-consolidation-plan.md"),
        _text("docs/rust-migrations/verifier-release-incident-2026-08-31.md"),
    )
    for document in documents:
        normalized = " ".join(document.split())
        assert (
            "`v0.1.72` is a valid issuance component, not a failed verifier "
            "artifact" in normalized
        )
        assert (
            "`v1.2.76` is retained held evidence only and grants no cutover "
            "authorization" in normalized
        )
        assert "`v1.2.77` is intermediate evidence only" in normalized
        assert "`v1.2.78` is preliminary, non-activating evidence" in normalized
        assert (
            "PR `#737` introduced the candidate producer; its first dispatch "
            "occurred only after the later hardening described below" in normalized
        )
        assert (
            "PR `#741` hardened the producer but retained raw tar-header "
            "offset defects" in normalized
        )
        assert "PR `#744` corrected those specific defects" in normalized
        assert (
            "Producer run `33465702948`, attempt `1`, was dispatched from exact "
            "protected-main commit "
            "`2fa1ffa3b36a0c978a41377dd64ab084bc8fc204` before the trusted "
            "consumer landed" in normalized
        )
        assert (
            "It failed bundle validation with `OCI layer tar is empty` before "
            "attestation or artifact upload, so it supplies no admissible "
            "candidate-gate acceptance" in normalized
        )
        assert "`7a1e2d6f31a563b33832b46921ec3376cd124113`" in normalized
        assert "producer run `33490549237`, attempt `1`" in normalized
        assert "consumer run `33491836719`, attempt `1`" in normalized
        assert "all 19 language-neutral checks matched" in normalized.lower()
        assert "`canonical.oid4vp-positive-runtime-not-exercised`" in normalized
        assert "`4e817b32f6d65f88c763af79e2f07df1eb8a1ce7`" in normalized
        assert "`v1.1.211`" in document
        assert "`v1.1.212`" in document
        assert "`v1.1.213`" in document
        assert "`v1.1.214`" in document
        assert "`33926833221`" in document
        assert "`9957092310`" in document


def test_stack_release_is_claim_only_digest_first_and_publishes_last() -> None:
    workflow = _text(".github/workflows/cd.yml")

    assert "workflow_dispatch:" in workflow
    assert "push:\n    tags:" not in workflow
    assert "claim_run_id:" in workflow
    assert "resume_run_id:" in workflow
    assert "resume_artifact:" in workflow
    assert "push-by-digest=true" in workflow
    assert "name-canonical=true" in workflow
    assert "scripts/release_transaction.py record-digests" in workflow
    assert "scripts/release_transaction.py qualify" in workflow
    assert "scripts/release_transaction.py record-promotion" in workflow
    assert "scripts/release_transaction.py publish" in workflow
    assert "create-transaction-pin" in workflow
    assert "run-transaction" in workflow
    assert "TAG: ${{ needs.resolve-transaction.outputs.tag }}" in workflow
    assert 'gh release create "$TAG" --verify-tag --generate-notes "${assets[@]}"' in workflow
    assert "overwrite_files:" not in workflow
    assert "draft: true" not in workflow
    assert 'gh release edit "$RELEASE_TAG"' not in workflow
    assert "--draft=false" not in workflow
    assert "inputs.lock_file" not in workflow
    assert workflow.index("pytest tests/oss_stack -v") < workflow.index(
        "docker buildx imagetools create --tag"
    )
    assert "compare-transaction-evidence" in workflow
    assert "--oracle-pin config/credentials-verifier-oracle.json" in workflow
    assert "--transaction-pin work/transaction-pin.json" in workflow
    assert '.status == "matched"' in workflow
    assert ".comparison_status" not in workflow
    assert ".release_blockers" not in workflow
    assert workflow.index("compare-transaction-evidence") < workflow.index(
        "docker buildx imagetools create --tag"
    )
    assert workflow.index("docker buildx imagetools create --tag") < workflow.index(
        'gh release create "$TAG"'
    )


def test_stack_release_actions_are_pinned_by_full_commit_sha() -> None:
    workflow = _text(".github/workflows/cd.yml")
    uses_lines = [line for line in workflow.splitlines() if "uses:" in line]

    assert uses_lines
    assert all(
        FULL_SHA_ACTION.match(line) or "uses: ./.github/workflows/" in line
        for line in uses_lines
    )


def test_conflicting_or_unrecoverable_release_claims_have_a_tombstone_lane() -> None:
    workflow = _text(".github/workflows/tombstone-stack-release.yml")

    assert "workflow_dispatch:" in workflow
    assert "claim_run_id:" in workflow
    assert "source_run_id:" in workflow
    assert "source_artifact:" in workflow
    assert "reason:" in workflow
    assert "evidence_sha256:" in workflow
    assert "scripts/release_transaction.py validate" in workflow
    assert "scripts/release_transaction.py tombstone" in workflow
    assert "git merge-base --is-ancestor" in workflow
    assert 'git show "${SOURCE_SHA}:release/stack-lock.json"' in workflow
    assert "--stack-lock claimed-stack-lock.json" in workflow
    assert "stack-release-tombstone-${{ inputs.claim_run_id }}" in workflow
    assert "contents: write" not in workflow
    assert "packages: write" not in workflow
    assert "git push" not in workflow
    assert "gh release" not in workflow
    uses_lines = [line for line in workflow.splitlines() if "uses:" in line]
    assert uses_lines
    assert all(FULL_SHA_ACTION.match(line) for line in uses_lines)


def test_release_workflows_never_checkout_dispatch_or_transaction_data() -> None:
    workflows = (
        _text(".github/workflows/cd.yml"),
        _text(".github/workflows/prepare-stack-tag.yml"),
        _text(".github/workflows/tombstone-stack-release.yml"),
    )
    forbidden_refs = (
        "ref: ${{ inputs.source_sha }}",
        "ref: ${{ steps.identity.outputs.source_sha }}",
        "ref: ${{ steps.untrusted.outputs.source_sha }}",
        "ref: ${{ needs.resolve-transaction.outputs.source_sha }}",
        "ref: ${{ needs.validate-stack.outputs.integration_commit }}",
    )
    for workflow in workflows:
        assert all(reference not in workflow for reference in forbidden_refs)


def test_stack_release_uses_read_only_default_permissions() -> None:
    document = yaml.safe_load(_text(".github/workflows/cd.yml"))

    assert document["permissions"] == {"contents": "read"}
    for job in document["jobs"].values():
        permissions = job.get("permissions", {})
        assert permissions.get("actions") != "write"
        assert permissions.get("security-events") != "write"


def test_public_builds_do_not_checkout_sibling_sources() -> None:
    workflow = _text(".github/workflows/cd.yml")
    dockerfiles = "\n".join(
        _text(path)
        for path in (
            "docker/ui.Dockerfile",
            "services/Dockerfile",
            "services/Dockerfile.migrations",
        )
    )

    assert "context: .." not in workflow
    assert "COPY ../" not in dockerfiles
    assert "MARTY_COMMON_URI" in dockerfiles
    assert "MARTY_COMMON_DIGEST" in dockerfiles
    assert "MARTY_VERIFICATION_URI" in dockerfiles
    assert "MARTY_VERIFICATION_DIGEST" in dockerfiles
    assert "MARTY_ISO18013_URI" in dockerfiles
    assert "MARTY_ISO18013_DIGEST" in dockerfiles
    assert 'MARTY_COMMON_WHEEL="/tmp/${MARTY_COMMON_URI##*/}"' in dockerfiles
    assert "/tmp/marty-common.whl" not in dockerfiles
    assert "sha256sum --check --strict" in dockerfiles


def test_stack_release_creates_the_annotated_tag_only_after_digest_qualification() -> (
    None
):
    workflow = _text(".github/workflows/cd.yml")

    assert "Require the exact claimed protected-main source" in workflow
    assert "+refs/heads/main:refs/remotes/origin/main" in workflow
    assert "Create or verify the late annotated source tag" in workflow
    assert 'git tag -a "$TAG" "$SOURCE_SHA"' in workflow
    assert 'git push origin "refs/tags/$TAG:refs/tags/$TAG"' in workflow
    assert 'test "$(git cat-file -t "refs/tags/$TAG")" = tag' in workflow
    assert (
        'test "$(git rev-parse "refs/tags/$TAG^{commit}")" = "$SOURCE_SHA"' in workflow
    )
    assert 'grep -Fx "Release-Transaction: $TRANSACTION_ID"' in workflow
    assert workflow.index("stack-release-qualified-") < workflow.index(
        "Create or verify the late annotated source tag"
    )


def test_stack_tag_requires_exact_main_gate_evidence() -> None:
    workflow = _text(".github/workflows/cd.yml")
    prepare = _text(".github/workflows/prepare-stack-tag.yml")
    policy = json.loads(_text(".github/stack-tag-policy.json"))

    assert policy["schema"] == "elevenid.stack-tag-preparation/v1"
    assert policy["required_workflows"] == [
        {"path": ".github/workflows/ci.yml", "event": "merge_group"},
        {
            "path": ".github/workflows/open-source-policy.yml",
            "event": "merge_group",
        },
        {
            "path": ".github/workflows/organization-quality.yml",
            "event": "merge_group",
        },
        {"path": ".github/workflows/codeql-rust.yml", "event": "merge_group"},
        {"path": ".github/workflows/codeql-actions.yml", "event": "merge_group"},
    ]
    assert "scripts/stack_tag_gate.py prepare" in prepare
    assert "git ls-remote --tags" in prepare
    assert "git tag -a" not in prepare
    assert "git bundle create" not in prepare
    assert "scripts/check_release_absent.py" in prepare
    assert "scripts/release_transaction.py claim" in prepare
    assert "stack-release-claim-${{ inputs.tag }}" in prepare
    assert "release-transaction.json" in prepare
    assert "git push origin" not in prepare
    assert "gh workflow run cd.yml" not in prepare
    assert "scripts/release_transaction.py validate" in workflow
    assert "stack-release-claim-v" in workflow
    assert "actions: read" in workflow


def test_stack_tag_and_release_require_explicit_eligibility() -> None:
    workflow = _text(".github/workflows/cd.yml")
    prepare = _text(".github/workflows/prepare-stack-tag.yml")
    lock = json.loads(_text("release/stack-lock.json"))
    example_lock = json.loads(_text("release/stack-lock.example.json"))

    assert lock["release_state"] == "eligible"
    assert example_lock["release_state"] == "hold"
    assert "scripts/stack_tag_gate.py prepare" in prepare
    assert "--repository ." in prepare
    assert "scripts/release_transaction.py claim" in prepare
    assert "scripts/release_transaction.py validate" in workflow
    assert "--stack-lock release/stack-lock.json" in workflow
    assert workflow.index("scripts/release_transaction.py validate") < workflow.index(
        "scripts/build_stack_manifest.py"
    )


def test_python_migration_image_installs_every_required_native_backend() -> None:
    service = _text("services/Dockerfile")
    migrations = _text("services/Dockerfile.migrations")

    assert 'MARTY_RS_WHEEL="/tmp/${MARTY_RS_URI##*/}"' in migrations
    assert 'MARTY_VERIFICATION_WHEEL="/tmp/${MARTY_VERIFICATION_URI##*/}"' in migrations
    assert 'MARTY_ISO18013_WHEEL="/tmp/${MARTY_ISO18013_URI##*/}"' in migrations
    assert '"$MARTY_VERIFICATION_WHEEL"' in migrations
    assert '"$MARTY_ISO18013_WHEEL"' in migrations
    assert "MARTY_RS_WHEEL" not in service
    assert "python" not in service.split("FROM debian:bookworm-slim", maxsplit=1)[1]

    lock = json.loads(_text("release/stack-lock.json"))
    components = {component["name"]: component for component in lock["components"]}
    for name in (
        "marty-core-python",
        "marty-verification-python",
        "marty-iso18013-python",
    ):
        assert components[name]["version"] == "0.1.61"
        assert components[name]["commit"] == "a3adbbdca93251e4db7933c5c77fe5e8c3f4266c"


def test_release_images_reject_commerce_markers() -> None:
    workflow = _text(".github/workflows/cd.yml")

    assert "Reject commerce configuration" in workflow
    assert "square|subscription|product[_-]?catalog|billing" in workflow
