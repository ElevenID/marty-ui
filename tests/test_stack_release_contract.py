from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import yaml
import pytest

from scripts import stack_tag_gate
from scripts.selfhost_handoff_contract import PINNED_INTEGRATION_SHA
from scripts.kms_core_release import (
    CORE_RELEASE_URI,
    CORE_REVISION,
    CORE_VERSION,
    CORE_WHEEL_PREFIXES,
)

ROOT = Path(__file__).resolve().parents[1]
FULL_SHA_ACTION = re.compile(r"^\s*(?:-\s*)?uses:\s*[^\s]+@[0-9a-f]{40}\s*$")
GH_RUN_DOWNLOAD = re.compile(r"gh run download\b(?:[^\n]*\\\n)*[^\n]*")


def _text(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_stack_lock_bytes_are_platform_stable() -> None:
    assert "release/stack-lock*.json text eol=lf" in _text(".gitattributes")


def test_ci_retries_transient_public_wheel_errors_without_skipping_digests() -> None:
    jobs = yaml.safe_load(_text(".github/workflows/ci.yml"))["jobs"]
    for job_id in ("test-services", "test-release-contracts"):
        install = next(
            step["run"] for step in jobs[job_id]["steps"]
            if step.get("name") in {"Install dependencies", "Install released test dependencies"}
        )
        for name in ("marty_rs", "verification", "iso18013"):
            assert (
                "curl --fail --location --silent --show-error --connect-timeout 15 "
                "--max-time 60 --retry 5 --retry-delay 2 --retry-max-time 120 "
                f'"${name}_uri" --output "${name}_wheel"'
            ) in install
            assert f'echo "${{{name}_digest#sha256:}}  ${name}_wheel" | sha256sum --check --strict' in install


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
        if workflow_path.name == "e2e-tests.yml" and '"$DEMO_QUALIFICATION_RUN_ID"' in command:
            assert '--repo ElevenID/marty-demo-recorder' in command, workflow_path
            assert '--name "demo-release-qualification-$RELEASE_VERSION"' in command
        else:
            assert '--repo "$GITHUB_REPOSITORY"' in command, workflow_path


def test_stack_release_consumes_only_immutable_public_components() -> None:
    workflow = _text(".github/workflows/cd.yml")

    required_components = {
        "marty-api-core",
        "marty-blog",
        "marty-cli",
        "marty-core-python",
        "marty-verification-python",
        "marty-iso18013-python",
        "marty-integration-tests",
    }
    for component in required_components:
        assert f'select(.name == "{component}")' in workflow

    assert "gh attestation verify" in workflow
    assert 'gh attestation verify "oci://ghcr.io/elevenid/marty-ui-oss/services@$SERVICES_DIGEST"' in workflow
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
    assert "Render the exact Rust-only public stack images" in workflow
    assert "--previous-manifest" not in workflow
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


def test_ci_and_stack_lock_exclude_retired_marty_common_wheel() -> None:
    workflow_text = _text(".github/workflows/ci.yml")
    workflow = yaml.safe_load(workflow_text)
    lock = json.loads(_text("release/stack-lock.json"))
    assert all(item["name"] != "marty-common" for item in lock["components"])
    assert "MARTY_COMMON_URI" not in workflow["env"]
    assert "MARTY_COMMON_DIGEST" not in workflow["env"]
    assert 'marty_common_wheel=' not in workflow_text


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
    assert 'gh release create "$TAG" --verify-tag --generate-notes "${OPERATOR_RELEASE_ASSETS[@]}"' in workflow
    assert "source scripts/operator-release-assets.sh" in workflow
    assert "operator_release_require_remote_allowlist" in workflow
    assert 'release_id="$(gh api' in workflow
    assert 'echo "id=$release_id" >> "$GITHUB_OUTPUT"' in workflow
    assert "pytest tests/oss_stack" in workflow


def test_release_checksums_cover_every_published_asset_once(tmp_path: Path) -> None:
    """Execute the producer's actual checksum/asset expressions, without publishing."""
    workflow = yaml.safe_load(_text(".github/workflows/cd.yml"))
    steps = workflow["jobs"]["publish-manifest"]["steps"]
    signing = next(
        step["run"] for step in steps
        if step.get("name") == "Sign and checksum manifest evidence"
    )
    assert 'sha256sum "${OPERATOR_CHECKSUM_INPUTS[@]}" > SHA256SUMS' in signing
    assert "operator_release_require_local_assets" in signing

    subjects = {
        "stack-manifest.json",
        "release-transaction.json",
        "marty-ui-sbom.cdx.json",
        "marty-ui-services-sbom.cdx.json",
        "marty-ui-migrations-sbom.cdx.json",
        "marty-deploy-linux-amd64",
        "marty-deploy-linux-arm64",
        "marty-ui-openbao-didcomm-sbom.cdx.json",
        "marty-ui-keycloak-sbom.cdx.json",
    }
    expected_assets = subjects | {f"{name}.sigstore.json" for name in subjects}
    for name in expected_assets:
        (tmp_path / name).write_bytes(f"fixture:{name}\n".encode())

    # Windows' system bash can be an unconfigured WSL launcher; use Git Bash.
    if os.name == "nt":
        git = shutil.which("git")
        assert git is not None, "Git Bash is required for release shell contracts"
        bash = str(Path(git).resolve().parents[1] / "bin" / "bash.exe")
    else:
        bash = shutil.which("bash")
    assert bash is not None and Path(bash).is_file(), "Bash is required"

    result = subprocess.run(
        [
            bash, "--noprofile", "--norc", "-euo", "pipefail", "-c",
            'source "$ASSET_SCRIPT"\nsha256sum "${OPERATOR_CHECKSUM_INPUTS[@]}" > SHA256SUMS\n'
            'operator_release_require_local_assets\nprintf "%s\\n" "${OPERATOR_RELEASE_ASSETS[@]}"',
        ],
        cwd=tmp_path,
        env={**os.environ, "ASSET_SCRIPT": str(ROOT / "scripts/operator-release-assets.sh")},
        capture_output=True, text=True, check=True, timeout=30,
    )

    def flat_name(value: str) -> str:
        name = value.removeprefix("./")
        assert name and "/" not in name and "\\" not in name
        assert name not in {".", ".."}
        return name

    published = [flat_name(line) for line in result.stdout.splitlines()]
    assert len(published) == len(set(published))
    assert set(published) == expected_assets | {"SHA256SUMS"}
    checksummed = []
    for line in (tmp_path / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        assert match is not None
        digest, name = match.groups()
        name = flat_name(name)
        assert name in expected_assets
        assert digest == hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
        checksummed.append(name)
    assert len(checksummed) == len(set(checksummed))
    assert set(checksummed) == set(published) - {"SHA256SUMS"}

    def verify() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [bash, "--noprofile", "--norc", "-c", "sha256sum --check --strict SHA256SUMS"],
            cwd=tmp_path, check=False, capture_output=True, text=True,
            timeout=30,
        )

    assert verify().returncode == 0
    (tmp_path / "release-transaction.json").write_bytes(b"changed transaction\n")
    corrupted = verify()
    assert corrupted.returncode != 0
    assert "release-transaction.json: FAILED" in corrupted.stdout

    (tmp_path / "release-transaction.json").write_bytes(
        b"fixture:release-transaction.json\n"
    )
    with (tmp_path / "SHA256SUMS").open("a", encoding="utf-8") as handle:
        handle.write(f"{'0' * 64}  unexpected-asset\n")
    unexpected = subprocess.run(
        [bash, "--noprofile", "--norc", "-c",
         'source "$ASSET_SCRIPT"; operator_release_require_checksum_names SHA256SUMS'],
        cwd=tmp_path,
        env={**os.environ, "ASSET_SCRIPT": str(ROOT / "scripts/operator-release-assets.sh")},
        capture_output=True, text=True, timeout=30,
    )
    assert unexpected.returncode != 0
    assert "exact release assets" in unexpected.stderr


def test_operator_release_builds_native_arches_and_verifies_provenance() -> None:
    jobs = yaml.safe_load(_text(".github/workflows/cd.yml"))["jobs"]
    build = jobs["build-operator-catalog"]
    publisher = jobs["publish-manifest"]
    matrix = build["strategy"]["matrix"]["include"]
    assert {(item["runner"], item["arch"]) for item in matrix} == {
        ("ubuntu-24.04", "amd64"), ("ubuntu-24.04-arm", "arm64")
    }
    assert {item["target"] for item in matrix} == {
        "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"
    }
    assert build["permissions"]["attestations"] == "write"
    assert "build-operator-catalog" in publisher["needs"]
    build_steps = "\n".join(step.get("run", "") for step in build["steps"])
    publish_steps = "\n".join(step.get("run", "") for step in publisher["steps"])
    assert 'test "$GITHUB_SHA" = "$SOURCE_SHA"' in build_steps
    assert 'if readelf -l "$asset" | grep -q INTERP' in build_steps
    assert 'test "$(./"$asset" --build-identity)" = "$MARTY_DEPLOY_SOURCE_SHA:$MARTY_DEPLOY_RELEASE_TAG"' in build_steps
    assert 'grep -aFq -- "$SOURCE_SHA:$RELEASE_TAG" "$asset"' in publish_steps
    assert '--source-digest "$SOURCE_SHA" --source-ref refs/heads/main' in publish_steps
    assert "operator_release_require_remote_allowlist" in publish_steps

    installer = _text("scripts/install-marty-deploy.sh")
    for condition in (
        "operator_release_require_remote_allowlist",
        "operator_release_require_checksum_names",
        "cosign verify-blob",
        '--certificate-identity "https://github.com/$repo/.github/workflows/cd.yml@refs/heads/main"',
        '--source-digest "$source_sha" --source-ref refs/heads/main',
        'test "$("$stage/$asset" --build-identity)" = "$source_sha:$tag"',
    ):
        assert condition in installer


def test_release_resume_accepts_original_signed_assets_after_bundle_regeneration(
    tmp_path: Path,
) -> None:
    """A retry may produce different valid Sigstore bundles for the same source."""
    workflow = yaml.safe_load(_text(".github/workflows/cd.yml"))
    step = next(
        step["run"] for step in workflow["jobs"]["publish-manifest"]["steps"]
        if step.get("name") == "Detect only an exact resumable immutable release"
    )
    assert "operator_release_verify_published_assets existing-release" in step
    assert "cmp --silent stack-manifest.json existing-release/stack-manifest.json" in step
    assert "cmp --silent release-transaction.json existing-release/release-transaction.json" in step
    assert 'cmp --silent "$asset"' not in step

    old = tmp_path / "published"
    new = tmp_path / "regenerated"
    for directory, signature in ((old, b"original"), (new, b"retry")):
        directory.mkdir()
        subjects = (
            "stack-manifest.json", "release-transaction.json",
            "marty-ui-sbom.cdx.json", "marty-ui-services-sbom.cdx.json",
            "marty-ui-migrations-sbom.cdx.json", "marty-ui-openbao-didcomm-sbom.cdx.json",
            "marty-ui-keycloak-sbom.cdx.json",
            "marty-deploy-linux-amd64",
            "marty-deploy-linux-arm64",
        )
        for name in subjects:
            (directory / name).write_bytes(f"qualified:{name}\n".encode())
            (directory / f"{name}.sigstore.json").write_bytes(signature + name.encode())
        checksums = "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in directory.iterdir()
        )
        (directory / "SHA256SUMS").write_bytes(checksums.encode())

    assert (old / "SHA256SUMS").read_bytes() != (new / "SHA256SUMS").read_bytes()
    if os.name == "nt":
        git = shutil.which("git")
        assert git is not None
        bash = str(Path(git).resolve().parents[1] / "bin" / "bash.exe")
    else:
        bash = shutil.which("bash")
    assert bash is not None
    script = (
        'source "$ASSET_SCRIPT"\n'
        'cosign() { printf "cosign:%s\\n" "$3" >> "$VERIFY_LOG"; }\n'
        'gh() { printf "gh:%s\\n" "$3" >> "$VERIFY_LOG"; }\n'
        'operator_release_verify_published_assets "$PUBLISHED" '
        '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ElevenID/marty-ui\n'
    )
    log = tmp_path / "verification.log"
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-euo", "pipefail", "-c", script],
        env={**os.environ, "ASSET_SCRIPT": str(ROOT / "scripts/operator-release-assets.sh"),
             "PUBLISHED": str(old), "VERIFY_LOG": str(log)},
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    calls = log.read_text(encoding="utf-8").splitlines()
    assert len(calls) == 18  # Nine Cosign signatures and nine source attestations.
    assert sum(call.startswith("cosign:") for call in calls) == 9
    assert sum(call.startswith("gh:") for call in calls) == 9

    (old / "marty-deploy-linux-arm64").write_bytes(b"tampered")
    tampered = subprocess.run(
        [bash, "--noprofile", "--norc", "-euo", "pipefail", "-c", script],
        env={**os.environ, "ASSET_SCRIPT": str(ROOT / "scripts/operator-release-assets.sh"),
             "PUBLISHED": str(old), "VERIFY_LOG": str(log)},
        capture_output=True, text=True, timeout=30,
    )
    assert tampered.returncode != 0


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


def test_beta_browser_contracts_run_after_chromium_and_system_dependencies() -> None:
    workflow = yaml.safe_load(_text(".github/workflows/e2e-tests.yml"))
    steps = workflow["jobs"]["full-stack-credential-lifecycle"]["steps"]
    names = [step.get("name") for step in steps]
    required_order = [
        "Install browser test dependencies",
        "Cache Chromium",
        "Install Chromium",
        "Install Chromium system dependencies",
        "Test beta evidence and recording contracts",
        "Require release-bound public demos on beta",
    ]
    assert all(names.count(name) == 1 for name in required_order)
    positions = [names.index(name) for name in required_order]
    assert positions == sorted(positions)
    contracts = steps[names.index("Test beta evidence and recording contracts")]
    assert contracts["run"] == "node --test scripts/*.test.js"
    assert contracts["working-directory"] == "tests"
    assert "if" not in contracts
    assert not contracts.get("continue-on-error", False)
    install = steps[names.index("Install Chromium")]
    dependencies = steps[names.index("Install Chromium system dependencies")]
    assert install["run"] == "npx playwright install --with-deps chromium"
    assert install["if"] == "steps.playwright-cache.outputs.cache-hit != 'true'"
    assert dependencies["run"] == "npx playwright install-deps chromium"
    assert dependencies["if"] == "steps.playwright-cache.outputs.cache-hit == 'true'"


def test_passport_publication_installs_pinned_chromium_before_verification() -> None:
    workflow = yaml.safe_load(
        _text(".github/workflows/passport-beta-demo-publication.yml")
    )
    steps = workflow["jobs"]["publish-evidence"]["steps"]
    install_index = next(
        index for index, step in enumerate(steps)
        if step.get("name") == "Install pinned publication verifier dependencies"
    )
    verification_index = next(
        index for index, step in enumerate(steps)
        if step.get("name")
        == "Authenticate preliminary and release, then verify live publication"
    )
    install = steps[install_index]
    commands = [line.strip() for line in install["run"].splitlines()]
    assert install_index < verification_index
    assert commands.index("npm ci") < commands.index(
        "npx playwright install --with-deps chromium"
    ) < commands.index("node --test test/passportPublicationEvidence.test.js")


def test_every_rust_toolchain_action_pins_the_workspace_toolchain() -> None:
    action = "dtolnay/rust-toolchain@02cb101ec7c40f2c49e1d9714d64511d8e1b74de"
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


def test_selfhost_ui_image_carries_its_runtime_assets() -> None:
    dockerfile = _text("docker/ui.Dockerfile")
    registry_builder = _text("scripts/build-push-registry.sh")
    selfhost_stage = dockerfile.split("FROM runtime-base AS selfhost", maxsplit=1)[1].split(
        "FROM runtime-base AS public", maxsplit=1
    )[0]
    selfhost_build = registry_builder.split('"ui-selfhost"', maxsplit=1)[1].split(
        '"ui"', maxsplit=1
    )[0]

    assert "COPY --from=builder /workspace/marty-ui/ui/dist-final /opt/marty-ui-static" in selfhost_stage
    assert "COPY scripts/load-secrets-env.sh /scripts/load-secrets-env.sh" in selfhost_stage
    assert (
        "COPY scripts/ui-selfhost-start.sh /docker-entrypoint.d/40-ui-selfhost.sh"
        in selfhost_stage
    )
    assert "--target selfhost" in selfhost_build
    assert "--build-arg UI_VARIANT=selfhost" in selfhost_build
    assert "--build-arg NGINX_CONFIG=nginx.spa.conf" in selfhost_build
    assert dockerfile.rstrip().endswith(
        "COPY --from=builder /workspace/marty-ui/ui/dist-final /usr/share/nginx/html"
    )


def test_stack_release_allows_only_successful_one_shot_exits() -> None:
    workflow = _text(".github/workflows/cd.yml")

    assert (
        "docker compose --env-file .env.stack ps --status exited --services" in workflow
    )
    assert "migrations|issuance-migrations|revocation-profile-migrations|" in workflow
    assert "docker inspect --format '{{.State.ExitCode}}'" in workflow
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
    assert integration["version"] == "1.2.90"
    assert integration["commit"] == "5b3ec6a802a5e13201be8883741889405a86d146"
    assert PINNED_INTEGRATION_SHA == integration["commit"]
    assert integration["artifacts"][0]["digest"] == (
            "sha256:2dddf814b58d0214c41407c92eca331e54ff85ee30990c224fb3a82dccec589c"
    )

    assert all(component["name"] != "marty-credentials-issuance"
               for component in lock["components"])
    assert all(artifact["type"] != "oci"
               for component in lock["components"]
               for artifact in component["artifacts"])


def test_verifier_release_lineage_uses_hardened_core_and_native_issuance() -> None:
    lock = json.loads(_text("release/stack-lock.json"))
    components = {component["name"]: component for component in lock["components"]}

    assert lock["release"] == "marty-ui@1.1.258"
    assert lock["release_state"] == "eligible"
    stack_tag_gate.require_release_eligible(ROOT, "v1.1.258")
    workflow = _text(".github/workflows/cd.yml")
    assert 'manifest_timestamp="$(git show -s --format=%cI "$SOURCE_SHA")"' in workflow
    assert '--generated-at "$manifest_timestamp" --output stack-manifest.json' in workflow
    assert '`prepare_selfhost_lock=true`' in _text("docs/selfhost-disposable-qualification-runbook.md")
    release_tag = "v" + lock["release"].removeprefix("marty-ui@")
    cutover_guide = _text("docs/keycloak-kms-installed-cutover.md")
    assert release_tag in cutover_guide
    kms_tracker = _text("docs/remote-kms-hardening-plan.md")
    assert f"source stack lock currently selects `{lock['release']}`" in kms_tracker
    with pytest.raises(stack_tag_gate.StackTagGateError, match="release"):
        stack_tag_gate.require_release_eligible(ROOT, "v1.1.244")
    assert "marty-credentials-issuance" not in components
    assert components["marty-integration-tests"]["version"] == "1.2.90"

    # Detailed producer incident history belongs in the incident/runbook owners,
    # rather than being duplicated in the current migration requirements.
    documents = (
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
    assert 'gh release create "$TAG" --verify-tag --generate-notes "${OPERATOR_RELEASE_ASSETS[@]}"' in workflow
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


def test_verifier_scans_request_the_frozen_cyclonedx_schema() -> None:
    release = yaml.safe_load(_text(".github/workflows/cd.yml"))
    candidate = yaml.safe_load(_text(".github/workflows/verification-candidate-build.yml"))

    for job in (release["jobs"]["verifier-differential"], candidate["jobs"]["build"]):
        scans = [step for step in job["steps"] if str(step.get("uses", "")).startswith("anchore/sbom-action@")]
        assert len(scans) == 1
        assert scans[0]["with"]["format"] == "cyclonedx-json@1.6"

    verifier = next(
        step for step in release["jobs"]["verifier-differential"]["steps"]
        if step.get("name") == "Verify and exercise the exact services digest against the immutable oracle"
    )
    assert "create-transaction-pin" in verifier["run"]
    assert "validate-sbom" in verifier["run"]


def test_verifier_transaction_uses_attested_core_source_and_disposable_kms() -> None:
    release = yaml.safe_load(_text(".github/workflows/cd.yml"))
    steps = release["jobs"]["verifier-differential"]["steps"]
    producer = next(step for step in steps if step.get("name") == "Build the exact attested Core KMS verifier producer")
    assert "config/credentials-verifier-positive-producer.json" in producer["run"]
    assert "gh attestation verify" in producer["run"]
    assert "--source-ref \"refs/tags/$tag\"" in producer["run"]
    assert "--source-digest \"$commit\"" in producer["run"]
    assert "--deny-self-hosted-runners" in producer["run"]
    assert "extract_verified_source.py" in producer["run"]
    assert "--expected-sha256 \"$digest\"" in producer["run"]
    assert "--expected-commit \"$commit\"" in producer["run"]
    assert "cargo +1.97.1 build --locked" in producer["run"]
    verifier = next(
        step for step in steps
        if step.get("name") == "Verify and exercise the exact services digest against the immutable oracle"
    )
    assert "scripts/with_disposable_verifier_kms.py" in verifier["run"]
    assert "--bin marty-test-signer-agent" in producer["run"]
    assert "--agent \"$GITHUB_WORKSPACE/core-source/target/debug/marty-test-signer-agent\"" in verifier["run"]
    assert "compare-transaction-evidence" in verifier["run"]


def test_exercised_public_kms_helper_is_attested_only_for_prepared_selfhost() -> None:
    jobs = yaml.safe_load(_text(".github/workflows/cd.yml"))["jobs"]
    verifier = jobs["verifier-differential"]
    assert verifier["runs-on"] == "ubuntu-24.04"
    assert verifier["permissions"]["attestations"] == "write"
    assert verifier["permissions"]["id-token"] == "write"
    steps = verifier["steps"]
    named = {step.get("name"): i for i, step in enumerate(steps)}
    build = named["Build the Rust public-key fixture converter"]
    exercise = named["Verify and exercise the exact services digest against the immutable oracle"]
    record = named["Record the exercised self-host public-key helper"]
    verify = named["Verify the just-attested helper source"]
    attest = [i for i, step in enumerate(steps)
              if step.get("uses", "").startswith("actions/attest-build-provenance@")]
    bundles = named["Preserve exact public-key helper SLSA bundles"]
    upload = next(i for i, step in enumerate(steps)
                  if step.get("with", {}).get("name", "").startswith("selfhost-public-kms-jwk-unqualified-"))
    assert len(attest) == 2
    assert build < exercise < record < attest[0] < attest[1] < bundles < verify < upload
    assert steps[build]["env"]["PREPARE_SELFHOST_LOCK"] == "${{ inputs.prepare_selfhost_lock }}"
    assert 'if [[ "$PREPARE_SELFHOST_LOCK" = true ]]; then' in steps[build]["run"]
    assert 'test "$GITHUB_SHA" = "$SOURCE_SHA"' in steps[build]["run"]
    assert "--bin public-kms-jwk" in steps[build]["run"]
    assert all(steps[i]["if"] == "inputs.prepare_selfhost_lock == true"
               for i in (record, *attest, verify, upload))
    assert [steps[i]["with"]["subject-path"] for i in attest] == [
        "public-kms-jwk", "selfhost-public-kms-jwk.json"]
    assert [steps[i]["id"] for i in attest] == [
        "attest-public-kms-binary", "attest-public-kms-receipt"]
    assert all("outputs.bundle-path" in value for value in steps[bundles]["env"].values())
    assert "test -s \"$BINARY_BUNDLE\"" in steps[bundles]["run"]
    assert "test -s \"$RECEIPT_BUNDLE\"" in steps[bundles]["run"]
    assert "install -m 0755 marty-ui/rust/target/release/public-kms-jwk public-kms-jwk" in steps[record]["run"]
    assert "cmp marty-ui/rust/target/release/public-kms-jwk public-kms-jwk" in steps[record]["run"]
    assert "verify_selfhost_public_kms_helper.py" in steps[verify]["run"]
    assert '--run-id "$GITHUB_RUN_ID"' in steps[verify]["run"]
    assert "selfhost-public-kms-jwk.json" in steps[upload]["with"]["path"]
    assert "public-kms-jwk" in steps[upload]["with"]["path"]
    assert "public-kms-jwk.slsa-bundle.json" in steps[upload]["with"]["path"]
    assert "selfhost-public-kms-jwk.slsa-bundle.json" in steps[upload]["with"]["path"]
    assert steps[upload]["with"]["retention-days"] == 7
    # Producer-only: no immutable release asset or tester-side bypass yet.
    assert "selfhost-public-kms-jwk" not in str(jobs["publish-manifest"])
    assert "build_public_kms_jwk_tool" in _text("scripts/run_selfhost_business_journey.py")


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


def test_verifier_kms_producer_is_an_attested_release_locked_commit() -> None:
    jobs = yaml.safe_load(_text(".github/workflows/cd.yml"))["jobs"]
    verifier = jobs["verifier-differential"]
    producer = next(step for step in verifier["steps"]
                    if step.get("name") == "Build the exact attested Core KMS verifier producer")
    assert 'select(.repository == "ElevenID/marty-core")' in producer["run"]
    assert 'all(.[]; . == [$commit, $version])' in producer["run"]
    assert "gh attestation verify" in producer["run"]
    assert "extract_verified_source.py" in producer["run"]
    script = next(step["run"] for step in verifier["steps"]
                  if step.get("name") == "Verify and exercise the exact services digest against the immutable oracle")
    assert "--jwk-tool" in script
    assert "with_disposable_verifier_kms.py" in script


def test_fresh_native_schema_gate_binds_exact_release_images() -> None:
    jobs = yaml.safe_load(_text(".github/workflows/cd.yml"))["jobs"]
    native = jobs["native-schema-image-qualification"]
    release = jobs["qualify-release"]
    assert native["needs"] == [
        "resolve-transaction", "build-services", "record-digests",
    ]
    assert "native-schema-image-qualification" in release["needs"]
    step = next(item for item in native["steps"]
                if item.get("name") == "Verify and qualify exact released Rust schema images")
    assert step["env"]["SERVICES_DIGEST"] == (
        "${{ needs.build-services.outputs.services_digest }}")
    assert step["env"]["MIGRATIONS_DIGEST"] == (
        "${{ needs.build-services.outputs.migrations_digest }}")
    assert step["env"]["SOURCE_SHA"] == (
        "${{ needs.resolve-transaction.outputs.source_sha }}")
    script = step["run"]
    assert "gh attestation verify" in script
    assert "--source-ref refs/heads/main --deny-self-hosted-runners" in script
    assert "python scripts/qualify_selfhost_migrations.py" in script
    assert "deploy-config/passport-supported-disposable-infra-images.json" in script
    assert "--services-image \"$services_image\"" in script
    assert "--migrations-image \"$migrations_image\"" in script
    assert 'marty.selfhost-migrations-qualification/v3' in script
    assert 'marty.selfhost-migrations-qualification/v3' in _text(
        "scripts/qualify_selfhost_migrations.py")
    assert 'reachable-unreachable-malformed-read-only' in script
    assert '.runs == "2"' in script
    assert any(item.get("with", {}).get("name") ==
               "stack-release-native-schema-gate-${{ github.run_id }}"
               for item in native["steps"])
    assert any(item.get("with", {}).get("name") ==
               "stack-release-native-schema-gate-${{ github.run_id }}"
               for item in release["steps"])
    persist = next(item["run"] for item in release["steps"]
                   if item.get("name") == "Persist exact gate evidence")
    assert "sha256sum gates/native/native-schema.json" in persist
    assert '--gate "native_schema=$GITHUB_RUN_ID:$native_digest"' in persist


def test_public_stack_smoke_binds_all_five_kms_images() -> None:
    jobs = yaml.safe_load(_text(".github/workflows/cd.yml"))["jobs"]
    smoke = jobs["public-stack-smoke"]
    plugin = jobs["didcomm-plugin-image-qualification"]
    release = jobs["qualify-release"]
    build = next(step for step in smoke["steps"]
                 if step.get("name") == "Build candidate stack manifest")
    script = build["run"]

    assert "build-openbao-didcomm" in smoke["needs"]
    assert build["env"]["OPENBAO_DIDCOMM_DIGEST"] == "${{ needs.build-openbao-didcomm.outputs.digest }}"
    assert script.count('{type: "oci"') == 5
    assert 'marty-ui-oss/keycloak' in script
    assert 'marty-ui-oss/openbao-didcomm' in script
    assert "build-openbao-didcomm" in plugin["needs"]
    assert "didcomm-plugin-image-qualification" in release["needs"]
    run = next(step["run"] for step in smoke["steps"]
               if step.get("name") == "Run the artifact-only public integration suite")
    for service in (
        "openbao-tls-init",
        "openbao-ca-export",
        "openbao-plugin-bootstrap",
        "signing-integration-tls-bootstrap",
    ):
        assert service in run
    assert "docker inspect --format '{{.State.ExitCode}}'" in run


def test_release_qualifies_exact_keycloak_kms_image_before_promotion() -> None:
    jobs = yaml.safe_load(_text(".github/workflows/cd.yml"))["jobs"]
    gate = jobs["keycloak-kms-image-qualification"]
    assert {"build-keycloak", "build-openbao-didcomm", "record-digests"} <= set(gate["needs"])
    proof = next(step["run"] for step in gate["steps"]
                 if step.get("name") == "Verify and exercise exact Keycloak and OpenBao image digests")
    assert 'gh attestation verify "oci://$image"' in proof
    assert '--require-browser' in proof
    assert '--keycloak-image "$keycloak" --openbao-image "$openbao"' in proof
    assert "keycloak-kms-image-qualification" in jobs["qualify-release"]["needs"]
    qualifier = next(step["run"] for step in jobs["qualify-release"]["steps"]
                     if step.get("name") == "Persist exact gate evidence")
    assert '--gate "keycloak_kms=$GITHUB_RUN_ID:$keycloak_digest"' in qualifier


def test_release_publishes_and_qualifies_the_exact_openbao_didcomm_image() -> None:
    workflow = _text(".github/workflows/cd.yml")
    jobs = yaml.safe_load(workflow)["jobs"]
    prepare = _text(".github/workflows/prepare-stack-tag.yml")
    image = "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm"

    assert f"OPENBAO_DIDCOMM_IMAGE: {image}" in workflow
    assert f"OPENBAO_DIDCOMM_IMAGE: {image}" in prepare
    assert '--image "openbao_didcomm=$OPENBAO_DIDCOMM_IMAGE"' in prepare
    build = jobs["build-openbao-didcomm"]
    build_step = next(step for step in build["steps"] if step.get("id") == "build")
    assert build_step["with"]["file"] == "openbao/didcomm-authcrypt/Dockerfile"
    assert "push-by-digest=true" in build_step["with"]["outputs"]
    assert any("actions/attest-build-provenance" in step.get("uses", "")
               for step in build["steps"])
    assert any('cosign sign --yes "$OPENBAO_DIDCOMM_IMAGE@$DIGEST"'
               in step.get("run", "") for step in build["steps"])

    assert "build-openbao-didcomm" in jobs["record-digests"]["needs"]
    recorded = next(step["run"] for step in jobs["record-digests"]["steps"]
                    if step.get("name") == "Persist the exact digest checkpoint")
    assert '--digest "openbao_didcomm=$OPENBAO_DIDCOMM_DIGEST"' in recorded
    gate = jobs["didcomm-plugin-image-qualification"]
    assert "build-openbao-didcomm" in gate["needs"]
    probe = next(step["run"] for step in gate["steps"]
                 if step.get("name") == "Verify and exercise the exact published OpenBao DIDComm image")
    for required in (
        'gh attestation verify "oci://$image"',
        'export MARTY_OPENBAO_PROBE_IMAGE="$image"',
        "probe_didcomm_issuance_token.py",
        "probe_didcomm_openbao_ha.py",
        "probe_selfhost_openbao_raft_bootstrap.py",
    ):
        assert required in probe
    assert "didcomm-plugin-image-qualification" in jobs["qualify-release"]["needs"]
    assert '--gate "didcomm_plugin=$GITHUB_RUN_ID:$didcomm_digest"' in workflow
    publication = jobs["publish-manifest"]
    assert "build-openbao-didcomm" in publication["needs"]
    assert '--role openbao_didcomm --digest "$DIGEST"' in workflow
    assert 'uri: "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm"' in workflow
    assert "marty-ui-openbao-didcomm-sbom.cdx.json" in workflow


def test_release_publication_needs_qualified_artifacts_without_manual_review() -> None:
    jobs = yaml.safe_load(_text(".github/workflows/cd.yml"))["jobs"]
    publication = jobs["publish-manifest"]
    requirement = json.loads(_text("deploy-config/github-release-environments.json"))[
        "environments"
    ]["stack-release"]

    assert "notify-release-approval" not in jobs
    assert publication["environment"] == "stack-release"
    assert "qualify-release" in publication["needs"]
    assert requirement["require_reviewers"] is False
    assert requirement["require_branch_policy"] is True
    assert requirement["prevent_admin_bypass"] is True


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
    assert "marty-migration-bootstrap" in dockerfiles
    assert "COPY ../" not in dockerfiles
    assert "pip install" not in _text("services/Dockerfile.migrations")
    assert "marty_common" not in dockerfiles


def test_stack_release_creates_the_annotated_tag_only_after_digest_qualification() -> (
    None
):
    workflow = _text(".github/workflows/cd.yml")

    assert "Require the exact claimed protected-main source" in workflow
    assert "+refs/heads/main:refs/remotes/origin/main" in workflow
    assert "Create or verify the late annotated source tag" in workflow
    helper = _text("scripts/push_promoted_release_tag.py")
    assert 'command("git", "tag", "-a", tag, source' in helper
    assert 'command("git", "push", "--atomic", "origin", f"{source}:refs/heads/main"' in helper
    assert 'f"refs/tags/{tag}:refs/tags/{tag}"' in helper
    assert 'test "$(git cat-file -t "refs/tags/$TAG")" = tag' in workflow
    assert (
        'test "$(git rev-parse "refs/tags/$TAG^{commit}")" = "$SOURCE_SHA"' in workflow
    )
    assert 'grep -Fx "Release-Transaction: $TRANSACTION_ID"' in workflow
    assert workflow.index("stack-release-qualified-") < workflow.index(
        "Create or verify the late annotated source tag"
    )


def test_workflow_changing_source_tag_uses_local_promotion_handoff() -> None:
    jobs = yaml.safe_load(_text(".github/workflows/cd.yml"))["jobs"]
    assert "STACK_RELEASE_TAG_TOKEN" not in _text(".github/workflows/cd.yml")

    publisher = jobs["publish-manifest"]
    checkout = next(
        step for step in publisher["steps"]
        if step.get("uses", "").startswith("actions/checkout@")
    )
    assert checkout["with"]["persist-credentials"] is False
    tag_step = next(
        step for step in publisher["steps"]
        if step.get("name") == "Create or verify the late annotated source tag"
    )
    assert "GH_TOKEN" not in tag_step["env"]
    assert "stack-release-promotion-complete-$GITHUB_RUN_ID" in tag_step["run"]
    assert "exit 1" in tag_step["run"]
    helper = _text("scripts/push_promoted_release_tag.py")
    assert 'required_state="promoted"' in helper
    assert "gh\", \"auth\", \"setup-git" in helper


def test_stack_tag_requires_exact_main_gate_evidence() -> None:
    workflow = _text(".github/workflows/cd.yml")
    prepare = _text(".github/workflows/prepare-stack-tag.yml")
    ci = _text(".github/workflows/ci.yml")
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
    assert policy["required_full_qualification"] == {
        "path": ".github/workflows/ci.yml",
        "events": ["schedule", "workflow_dispatch"],
    }
    assert (
        "MARTY_CANVAS_FULL_QUALIFICATION: "
        "${{ (github.event_name == 'workflow_dispatch' || "
        "github.event_name == 'schedule') && '1' || '0' }}"
    ) in ci
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


def test_stack_tag_and_release_require_the_reviewed_eligibility_lock() -> None:
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


def test_rust_migration_image_has_no_python_runtime_or_wheels() -> None:
    service = _text("services/Dockerfile")
    migrations = _text("services/Dockerfile.migrations")

    assert "FROM debian:bookworm-slim" in migrations
    assert "marty-migration-bootstrap" in migrations
    assert "marty-notification" in migrations
    assert "COPY services /app/services" not in migrations
    assert "RUN python" not in migrations
    assert "pip install" not in migrations
    assert "MARTY_RS_WHEEL" not in service
    assert "python" not in service.split("FROM debian:bookworm-slim", maxsplit=1)[1]

    lock = json.loads(_text("release/stack-lock.json"))
    components = {component["name"]: component for component in lock["components"]}
    for name in (
        "marty-core-python",
        "marty-verification-python",
        "marty-iso18013-python",
    ):
        assert components[name]["version"] == CORE_VERSION
        assert components[name]["commit"] == CORE_REVISION
        assert components[name]["artifacts"][0]["uri"].startswith(
            CORE_RELEASE_URI + CORE_WHEEL_PREFIXES[name] + "-" + CORE_VERSION + "-"
        )


def test_release_images_reject_commerce_markers() -> None:
    workflow = _text(".github/workflows/cd.yml")

    assert "Reject commerce configuration" in workflow
    assert "square|subscription|product[_-]?catalog|billing" in workflow
