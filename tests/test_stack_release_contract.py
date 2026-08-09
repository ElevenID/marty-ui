from __future__ import annotations

import json
import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
FULL_SHA_ACTION = re.compile(r"^\s*(?:-\s*)?uses:\s*[^\s]+@[0-9a-f]{40}\s*$")


def _text(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_stack_release_consumes_only_immutable_public_components() -> None:
    workflow = _text(".github/workflows/cd.yml")

    required_components = {
        "marty-api-core",
        "marty-blog",
        "marty-cli",
        "marty-common",
        "marty-core-python",
        "marty-integration-tests",
    }
    for component in required_components:
        assert f'select(.name == "{component}")' in workflow

    assert "gh attestation verify" in workflow
    assert 'docker pull "$uri@$digest"' in workflow
    assert "repository: ElevenID/marty-integration-tests" in workflow
    assert "ref: ${{ needs.validate-stack.outputs.integration_commit }}" in workflow
    assert "API_CORE_URI: ${{ needs.validate-stack.outputs.api_core_uri }}" in workflow
    assert (
        "API_CORE_DIGEST: ${{ needs.validate-stack.outputs.api_core_digest }}"
        in workflow
    )
    assert "npm install --global /tmp/marty-api-core.tgz /tmp/marty-cli.tgz" in workflow
    assert 'any(.assets[]; .name == "stack-manifest.json")' in workflow
    assert "No previous public stack release" in workflow
    assert "marty-subscriptions" not in workflow
    assert "self-hosted" not in workflow
    assert "runs-on: ubuntu-latest" in workflow


def test_ci_verifies_the_pinned_mdoc_binding_evidence_contract() -> None:
    workflow = _text(".github/workflows/ci.yml")

    assert 'select(.name == "marty-core-python")' in workflow
    assert 'select(.type == "python") | .uri' in workflow
    assert 'select(.type == "python") | .digest' in workflow
    assert "sha256sum --check --strict" in workflow
    assert (
        'pip install pytest pyyaml jsonschema cryptography playwright "$marty_rs_wheel"'
        in workflow
    )
    assert "Verify released mdoc binding evidence contract" in workflow
    assert "from marty_rs import _marty_rs" in workflow
    assert "_marty_rs.MdocDocumentVerificationEvidence" in workflow
    assert '"issuer_certificate_sha256"' in workflow
    assert '"valid_at_verification_time"' in workflow
    assert "result.document_evidence == []" in workflow
    assert "result.revocation_checked is False" in workflow
    assert "result.not_revoked is None" in workflow


def test_cli_and_api_core_use_the_same_monorepo_release() -> None:
    lock = json.loads(_text("release/stack-lock.json"))
    components = {component["name"]: component for component in lock["components"]}

    api_core = components["marty-api-core"]
    cli = components["marty-cli"]
    assert api_core["repository"] == cli["repository"] == "ElevenID/marty-cli"
    assert api_core["version"] == cli["version"]
    assert api_core["commit"] == cli["commit"]


def test_stack_release_publishes_signed_evidence() -> None:
    workflow = _text(".github/workflows/cd.yml")

    assert "stack-manifest.json" in workflow
    assert "cosign sign --yes" in workflow
    assert "cosign sign-blob --yes" in workflow
    assert "actions/attest-build-provenance" in workflow
    assert "sbom: true" in workflow
    assert "SHA256SUMS" in workflow
    assert "softprops/action-gh-release" in workflow
    assert "pytest tests/oss_stack" in workflow


def test_stack_release_allows_only_successful_one_shot_exits() -> None:
    workflow = _text(".github/workflows/cd.yml")

    assert (
        "docker compose --env-file .env.stack ps --status exited --services" in workflow
    )
    assert '$0 != "migrations"' in workflow
    assert '$0 != "issuance-migrations"' in workflow
    assert "grep -v '^migrations$' || true" not in workflow


def test_stack_release_is_tag_only_and_targets_the_validated_tag() -> None:
    workflow = _text(".github/workflows/cd.yml")

    assert "workflow_dispatch:" in workflow
    assert (
        'test "$GITHUB_EVENT_NAME" = "push" || '
        'test "$GITHUB_EVENT_NAME" = "workflow_dispatch"'
    ) in workflow
    assert 'test "$GITHUB_REF_TYPE" = "tag"' in workflow
    assert 'test "$GITHUB_REF_NAME" = "v$version"' in workflow
    assert "tag_name: v${{ needs.validate-stack.outputs.version }}" in workflow
    assert "Reject any existing release" in workflow
    assert "python scripts/check_release_absent.py" in workflow
    assert "overwrite_files: false" in workflow
    # action-gh-release v3 stages assets before finalizing a standard release.
    # A second API edit is incompatible with GitHub immutable releases.
    assert "draft: true" not in workflow
    assert 'gh release edit "$RELEASE_TAG"' not in workflow
    assert "--draft=false" not in workflow
    assert "inputs.lock_file" not in workflow


def test_stack_release_actions_are_pinned_by_full_commit_sha() -> None:
    workflow = _text(".github/workflows/cd.yml")
    uses_lines = [line for line in workflow.splitlines() if "uses:" in line]

    assert uses_lines
    assert all(FULL_SHA_ACTION.match(line) for line in uses_lines)


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
    assert 'MARTY_COMMON_WHEEL="/tmp/${MARTY_COMMON_URI##*/}"' in dockerfiles
    assert "/tmp/marty-common.whl" not in dockerfiles
    assert "sha256sum --check --strict" in dockerfiles


def test_release_images_reject_commerce_markers() -> None:
    workflow = _text(".github/workflows/cd.yml")

    assert "Reject commerce configuration" in workflow
    assert "square|subscription|product[_-]?catalog|billing" in workflow
