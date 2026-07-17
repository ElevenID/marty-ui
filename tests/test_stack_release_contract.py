from __future__ import annotations

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
    assert "docker pull \"$uri@$digest\"" in workflow
    assert "repository: ElevenID/marty-integration-tests" in workflow
    assert "ref: ${{ needs.validate-stack.outputs.integration_commit }}" in workflow
    assert "API_CORE_URI: ${{ needs.validate-stack.outputs.api_core_uri }}" in workflow
    assert "API_CORE_DIGEST: ${{ needs.validate-stack.outputs.api_core_digest }}" in workflow
    assert "npm install --global /tmp/marty-api-core.tgz /tmp/marty-cli.tgz" in workflow
    assert 'any(.assets[]; .name == "stack-manifest.json")' in workflow
    assert "No previous public stack release" in workflow
    assert "marty-subscriptions" not in workflow
    assert "self-hosted" not in workflow
    assert "runs-on: ubuntu-latest" in workflow


def test_stack_release_publishes_signed_evidence() -> None:
    workflow = _text(".github/workflows/cd.yml")

    assert "stack-manifest.json" in workflow
    assert "cosign sign --yes" in workflow
    assert "cosign sign-blob --yes" in workflow
    assert "actions/attest-build-provenance" in workflow
    assert "sbom: true" in workflow
    assert "SHA256SUMS" in workflow
    assert "softprops/action-gh-release" in workflow
    assert "pytest tests/integration" in workflow


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
