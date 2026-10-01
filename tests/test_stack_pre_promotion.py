"""The final release check runs immediately before public version tags."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scripts.check_stack_pre_promotion import PrePromotionError, check


ROOT = Path(__file__).resolve().parents[1]
SOURCE = "a" * 40
IMAGES = (
    "ghcr.io/elevenid/marty-ui-oss/ui",
    "ghcr.io/elevenid/marty-ui-oss/services",
    "ghcr.io/elevenid/marty-ui-oss/migrations",
)


def transaction(*, promoted: list[str] | None = None) -> dict[str, object]:
    roles = [] if promoted is None else promoted
    return {
        "state": "qualified" if not roles else "promoting",
        "source_sha": SOURCE,
        "claim_run_id": "123",
        "tag": "v1.1.218",
        "version": "1.1.218",
        "repository": "ElevenID/marty-ui",
        "image_uris": dict(zip(("ui", "services", "migrations"), IMAGES, strict=True)),
        "promoted_roles": roles,
    }


def run_check(
    value: dict[str, object], *, main: str = SOURCE, tag_exists: bool = False,
    release_exists: bool = False, registry_exists: bool = False,
) -> tuple[bool, list[tuple[str, ...]]]:
    calls: list[tuple[str, ...]] = []

    def fake_git(*arguments: str) -> str:
        calls.append(("git", *arguments))
        if arguments == ("rev-parse", "HEAD^{commit}"):
            return SOURCE
        if arguments == ("rev-parse", "refs/remotes/origin/main^{commit}"):
            return main
        if arguments[0] == "ls-remote":
            return "existing" if tag_exists else ""
        return ""

    def fake_release(_repository: str, _tag: str, _token: str) -> None:
        calls.append(("release",))
        if release_exists:
            raise PrePromotionError("Release already exists")

    def fake_registry(image: str, _version: str, _actor: str, _token: str) -> None:
        calls.append(("registry", image))
        if registry_exists:
            raise PrePromotionError("Version tag already exists")

    result = check(
        value, source_sha=SOURCE, claim_run_id="123", tag="v1.1.218",
        repository="ElevenID/marty-ui", git_command=fake_git,
        release_absent=fake_release, registry_absent=fake_registry,
        token="test-token", actor="test-actor", images=IMAGES,
    )
    return result, calls


def test_fresh_claim_rechecks_main_tag_release_and_all_three_images() -> None:
    fresh, calls = run_check(transaction())
    assert fresh is True
    assert ("git", "fetch", "--no-tags", "origin",
            "+refs/heads/main:refs/remotes/origin/main") in calls
    assert ("git", "ls-remote", "--tags", "origin", "refs/tags/v1.1.218",
            "refs/tags/v1.1.218^{}") in calls
    assert ("release",) in calls
    assert [(call[1]) for call in calls if call[0] == "registry"] == list(IMAGES)


@pytest.mark.parametrize("change,match", [
    ({"source_sha": "b" * 40}, "exact claim"),
    ({"claim_run_id": "124"}, "exact claim"),
    ({"image_uris": {}}, "exact claim"),
])
def test_transaction_identity_must_match_claim(change: dict, match: str) -> None:
    with pytest.raises(PrePromotionError, match=match):
        run_check(transaction() | change)


@pytest.mark.parametrize("condition,match", [
    ({"main": "b" * 40}, "Protected main moved"),
    ({"tag_exists": True}, "tag already exists"),
    ({"release_exists": True}, "Release already exists"),
    ({"registry_exists": True}, "Version tag already exists"),
])
def test_fresh_claim_refuses_drift_or_owned_coordinate(condition: dict, match: str) -> None:
    with pytest.raises(PrePromotionError, match=match):
        run_check(transaction(), **condition)


def test_partial_resume_rechecks_main_without_requiring_absent_promoted_tags() -> None:
    fresh, calls = run_check(transaction(promoted=["ui"]), tag_exists=True)
    assert fresh is False
    assert ("git", "rev-parse", "refs/remotes/origin/main^{commit}") in calls
    assert not any(call[0] in ("release", "registry") or call[1] == "ls-remote"
                   for call in calls)


def test_workflow_runs_guard_before_first_public_tag_write() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/cd.yml").read_text())
    steps = workflow["jobs"]["publish-manifest"]["steps"]
    guard = next(index for index, step in enumerate(steps)
                 if step.get("name", "").startswith("Recheck exact main"))
    first_promotion = next(index for index, step in enumerate(steps)
                           if step.get("name", "").startswith("Promote the UI version tag"))
    assert guard < first_promotion
    assert "scripts/check_stack_pre_promotion.py" in steps[guard]["run"]
    assert steps[guard]["env"]["SOURCE_SHA"] == "${{ needs.resolve-transaction.outputs.source_sha }}"
    assert steps[guard]["env"]["CLAIM_RUN_ID"] == "${{ needs.resolve-transaction.outputs.claim_run_id }}"
