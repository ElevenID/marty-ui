"""The final release check runs immediately before public version tags."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scripts.check_release_absent import RegistryTagAlreadyExists
from scripts.check_stack_pre_promotion import PrePromotionError, check
from scripts.release_transaction import IMAGE_URIS, REQUIRED_IMAGE_ROLES


ROOT = Path(__file__).resolve().parents[1]
SOURCE = "a" * 40
IMAGES = tuple(IMAGE_URIS[role] for role in REQUIRED_IMAGE_ROLES)
DIGESTS = dict(zip(REQUIRED_IMAGE_ROLES,
                   ("sha256:" + character * 64 for character in "abcd"), strict=True))


def transaction(*, promoted: list[str] | None = None, state: str | None = None) -> dict[str, object]:
    roles = [] if promoted is None else promoted
    return {
        "state": state or ("qualified" if not roles else "promoting"),
        "source_sha": SOURCE,
        "claim_run_id": "123",
        "tag": "v1.1.218",
        "version": "1.1.218",
        "repository": "ElevenID/marty-ui",
        "image_uris": dict(zip(REQUIRED_IMAGE_ROLES, IMAGES, strict=True)),
        "images": {role: {"uri": image, "digest": DIGESTS[role]}
                   for role, image in zip(REQUIRED_IMAGE_ROLES, IMAGES, strict=True)},
        "promoted_roles": roles,
    }


def run_check(
    value: dict[str, object], *, main: str = SOURCE, source_is_ancestor: bool = True,
    tag_exists: bool = False,
    release_exists: bool = False, registry_exists: tuple[str, ...] = (),
    drift_role: str | None = None,
) -> tuple[dict[str, bool], list[tuple[str, ...]]]:
    calls: list[tuple[str, ...]] = []

    def fake_git(*arguments: str) -> str:
        calls.append(("git", *arguments))
        if arguments == ("rev-parse", "HEAD^{commit}"):
            return SOURCE
        if arguments == ("rev-parse", "refs/remotes/origin/main^{commit}"):
            return main
        if arguments == ("merge-base", SOURCE, main):
            return SOURCE if source_is_ancestor else "c" * 40
        if arguments[0] == "ls-remote":
            return "existing" if tag_exists else ""
        return ""

    def fake_release(_repository: str, _tag: str, _token: str) -> None:
        calls.append(("release",))
        if release_exists:
            raise PrePromotionError("Release already exists")

    def fake_registry(image: str, _version: str, _actor: str, _token: str) -> None:
        calls.append(("registry", image))
        if image in registry_exists:
            raise RegistryTagAlreadyExists("Version tag already exists")

    def fake_digest(image: str, _version: str) -> str:
        calls.append(("digest", image))
        role = REQUIRED_IMAGE_ROLES[IMAGES.index(image)]
        return "sha256:" + "f" * 64 if role == drift_role else DIGESTS[role]

    result = check(
        value, source_sha=SOURCE, claim_run_id="123", tag="v1.1.218",
        repository="ElevenID/marty-ui", git_command=fake_git,
        release_absent=fake_release, registry_absent=fake_registry,
        digest_lookup=fake_digest,
        token="test-token", actor="test-actor", images=IMAGES,
    )
    return result, calls


def test_fresh_claim_rechecks_main_tag_release_and_all_images() -> None:
    existing, calls = run_check(transaction())
    assert existing == {role: False for role in REQUIRED_IMAGE_ROLES}
    assert ("git", "fetch", "--no-tags", "origin",
            "+refs/heads/main:refs/remotes/origin/main") in calls
    assert ("git", "ls-remote", "--tags", "origin", "refs/tags/v1.1.218",
            "refs/tags/v1.1.218^{}") in calls
    assert ("release",) in calls
    assert [(call[1]) for call in calls if call[0] == "registry"] == list(IMAGES)


def test_descendant_main_does_not_invalidate_qualified_source() -> None:
    existing, calls = run_check(transaction(), main="b" * 40)
    assert existing == {role: False for role in REQUIRED_IMAGE_ROLES}
    assert ("git", "merge-base", SOURCE, "b" * 40) in calls


@pytest.mark.parametrize("change,match", [
    ({"source_sha": "b" * 40}, "exact claim"),
    ({"claim_run_id": "124"}, "exact claim"),
    ({"image_uris": {}}, "exact claim"),
])
def test_transaction_identity_must_match_claim(change: dict, match: str) -> None:
    with pytest.raises(PrePromotionError, match=match):
        run_check(transaction() | change)


@pytest.mark.parametrize("condition,match", [
    ({"main": "b" * 40, "source_is_ancestor": False}, "not an ancestor"),
    ({"tag_exists": True}, "tag already exists"),
    ({"release_exists": True}, "Release already exists"),
    ({"registry_exists": (IMAGES[0],), "drift_role": "ui"}, "Unrecorded ui version tag differs"),
    ({"registry_exists": (IMAGES[3],), "drift_role": "openbao_didcomm"},
     "Unrecorded openbao_didcomm version tag differs"),
])
def test_fresh_claim_refuses_drift_or_owned_coordinate(condition: dict, match: str) -> None:
    with pytest.raises(PrePromotionError, match=match):
        run_check(transaction(), **condition)


def test_partial_resume_checks_recorded_and_unused_image_coordinates() -> None:
    existing, calls = run_check(transaction(promoted=["ui"]))
    assert existing == {role: role == "ui" for role in REQUIRED_IMAGE_ROLES}
    assert ("git", "rev-parse", "refs/remotes/origin/main^{commit}") in calls
    assert ("digest", IMAGES[0]) in calls
    assert [(call[1]) for call in calls if call[0] == "registry"] == list(IMAGES[1:])
    assert ("release",) in calls


def test_partial_resume_refuses_recorded_tag_drift() -> None:
    with pytest.raises(PrePromotionError, match="Recorded ui version tag differs"):
        run_check(transaction(promoted=["ui"]), drift_role="ui")


def test_partial_resume_refuses_unrecorded_tag_drift() -> None:
    with pytest.raises(PrePromotionError, match="Unrecorded services version tag differs"):
        run_check(transaction(promoted=["ui"]), registry_exists=(IMAGES[1],),
                  drift_role="services")


@pytest.mark.parametrize("promoted,state", [
    (["services"], "promoting"),
    (["ui"], "promoted"),
    (list(REQUIRED_IMAGE_ROLES), "promoting"),
])
def test_resume_requires_ordered_state(promoted: list[str], state: str) -> None:
    with pytest.raises(PrePromotionError, match="promotion (order|state)"):
        run_check(transaction(promoted=promoted, state=state))


def test_interrupted_first_promotion_adopts_only_exact_tag() -> None:
    existing, calls = run_check(transaction(), registry_exists=(IMAGES[0],))
    assert existing == {role: role == "ui" for role in REQUIRED_IMAGE_ROLES}
    assert ("digest", IMAGES[0]) in calls


def test_promoted_resume_keeps_exact_existing_source_and_release() -> None:
    existing, calls = run_check(
        transaction(promoted=list(REQUIRED_IMAGE_ROLES), state="promoted"),
        tag_exists=True, release_exists=True,
    )
    assert all(existing.values())
    assert [call for call in calls if call[0] == "digest"] == [
        ("digest", image) for image in IMAGES
    ]
    assert not any(call[0] in ("release", "registry") or call[1] == "ls-remote"
                   for call in calls)


def test_workflow_rechecks_immediately_before_each_public_write() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/cd.yml").read_text())
    steps = workflow["jobs"]["publish-manifest"]["steps"]
    login = next(index for index, step in enumerate(steps)
                 if str(step.get("uses", "")).startswith("docker/login-action@"))
    first_promotion = next(index for index, step in enumerate(steps)
                           if step.get("name", "").startswith("Promote the UI version tag"))
    assert login < first_promotion
    for name in ("Promote the UI", "Promote the services", "Promote the migrations",
                 "Promote the OpenBao DIDComm",
                 "Create or verify the late annotated source tag",
                 "Publish the qualified GitHub release"):
        step = next(step for step in steps if step.get("name", "").startswith(name))
        run = step["run"]
        assert run.index("scripts/check_stack_pre_promotion.py") < run.index(
            "docker buildx imagetools create" if name.startswith("Promote") else
            "git push origin" if name.startswith("Create") else "gh release create"
        )
        if name.startswith("Promote"):
            role = "openbao_didcomm" if name.startswith("Promote the OpenBao") else name.split()[2].lower()
            assert f".images.{role}.digest" in run
            assert run.index(f".images.{role}.digest") < run.index("docker buildx imagetools create")
    assert workflow["jobs"]["publish-manifest"]["env"]["SOURCE_SHA"] == (
        "${{ needs.resolve-transaction.outputs.source_sha }}"
    )
