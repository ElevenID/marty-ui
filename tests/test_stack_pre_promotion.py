"""The final release check runs immediately before public version tags."""

from __future__ import annotations

import hashlib
import json
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
                   ("sha256:" + character * 64 for character in "abcde"), strict=True))
RUN_ID = 456
LANES = ("oid4vci-issuer", "oid4vp-final", "oid4vp-url-query", "oid4vp-mdoc",
         "haip", "w3c-v2", "eudi")


def gate_bytes(review_main: str | None = None) -> bytes:
    value = {
        "schema": "marty.official-release-gate/v1", "source_sha": SOURCE,
        "harness_sha": "d" * 40, "manifest_sha256": "sha256:" + "e" * 64,
        "run_id": RUN_ID, "qualification_context": "PRE_PUBLICATION_CANDIDATE",
        "lanes": [{"lane": lane, "summary_sha256": "sha256:" + "f" * 64}
                  for lane in LANES],
    }
    if review_main is not None:
        value["review_disposition"] = {
            "schema": "marty.accepted-official-review/v1",
            "protected_main_commit": review_main,
            "record_sha256": "sha256:" + "1" * 64,
            "request_sha256": "sha256:" + "2" * 64,
            "evidence_run_attempt": 1,
            "reviewer": {"kind": "delegated_codex", "github_login": "reviewer"},
            "reviewed_cases": 1, "original_official_results_unchanged": True,
        }
    return json.dumps(value).encode()


def transaction(*, promoted: list[str] | None = None, state: str | None = None,
                review_main: str | None = None) -> dict[str, object]:
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
        "gates": {"official_interoperability": {
            "run_id": str(RUN_ID),
            "evidence_sha256": "sha256:" + hashlib.sha256(gate_bytes(review_main)).hexdigest(),
        }},
    }


def run_check(
    value: dict[str, object], *, main: str = SOURCE, source_is_ancestor: bool = True,
    tag_exists: bool = False,
    release_exists: bool = False, registry_exists: tuple[str, ...] = (),
    drift_role: str | None = None,
    review_main: str | None = None, gate_override: bytes | None = None,
    current_attempt: int = 1, history_invalid: bool = False,
    main_after_coordinates: str | None = None,
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

    def fake_main(_repository: str) -> str:
        calls.append(("main",))
        if main_after_coordinates is not None and sum(call == ("main",) for call in calls) > 1:
            return main_after_coordinates
        return main

    def fake_history(source, target, run_id, origin, reviewed, **kwargs) -> None:
        calls.append(("history", source, target, str(run_id), str(origin), str(reviewed)))
        if not source_is_ancestor or history_invalid:
            raise ValueError("unrelated or incomplete history")

    result = check(
        value, source_sha=SOURCE, claim_run_id="123", tag="v1.1.218",
        repository="ElevenID/marty-ui", git_command=fake_git,
        release_absent=fake_release, registry_absent=fake_registry,
        digest_lookup=fake_digest,
        token="test-token", actor="test-actor", images=IMAGES,
        official_gate=gate_bytes(review_main) if gate_override is None else gate_override,
        run_id=RUN_ID, current_attempt=current_attempt,
        main_lookup=fake_main, history_check=fake_history,
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


def test_only_the_exact_accepted_review_main_may_differ_from_source() -> None:
    with pytest.raises(PrePromotionError, match="changed after official qualification"):
        run_check(transaction(), main="b" * 40)
    reviewed = "b" * 40
    existing, calls = run_check(transaction(review_main=reviewed), main=reviewed,
                                review_main=reviewed)
    assert existing == {role: False for role in REQUIRED_IMAGE_ROLES}
    assert ("history", SOURCE, reviewed, str(RUN_ID), "1", "True") in calls


@pytest.mark.parametrize("change,match", [
    ({"source_sha": "b" * 40}, "exact claim"),
    ({"claim_run_id": "124"}, "exact claim"),
    ({"image_uris": {}}, "exact claim"),
])
def test_transaction_identity_must_match_claim(change: dict, match: str) -> None:
    with pytest.raises(PrePromotionError, match=match):
        run_check(transaction() | change)


@pytest.mark.parametrize("condition,match", [
    ({"source_is_ancestor": False}, "permitted review history"),
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
    assert not any(call[0] in ("release", "registry")
                   or (call[0] == "git" and call[1] == "ls-remote") for call in calls)


def test_changed_gate_or_later_attempt_cannot_use_qualified_transaction() -> None:
    for changes in ({"gate_override": gate_bytes() + b"\n"}, {"current_attempt": 2}):
        with pytest.raises(PrePromotionError, match="Official gate differs"):
            run_check(transaction(), **changes)


def test_unrelated_or_reverted_main_history_cannot_promote() -> None:
    reviewed = "b" * 40
    with pytest.raises(PrePromotionError, match="permitted review history"):
        run_check(transaction(review_main=reviewed), main=reviewed,
                  review_main=reviewed, history_invalid=True)


def test_authorization_is_rechecked_after_coordinate_reads() -> None:
    with pytest.raises(PrePromotionError, match="changed during"):
        run_check(transaction(), main_after_coordinates="b" * 40)


def test_workflow_rechecks_immediately_before_each_public_write() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/cd.yml").read_text())
    steps = workflow["jobs"]["publish-manifest"]["steps"]
    login = next(index for index, step in enumerate(steps)
                 if str(step.get("uses", "")).startswith("docker/login-action@"))
    first_promotion = next(index for index, step in enumerate(steps)
                           if step.get("name", "").startswith("Promote the UI version tag"))
    assert login < first_promotion
    for name in ("Promote the UI", "Promote the services", "Promote the migrations",
                 "Promote the OpenBao DIDComm", "Promote the Keycloak",
                 "Publish the qualified GitHub release"):
        step = next(step for step in steps if step.get("name", "").startswith(name))
        run = step["run"]
        assert step.get("env", {}).get("GH_TOKEN") == "${{ github.token }}"
        assert "--official-gate gates/official/official-interoperability.json" in run
        assert run.index("scripts/check_stack_pre_promotion.py") < run.index(
            "docker buildx imagetools create" if name.startswith("Promote") else
            "gh release create"
        )
        if name.startswith("Promote"):
            role = "openbao_didcomm" if name.startswith("Promote the OpenBao") else name.split()[2].lower()
            assert f".images.{role}.digest" in run
            assert run.index(f".images.{role}.digest") < run.index("docker buildx imagetools create")
    assert workflow["jobs"]["publish-manifest"]["env"]["SOURCE_SHA"] == (
        "${{ needs.resolve-transaction.outputs.source_sha }}"
    )
