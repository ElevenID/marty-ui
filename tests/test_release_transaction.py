from __future__ import annotations

import importlib.util
import json
from copy import deepcopy
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "release_transaction.py"
SPEC = importlib.util.spec_from_file_location("release_transaction", SCRIPT)
assert SPEC and SPEC.loader
transaction = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transaction)

SOURCE = "a" * 40
DIGESTS = {
    "ui": "sha256:" + "1" * 64,
    "services": "sha256:" + "2" * 64,
    "migrations": "sha256:" + "3" * 64,
}
IMAGES = {
    "ui": "ghcr.io/elevenid/marty-ui-oss/ui",
    "services": "ghcr.io/elevenid/marty-ui-oss/services",
    "migrations": "ghcr.io/elevenid/marty-ui-oss/migrations",
}
GATES = {
    "public_stack": {
        "run_id": "101",
        "evidence_sha256": "sha256:" + "4" * 64,
    },
    "verifier_differential": {
        "run_id": "102",
        "evidence_sha256": "sha256:" + "5" * 64,
    },
}


def write_lock(path: Path, **updates: object) -> Path:
    value: dict[str, object] = {
        "schema": transaction.STACK_LOCK_SCHEMA,
        "release": "marty-ui@1.2.3",
        "release_state": transaction.RELEASE_ELIGIBLE_STATE,
        "components": [],
    }
    value.update(updates)
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    return path


def claim(tmp_path: Path) -> dict[str, object]:
    lock = write_lock(tmp_path / "stack-lock.json")
    return transaction.create_claim(
        repository="ElevenID/marty-ui",
        tag="v1.2.3",
        source_sha=SOURCE,
        stack_lock=lock,
        claim_run_id="99",
        image_uris=IMAGES,
        tag_absent=True,
        release_absent=True,
        version_tags_absent={role: True for role in transaction.REQUIRED_IMAGE_ROLES},
    )


def digests_recorded(tmp_path: Path) -> dict[str, object]:
    return transaction.record_digests(claim(tmp_path), DIGESTS, build_run_id="100")


def qualified(tmp_path: Path) -> dict[str, object]:
    return transaction.qualify(digests_recorded(tmp_path), GATES)


def promoted(tmp_path: Path) -> dict[str, object]:
    value = qualified(tmp_path)
    for role in transaction.REQUIRED_IMAGE_ROLES:
        value = transaction.record_promotion(value, role=role, digest=DIGESTS[role])
    return value


def test_claim_is_deterministic_and_binds_all_absence_checks(tmp_path: Path) -> None:
    first = claim(tmp_path)
    second = claim(tmp_path)

    assert first == second
    assert first["state"] == "claimed"
    assert len(first["transaction_id"]) == 64
    assert first["preflight"] == {
        "git_tag_absent": True,
        "github_release_absent": True,
        "registry_version_tags_absent": {
            "ui": True,
            "services": True,
            "migrations": True,
        },
    }
    assert first["stack_lock_sha256"] == transaction.file_digest(
        tmp_path / "stack-lock.json"
    )


def test_resume_rebinds_repository_source_run_lock_and_state(tmp_path: Path) -> None:
    value = claim(tmp_path)
    lock = tmp_path / "stack-lock.json"
    assert (
        transaction.validate_resume(
            value,
            repository="ElevenID/marty-ui",
            source_sha=SOURCE,
            stack_lock=lock,
            claim_run_id="99",
            required_state="claimed",
        )
        == value
    )
    for updates in (
        {"repository": "ElevenID/other"},
        {"source_sha": "b" * 40},
        {"claim_run_id": "100"},
        {"required_state": "qualified"},
    ):
        arguments = {
            "repository": "ElevenID/marty-ui",
            "source_sha": SOURCE,
            "stack_lock": lock,
            "claim_run_id": "99",
            "required_state": "claimed",
            **updates,
        }
        with pytest.raises(transaction.ReleaseTransactionError, match="resume"):
            transaction.validate_resume(value, **arguments)

    lock.write_text(lock.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(transaction.ReleaseTransactionError, match="lock"):
        transaction.validate_resume(
            value,
            repository="ElevenID/marty-ui",
            source_sha=SOURCE,
            stack_lock=lock,
            claim_run_id="99",
        )


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"release_state": "hold"}, "release_state"),
        ({"release_state": "Eligible"}, "release_state"),
        ({"release": "marty-ui@1.2.4"}, "does not match"),
        ({"schema": "marty.stack-lock/v2"}, "schema"),
    ],
)
def test_claim_fails_closed_before_any_write(
    tmp_path: Path, updates: dict[str, object], message: str
) -> None:
    lock = write_lock(tmp_path / "stack-lock.json", **updates)
    with pytest.raises(transaction.ReleaseTransactionError, match=message):
        transaction.create_claim(
            repository="ElevenID/marty-ui",
            tag="v1.2.3",
            source_sha=SOURCE,
            stack_lock=lock,
            claim_run_id="99",
            image_uris=IMAGES,
            tag_absent=True,
            release_absent=True,
            version_tags_absent={
                role: True for role in transaction.REQUIRED_IMAGE_ROLES
            },
        )


@pytest.mark.parametrize(
    ("tag_absent", "release_absent", "version_absence", "message"),
    [
        (False, True, {"ui": True, "services": True, "migrations": True}, "tag"),
        (True, False, {"ui": True, "services": True, "migrations": True}, "release"),
        (True, True, {"ui": True, "services": False, "migrations": True}, "registry"),
    ],
)
def test_claim_requires_every_exact_coordinate_absence(
    tmp_path: Path,
    tag_absent: bool,
    release_absent: bool,
    version_absence: dict[str, bool],
    message: str,
) -> None:
    lock = write_lock(tmp_path / "stack-lock.json")
    with pytest.raises(transaction.ReleaseTransactionError, match=message):
        transaction.create_claim(
            repository="ElevenID/marty-ui",
            tag="v1.2.3",
            source_sha=SOURCE,
            stack_lock=lock,
            claim_run_id="99",
            image_uris=IMAGES,
            tag_absent=tag_absent,
            release_absent=release_absent,
            version_tags_absent=version_absence,
        )


def test_digest_qualification_promotion_and_publication_are_ordered(
    tmp_path: Path,
) -> None:
    value = claim(tmp_path)
    with pytest.raises(transaction.ReleaseTransactionError, match="qualified"):
        transaction.qualify(value, GATES)

    value = transaction.record_digests(value, DIGESTS, build_run_id="100")
    assert value["state"] == "digests_recorded"
    with pytest.raises(transaction.ReleaseTransactionError, match="promoted"):
        transaction.publish(
            value,
            release_id="R_1",
            manifest_sha256="sha256:" + "6" * 64,
            publication_run_id="103",
        )

    value = transaction.qualify(value, GATES)
    assert value["state"] == "qualified"
    for index, role in enumerate(transaction.REQUIRED_IMAGE_ROLES, start=1):
        value = transaction.record_promotion(value, role=role, digest=DIGESTS[role])
        assert value["state"] == (
            "promoted"
            if index == len(transaction.REQUIRED_IMAGE_ROLES)
            else "promoting"
        )

    value = transaction.publish(
        value,
        release_id="R_1",
        manifest_sha256="sha256:" + "6" * 64,
        publication_run_id="103",
    )
    assert value["state"] == "published"
    assert value["publication"]["manifest_sha256"] == "sha256:" + "6" * 64


def test_every_successful_transition_is_an_exact_idempotent_retry(
    tmp_path: Path,
) -> None:
    initial = claim(tmp_path)
    recorded = transaction.record_digests(initial, DIGESTS, build_run_id="100")
    assert transaction.record_digests(recorded, DIGESTS, build_run_id="100") == recorded

    ready = transaction.qualify(recorded, GATES)
    assert transaction.qualify(ready, GATES) == ready

    partial = transaction.record_promotion(ready, role="ui", digest=DIGESTS["ui"])
    assert (
        transaction.record_promotion(partial, role="ui", digest=DIGESTS["ui"])
        == partial
    )

    complete = promoted(tmp_path)
    published = transaction.publish(
        complete,
        release_id="R_1",
        manifest_sha256="sha256:" + "6" * 64,
        publication_run_id="103",
    )
    assert (
        transaction.publish(
            published,
            release_id="R_1",
            manifest_sha256="sha256:" + "6" * 64,
            publication_run_id="103",
        )
        == published
    )


def test_conflicting_retry_never_rebinds_recorded_evidence(tmp_path: Path) -> None:
    value = digests_recorded(tmp_path)
    different = {**DIGESTS, "services": "sha256:" + "9" * 64}
    with pytest.raises(transaction.ReleaseTransactionError, match="conflict"):
        transaction.record_digests(value, different, build_run_id="100")
    assert transaction.record_digests(value, DIGESTS, build_run_id="999") == value

    value = qualified(tmp_path)
    different_gates = deepcopy(GATES)
    different_gates["public_stack"]["run_id"] = "999"
    with pytest.raises(transaction.ReleaseTransactionError, match="conflict"):
        transaction.qualify(value, different_gates)
    with pytest.raises(transaction.ReleaseTransactionError, match="conflict"):
        transaction.record_promotion(
            value, role="services", digest="sha256:" + "9" * 64
        )


@pytest.mark.parametrize(
    "checkpoint",
    ["claimed", "digests_recorded", "qualified", "promoting", "promoted"],
)
def test_cancellation_checkpoints_can_be_tombstoned_but_not_reused(
    tmp_path: Path, checkpoint: str
) -> None:
    states: dict[str, dict[str, object]] = {"claimed": claim(tmp_path)}
    states["digests_recorded"] = transaction.record_digests(
        states["claimed"], DIGESTS, build_run_id="100"
    )
    states["qualified"] = transaction.qualify(states["digests_recorded"], GATES)
    states["promoting"] = transaction.record_promotion(
        states["qualified"], role="ui", digest=DIGESTS["ui"]
    )
    states["promoted"] = promoted(tmp_path)

    dead = transaction.tombstone(
        states[checkpoint],
        reason="safe exact-source completion is no longer possible",
        evidence_sha256="sha256:" + "7" * 64,
    )
    assert dead["state"] == "tombstoned"
    assert (
        transaction.tombstone(
            dead,
            reason="safe exact-source completion is no longer possible",
            evidence_sha256="sha256:" + "7" * 64,
        )
        == dead
    )
    with pytest.raises(transaction.ReleaseTransactionError):
        transaction.record_digests(dead, DIGESTS, build_run_id="100")


def test_published_terminal_state_cannot_be_tombstoned(tmp_path: Path) -> None:
    value = transaction.publish(
        promoted(tmp_path),
        release_id="R_1",
        manifest_sha256="sha256:" + "6" * 64,
        publication_run_id="103",
    )
    with pytest.raises(transaction.ReleaseTransactionError, match="published"):
        transaction.tombstone(
            value,
            reason="must not rewrite publication",
            evidence_sha256="sha256:" + "7" * 64,
        )


@pytest.mark.parametrize(
    ("path", "replacement", "message"),
    [
        (("source_sha",), "b" * 40, "identity"),
        (("preflight", "git_tag_absent"), False, "preflight"),
        (("state",), "published", "publication"),
        (("image_uris", "services"), "ghcr.io/other/services", "URI"),
    ],
)
def test_claim_validation_rejects_tampering(
    tmp_path: Path, path: tuple[str, ...], replacement: object, message: str
) -> None:
    value = claim(tmp_path)
    target: dict[str, object] = value
    for key in path[:-1]:
        target = target[key]  # type: ignore[assignment]
    target[path[-1]] = replacement
    with pytest.raises(transaction.ReleaseTransactionError, match=message):
        transaction.validate_claim(value)
