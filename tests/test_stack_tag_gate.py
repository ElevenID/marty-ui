from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "stack_tag_gate.py"
SPEC = importlib.util.spec_from_file_location("stack_tag_gate", SCRIPT)
assert SPEC and SPEC.loader
stack_tag_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stack_tag_gate)

COMMIT = "a" * 40
TAG_OBJECT = "b" * 40
MISSING = object()
POLICY = {
    "schema": stack_tag_gate.SCHEMA,
    "required_workflows": [
        {"path": ".github/workflows/ci.yml", "event": "merge_group"},
        {"path": ".github/workflows/codeql-rust.yml", "event": "merge_group"},
        {"path": ".github/workflows/codeql-actions.yml", "event": "merge_group"},
    ],
}


def write_stack_lock(
    repository: Path,
    *,
    release_state: object = stack_tag_gate.RELEASE_ELIGIBLE_STATE,
    release: str = "marty-ui@1.2.3",
    schema: object = stack_tag_gate.STACK_LOCK_SCHEMA,
) -> None:
    document: dict[str, object] = {"release": release}
    if schema is not MISSING:
        document["schema"] = schema
    if release_state is not MISSING:
        document["release_state"] = release_state
    release_directory = repository / "release"
    release_directory.mkdir()
    (release_directory / "stack-lock.json").write_text(
        json.dumps(document), encoding="utf-8"
    )


def run(run_id: int, path: str, event: str, **updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "id": run_id,
        "path": path,
        "event": event,
        "status": "completed",
        "conclusion": "success",
        "head_sha": COMMIT,
    }
    value.update(updates)
    return value


def payload() -> dict[str, object]:
    return {
        "workflow_runs": [
            run(10, ".github/workflows/ci.yml", "merge_group"),
            run(11, ".github/workflows/codeql-rust.yml", "merge_group"),
            run(12, ".github/workflows/codeql-actions.yml", "merge_group"),
        ]
    }


def test_exact_head_terminal_workflows_pass() -> None:
    accepted = stack_tag_gate.validate_workflow_runs(payload(), POLICY, COMMIT, 99)
    assert [item["run_id"] for item in accepted] == [10, 11, 12]


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"status": "in_progress", "conclusion": None}, "pending"),
        ({"conclusion": "failure"}, "did not succeed"),
        ({"head_sha": "c" * 40}, "missing"),
    ],
)
def test_pending_failing_or_different_head_workflow_blocks(
    updates: dict[str, object], message: str
) -> None:
    document = payload()
    workflow_runs = document["workflow_runs"]
    assert isinstance(workflow_runs, list)
    workflow_runs[0].update(updates)
    with pytest.raises(stack_tag_gate.StackTagGateError, match=message):
        stack_tag_gate.validate_workflow_runs(document, POLICY, COMMIT, 99)


def test_source_requires_exact_main_and_matching_stack_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_stack_lock(tmp_path)
    monkeypatch.setattr(stack_tag_gate, "_git", lambda *_args: COMMIT)

    stack_tag_gate.validate_source(tmp_path, "v1.2.3", COMMIT)
    with pytest.raises(stack_tag_gate.StackTagGateError, match="does not match"):
        stack_tag_gate.validate_source(tmp_path, "v1.2.4", COMMIT)


@pytest.mark.parametrize(
    "release_state",
    [MISSING, None, False, True, 0, "", "hold", "Eligible", " eligible ", [], {}],
    ids=[
        "missing",
        "null",
        "false",
        "true",
        "zero",
        "empty",
        "hold",
        "wrong-case",
        "whitespace",
        "array",
        "object",
    ],
)
def test_source_fails_closed_without_exact_release_eligibility(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    release_state: object,
) -> None:
    write_stack_lock(tmp_path, release_state=release_state)
    monkeypatch.setattr(stack_tag_gate, "_git", lambda *_args: COMMIT)

    with pytest.raises(
        stack_tag_gate.StackTagGateError,
        match="release_state must be exactly 'eligible'",
    ):
        stack_tag_gate.validate_source(tmp_path, "v1.2.3", COMMIT)


@pytest.mark.parametrize("schema", [MISSING, None, "marty.stack-lock/v2"])
def test_source_rejects_missing_or_invalid_stack_lock_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    schema: object,
) -> None:
    write_stack_lock(tmp_path, schema=schema)
    monkeypatch.setattr(stack_tag_gate, "_git", lambda *_args: COMMIT)

    with pytest.raises(stack_tag_gate.StackTagGateError, match="schema is invalid"):
        stack_tag_gate.validate_source(tmp_path, "v1.2.3", COMMIT)


def release_evidence() -> dict[str, object]:
    return {
        "schema": stack_tag_gate.SCHEMA,
        "repository": "ElevenID/marty-ui",
        "tag": "v1.2.3",
        "source_sha": COMMIT,
        "preparation_run_id": 42,
        "required_workflows": [{"path": "ci", "run_id": 10}],
        "tag_object_sha": TAG_OBJECT,
        "peeled_source_sha": COMMIT,
    }


def preparation_run() -> dict[str, object]:
    return {
        "id": 42,
        "path": stack_tag_gate.PREPARATION_WORKFLOW,
        "event": "workflow_dispatch",
        "head_sha": COMMIT,
        "head_branch": "main",
        "status": "completed",
        "conclusion": "success",
    }


def tag_message() -> str:
    return (
        "Release 1.2.3\n\n"
        f"Stack-Tag-Gate: {stack_tag_gate.SCHEMA}\n"
        "Preparation-Run: 42\n"
        f"Source-SHA: {COMMIT}\n"
    )


def test_exact_annotated_release_proof_passes(tmp_path: Path) -> None:
    write_stack_lock(tmp_path)
    stack_tag_gate.validate_release_proof(
        tmp_path,
        "ElevenID/marty-ui",
        "v1.2.3",
        COMMIT,
        "tag",
        TAG_OBJECT,
        tag_message(),
        preparation_run(),
        release_evidence(),
    )


@pytest.mark.parametrize(
    ("tag_type", "message", "run_updates"),
    [
        ("commit", "annotated", {}),
        ("tag", "exact successful main", {"head_branch": "topic"}),
        ("tag", "exact successful main", {"conclusion": "failure"}),
    ],
)
def test_invalid_tag_or_preparation_run_is_rejected(
    tmp_path: Path,
    tag_type: str,
    message: str,
    run_updates: dict[str, object],
) -> None:
    write_stack_lock(tmp_path)
    run_document = preparation_run()
    run_document.update(run_updates)
    with pytest.raises(stack_tag_gate.StackTagGateError, match=message):
        stack_tag_gate.validate_release_proof(
            tmp_path,
            "ElevenID/marty-ui",
            "v1.2.3",
            COMMIT,
            tag_type,
            TAG_OBJECT,
            tag_message(),
            run_document,
            release_evidence(),
        )


@pytest.mark.parametrize(
    "release_state",
    [MISSING, None, False, True, 0, "", "hold", "Eligible", " eligible ", [], {}],
    ids=[
        "missing",
        "null",
        "false",
        "true",
        "zero",
        "empty",
        "hold",
        "wrong-case",
        "whitespace",
        "array",
        "object",
    ],
)
def test_release_proof_fails_closed_without_exact_release_eligibility(
    tmp_path: Path, release_state: object
) -> None:
    write_stack_lock(tmp_path, release_state=release_state)

    with pytest.raises(
        stack_tag_gate.StackTagGateError,
        match="release_state must be exactly 'eligible'",
    ):
        stack_tag_gate.validate_release_proof(
            tmp_path,
            "ElevenID/marty-ui",
            "v1.2.3",
            COMMIT,
            "tag",
            TAG_OBJECT,
            tag_message(),
            preparation_run(),
            release_evidence(),
        )


def test_cli_rejects_malformed_tag_without_creating_a_ref(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "prepare",
            "--repository",
            str(tmp_path),
            "--repository-name",
            "ElevenID/marty-ui",
            "--tag",
            "v1.2",
            "--commit",
            COMMIT,
            "--run-id",
            "99",
            "--runs-json",
            str(tmp_path / "missing-runs.json"),
            "--policy",
            str(tmp_path / "missing-policy.json"),
            "--evidence",
            str(tmp_path / "evidence.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "invalid stable tag" in result.stderr
