"""Keep v2 retry out of original qualification and retain v1/downstream gates."""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


def test_candidate_is_sealed_after_admission_and_original_cd_stays_first_attempt():
    workflow = load("cd.yml")
    inputs = workflow[True]["workflow_dispatch"]["inputs"]
    # Landing the implementation must not switch ordinary dispatches to an
    # unqualified publisher. The first live v2 use is an explicit rollout.
    assert inputs["publication_contract"]["default"] == "v1"
    assert inputs["publication_contract"]["options"] == ["v1", "v2"]
    jobs = workflow["jobs"]
    early = jobs["resolve-transaction"]["steps"][0]["run"]
    assert 'test "$GITHUB_RUN_ATTEMPT" = 1' in early
    assert 'PUBLICATION_CONTRACT' in early and 'PUBLISH_CLOUDFLARE_ADDON' in early
    steps = jobs["publish-manifest"]["steps"]
    names = [step.get("name", "") for step in steps]
    assert names.index("Wait for the exact operator tag handoff") < names.index("Seal the immutable v2 publication candidate")
    sealed = next(step for step in steps if step.get("name") == "Seal the immutable v2 publication candidate")
    assert sealed["if"] == "inputs.publication_contract == 'v2'"
    assert '--tag-admission "$RUNNER_TEMP/stable-tag-handoff.json"' in sealed["run"]
    for step in steps:
        if step.get("name") in {"Require the release coordinate to remain absent",
            "Publish the qualified GitHub release and exact assets", "Seal the published terminal transaction",
            "Record required stable installer qualification"} or step.get("with", {}).get("name", "").startswith("stack-release-published-"):
            assert step["if"] == "inputs.publication_contract == 'v1'"
    assert "inputs.publication_contract == 'v1'" in jobs["publish-cloudflare-addon"]["if"]


def test_new_publisher_uses_trusted_default_source_and_readonly_intake():
    workflow = load("publish-stable-candidate.yml")
    assert set(workflow[True]) == {"workflow_dispatch"}
    trigger = workflow[True]["workflow_dispatch"]["inputs"]
    assert set(trigger) == {"candidate_run_id"}
    assert trigger["candidate_run_id"]["required"] is True
    assert trigger["candidate_run_id"]["type"] == "string"
    jobs = workflow["jobs"]
    assert jobs["intake"]["if"] == "github.event_name == 'workflow_dispatch'"
    assert jobs["intake"]["permissions"] == {"actions": "read", "contents": "read"}
    assert jobs["publish"]["needs"] == "intake"
    assert jobs["publish"]["if"] == "needs.intake.outputs.eligible == 'true'"
    assert jobs["publish"]["environment"] == "stack-release"
    old_group = load("cd.yml")["jobs"]["publish-manifest"]["concurrency"]
    new_group = jobs["publish"]["concurrency"]
    assert old_group["group"].startswith("stable-release-coordinate-")
    assert new_group["group"].startswith("stable-release-coordinate-")
    assert old_group["cancel-in-progress"] is new_group["cancel-in-progress"] is False
    for job in jobs.values():
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r".+@[a-f0-9]{40}", step["uses"])
                if step["uses"].startswith("actions/checkout@"):
                    assert step["with"]["ref"] == "${{ github.sha }}"
                    assert step["with"]["persist-credentials"] is False
            assert "github.event.workflow_run.head_sha" not in step.get("run", "")
    run = next(step["run"] for step in jobs["publish"]["steps"] if "stable_publication.py" in step.get("run", ""))
    assert '--work "$RUNNER_TEMP/stable-candidate"' in run
    assert "--gh" in run and "--cosign" in run


def test_legacy_checkpoint_verification_and_installer_gates_are_retained():
    raw = (ROOT / ".github/workflows/cd.yml").read_text()
    assert raw.count("scripts/stable_publication_checkpoint.py verify") == 2
    assert 'test "$GITHUB_RUN_ATTEMPT" = 1' in raw
    assert "prepare-official-candidate, prepare-installer-inputs" in raw
    assert "staged installed-journey acceptance" in raw
    assert "resume is not supported" in raw
