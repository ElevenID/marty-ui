#!/usr/bin/env python3
"""Reserve one annotated tag through an exact bounded operator workflow.

The default inspect mode is read-only. Production ref creation requires the
original CD attempt to be waiting on an authenticated, byte-exact checkpoint.
No mode changes main, overwrites a tag, retries an ambiguous mutation, signs a
candidate payload, or publishes a release. Tag creation is conditioned only on
tag absence; independent main observations are not an atomic main assertion.
"""
from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

if __package__:
    from . import release_tag_handoff as handoff
    from . import release_git_atomic as atomic
    from .release_review_main import gate_authority, require_review_only_history
    from .release_transaction import IMAGE_URIS, validate_resume
else:
    import release_tag_handoff as handoff
    import release_git_atomic as atomic
    from release_review_main import gate_authority, require_review_only_history
    from release_transaction import IMAGE_URIS, validate_resume

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = handoff.REPOSITORY
MANDATORY_PUBLISH_STEPS = frozenset({
    "Revalidate exact installer inputs before any publication signing",
    "Verify exact operator binary provenance before signing",
    "Export and verify offline stable installer proofs",
    "Seal all signed publication bytes for the bounded tag handoff",
    "Preserve the exact publication checkpoint before the tag wait",
})
MANDATORY_JOBS = frozenset({
    "resolve-transaction", "validate-stack", "record-digests", "prepare-official-candidate",
    "official-gate-evidence", "qualify-release", "prepare-selfhost-image-lock",
    "preflight-selfhost-prepared-consumer", "prepare-installer-inputs",
})
REUSABLE_PREFLIGHT_JOB = "release-environment-preflight / validate"
LANES = frozenset({"oid4vci-issuer", "oid4vp-final", "oid4vp-url-query", "oid4vp-mdoc", "haip", "w3c-v2", "eudi"})
REFUSAL_STAGES = frozenset({
    "initialization", "repository_inspection", "mode_validation", "capability_protection",
    "capability_ancestor", "capability_tag_absence", "capability_tag_object",
    "capability_intent_object", "capability_intent_reservation", "capability_intent_readback",
    "capability_negative", "capability_negative_readback", "capability_before_positive",
    "capability_positive", "capability_positive_readback", "capability_final_inspection",
    "qualified_tag", "observation_finalization",
})
CAPABILITY_REFUSALS = frozenset({"capability_rulesets_unavailable", "capability_current_credential_not_protected"})


class OperatorRefusal(handoff.HandoffError):
    """A fixed internal reason code, never an API response or exception message."""

    def __init__(self, reason: str) -> None:
        handoff.require(reason in CAPABILITY_REFUSALS, "Invalid internal operator reason")
        super().__init__(reason)
        self.reason = reason


class RefusalDiagnostics:
    def __init__(self) -> None:
        self.stage = "initialization"

    def enter(self, stage: str) -> None:
        handoff.require(stage in REFUSAL_STAGES, "Invalid internal operator stage")
        self.stage = stage


def refusal_reason(error: BaseException) -> str:
    # Do not serialize str(error), arguments, API values, URLs, or subprocess output.
    if isinstance(error, OperatorRefusal) and error.reason in CAPABILITY_REFUSALS:
        return error.reason
    if isinstance(error, handoff.HandoffError):
        return "handoff_validation_refused"
    if isinstance(error, atomic.AtomicGitError):
        return "atomic_git_validation_refused"
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return "transport_timeout"
    if isinstance(error, subprocess.SubprocessError):
        return "subprocess_failed"
    if isinstance(error, OSError):
        return "local_io_failed"
    return "invalid_operator_state"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ObservationJournal:
    """Exclusive private audit identity; fsync the consumed intent before I/O."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.descriptor = -1
        try:
            parent = os.fstat(self.directory)
            handoff.require(parent.st_uid == os.geteuid() and not parent.st_mode & 0o022,
                            "Operator audit directory is not exclusively writable by its owner")
            self.descriptor = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                      0o600, dir_fd=self.directory)
            self.identity = self.fingerprint(os.fstat(self.descriptor))
            self.parent_identity = (parent.st_dev, parent.st_ino, parent.st_uid, parent.st_gid, parent.st_mode)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def fingerprint(value: os.stat_result) -> tuple:
        handoff.require(stat.S_ISREG(value.st_mode) and value.st_uid == os.geteuid()
                        and stat.S_IMODE(value.st_mode) == 0o600 and value.st_nlink == 1,
                        "Operator audit custody changed")
        return (value.st_dev, value.st_ino, value.st_size, value.st_uid, value.st_gid,
                value.st_mode, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)

    def unchanged(self) -> None:
        parent = os.stat(self.path.parent, follow_symlinks=False)
        handoff.require((parent.st_dev, parent.st_ino, parent.st_uid, parent.st_gid, parent.st_mode)
                        == self.parent_identity, "Operator audit parent changed")
        handoff.require(self.fingerprint(os.fstat(self.descriptor)) == self.identity
                        and self.fingerprint(os.stat(self.path.name, dir_fd=self.directory, follow_symlinks=False))
                        == self.identity, "Operator audit path changed")

    def write(self, value: dict) -> None:
        raw = handoff.encoded(value)
        handoff.require(len(raw) <= handoff.MAX_JSON, "Operator observation exceeds its bound")
        token = os.environ.get("GH_TOKEN", "")
        handoff.require(not token or token.encode() not in raw, "Operator observation failed credential redaction")
        self.unchanged()
        descriptor, temporary = tempfile.mkstemp(prefix=".tag-operator-audit-", dir=self.path.parent)
        try:
            os.fchmod(descriptor, 0o600)
            remaining = memoryview(raw)
            while remaining:
                written = os.write(descriptor, remaining)
                handoff.require(written > 0, "Operator audit write failed")
                remaining = remaining[written:]
            os.fsync(descriptor)
            self.unchanged()
            temporary_name = Path(temporary).name
            handoff.require(self.fingerprint(os.fstat(descriptor))
                            == self.fingerprint(os.stat(temporary_name, dir_fd=self.directory, follow_symlinks=False)),
                            "Operator audit temporary changed")
            os.replace(temporary_name, self.path.name, src_dir_fd=self.directory, dst_dir_fd=self.directory)
            os.fsync(self.directory)
            os.close(self.descriptor)
            self.descriptor = descriptor
            descriptor = -1
            self.identity = self.fingerprint(os.fstat(self.descriptor))
            self.unchanged()
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if os.path.lexists(temporary):
                os.unlink(temporary)

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1
        os.close(self.directory)


def transaction_summary(value: dict) -> dict:
    return {"transport": value["transport"], "request": value["request"],
            "not_after": value["not_after"],
            "discovery": value["discovery"]["admitted"],
            "mutation": {key: value["mutation"][key] for key in
                         ("method", "path", "requested_at", "body_sha256", "body_bytes", "outcome", "report")},
            "decision": value["decision"]}


def inspect_repository(github: handoff.GitHub) -> tuple[int, str, dict]:
    operator_run, source = handoff.exact_context(handoff.OPERATOR_WORKFLOW)
    repository = github.json(f"repos/{REPOSITORY}")
    handoff.require(isinstance(repository, dict) and repository.get("id") == handoff.REPOSITORY_ID
                    and repository.get("node_id") == handoff.REPOSITORY_NODE
                    and repository.get("full_name") == REPOSITORY,
                    "Operator repository identity differs")
    main = github.main()["commit"]["sha"]
    handoff.require(source == main and handoff.git("rev-parse", "HEAD^{commit}", deadline=github.deadline) == source,
                    "Operator checkout is not the dispatched current protected main")
    run = github.run(operator_run, handoff.OPERATOR_WORKFLOW, source)
    handoff.require(run.get("status") == "in_progress", "Operator invocation is no longer running")
    rules = github.array_pages(f"repos/{REPOSITORY}/rulesets?includes_parents=true")
    handoff.require(isinstance(rules, list) and all(isinstance(item, dict) for item in rules),
                    "Repository ruleset listing is unavailable")
    # Inspect every listed active ruleset by authenticated immutable identity.
    details = []
    for item in rules:
        handoff.require(handoff.positive(item.get("id")), "Ruleset ID is malformed")
        value = github.json(f"repos/{REPOSITORY}/rulesets/{item['id']}")
        handoff.require(isinstance(value, dict) and value.get("id") == item["id"],
                        "Ruleset identity changed")
        details.append(value)
    return operator_run, source, {"repository_id": repository["id"], "repository_node_id": repository["node_id"],
                                  "rulesets": sorted(details, key=lambda value: value["id"]),
                                  "rulesets_sha256": handoff.sha256(handoff.encoded(sorted(details, key=lambda value: value["id"])))}


def validate_finished_reusable_preflight(job: dict, publisher: dict) -> None:
    """Require terminal evidence for the named reusable job's stale API status."""
    handoff.require(job.get("name") == REUSABLE_PREFLIGHT_JOB
                    and job.get("status") == "in_progress" and job.get("conclusion") == "success",
                    "Reusable preflight lacks terminal success")
    publisher_steps = publisher.get("steps")
    handoff.require(isinstance(publisher_steps, list)
                    and all(isinstance(step, dict) for step in publisher_steps),
                    "Publisher steps are unavailable")
    waiting = [step for step in publisher_steps if step.get("name") == handoff.WAIT_STEP]
    handoff.require(len(waiting) == 1 and waiting[0].get("status") == "in_progress"
                    and waiting[0].get("conclusion") is None,
                    "Publisher is not at the unique bounded tag wait")
    started = handoff.timestamp(job.get("started_at"))
    completed = handoff.timestamp(job.get("completed_at"))
    wait_started = handoff.timestamp(waiting[0].get("started_at"))
    handoff.require(started <= completed <= wait_started,
                    "Reusable preflight completion is outside the original tag wait")

    steps = job.get("steps")
    handoff.require(isinstance(steps, list) and bool(steps)
                    and all(isinstance(step, dict) and step.get("status") == "completed"
                            and step.get("conclusion") == "success" for step in steps),
                    "Reusable preflight steps have not all succeeded")
    numbers = [step.get("number") for step in steps]
    handoff.require(all(handoff.positive(number) for number in numbers)
                    and len(set(numbers)) == len(numbers),
                    "Reusable preflight step numbering is ambiguous")
    protection = [step for step in steps
                  if step.get("name") == "Require protected and complete release environment"]
    completion = [step for step in steps if step.get("name") == "Complete job"]
    handoff.require(len(protection) == 1 and len(completion) == 1
                    and completion[0]["number"] == max(numbers),
                    "Reusable preflight protection or final completion evidence differs")
    previous_completed = started
    for step in sorted(steps, key=lambda item: item["number"]):
        step_started = handoff.timestamp(step.get("started_at"))
        step_completed = handoff.timestamp(step.get("completed_at"))
        handoff.require(previous_completed <= step_started <= step_completed <= completed,
                        "Reusable preflight step timestamps are inconsistent")
        previous_completed = step_completed


def validate_waiting_jobs(jobs: list[dict], run_id: int, source: str) -> None:
    handoff.require(jobs and all(handoff.positive(job.get("id")) for job in jobs)
                    and len({job["id"] for job in jobs}) == len(jobs), "CD job listing is ambiguous")
    for job in jobs:
        handoff.require(handoff.positive(job.get("run_id")) and job["run_id"] == run_id
                        and type(job.get("run_attempt")) is int and job["run_attempt"] == 1
                        and job.get("head_sha") == source, "CD job belongs to another invocation")
    names = [job.get("name") for job in jobs]
    handoff.require(MANDATORY_JOBS <= set(names), "CD transitive prerequisite jobs are missing")
    handoff.require(names.count(REUSABLE_PREFLIGHT_JOB) == 1,
                    "Exactly one release environment preflight is required")
    official = {name.removeprefix("Collect seven official candidate lanes / ") for name in names
                if isinstance(name, str) and name.startswith("Collect seven official candidate lanes / ")}
    handoff.require(official == LANES, "The complete seven official collection jobs are required")
    publishers = [job for job in jobs if job.get("name") == "publish-manifest"]
    handoff.require(len(publishers) == 1, "Exactly one original publisher is required")
    publisher = publishers[0]
    handoff.require(publisher.get("status") == "in_progress" and publisher.get("conclusion") is None,
                    "Original publisher is not running")
    for job in jobs:
        if job is publisher:
            continue
        if job.get("name") == "publish-cloudflare-addon":
            # This one optional downstream job depends on publication. Requiring
            # it to finish first would deadlock the genuine source workflow.
            handoff.require((job.get("status") == "completed" and job.get("conclusion") == "skipped")
                            or (job.get("status") in {"queued", "waiting", "pending"}
                                and job.get("conclusion") is None),
                            "Unexpected downstream Cloudflare execution before publication")
            continue
        if job.get("name") == REUSABLE_PREFLIGHT_JOB and job.get("status") == "in_progress":
            validate_finished_reusable_preflight(job, publisher)
            continue
        handoff.require(job.get("status") == "completed" and job.get("conclusion") == "success",
                        "An independent or transitive release prerequisite has not succeeded")
    steps = publisher.get("steps")
    handoff.require(isinstance(steps, list) and all(isinstance(step, dict) for step in steps),
                    "Publisher steps are unavailable")
    waiting = [step for step in steps if step.get("name") == handoff.WAIT_STEP]
    handoff.require(len(waiting) == 1 and waiting[0].get("status") == "in_progress"
                    and waiting[0].get("conclusion") is None, "Publisher is not at the unique bounded tag wait")
    number = waiting[0].get("number")
    handoff.require(handoff.positive(number), "Tag wait step identity is invalid")
    handoff.require(len({step.get("number") for step in steps}) == len(steps)
                    and all(handoff.positive(step.get("number")) for step in steps),
                    "Publisher step numbering is ambiguous")
    before = [step for step in steps if step["number"] < number]
    handoff.require(MANDATORY_PUBLISH_STEPS <= {step.get("name") for step in before}
                    and all(step.get("status") == "completed" and step.get("conclusion") == "success"
                            for step in before), "Publication signing or checkpoint preparation has not succeeded")
    handoff.require(all(step.get("conclusion") is None and step.get("status") in {"queued", "pending"}
                        for step in steps if step["number"] > number),
                    "A later publication step already executed")


def waiting_run(github: handoff.GitHub, run_id: int, source: str) -> None:
    run = github.run(run_id, handoff.CD_WORKFLOW, source)
    handoff.require(run.get("status") == "in_progress" and run.get("conclusion") is None,
                    "Original CD attempt is no longer running")
    jobs = github.pages(f"repos/{REPOSITORY}/actions/runs/{run_id}/attempts/1/jobs", "jobs")
    validate_waiting_jobs(jobs, run_id, source)


def create_tag_object(github: handoff.GitHub, tag: str, source: str, message: str) -> dict:
    status, raw = github.response(f"repos/{REPOSITORY}/git/tags", method="POST", payload={
        "tag": tag, "message": message, "object": source, "type": "commit",
        "tagger": {"name": "github-actions[bot]", "email": "41898282+github-actions[bot]@users.noreply.github.com",
                   "date": utc_now()},
    })
    handoff.require(status == 201, "Annotated tag-object creation failed; no reference fallback is allowed")
    value = handoff.decode(raw)
    handoff.require(isinstance(value, dict) and handoff.SHA.fullmatch(value.get("sha", "")) is not None
                    and value.get("tag") == tag and value.get("message", "").rstrip("\n") == message.rstrip("\n")
                    and value.get("object", {}).get("type") == "commit"
                    and value.get("object", {}).get("sha") == source,
                    "Created tag object differs from its exact request")
    return value


def read_exact_tag(github: handoff.GitHub, tag: str, object_sha: str, source: str, message: str) -> dict:
    ref = github.json(f"repos/{REPOSITORY}/git/ref/tags/{tag}")
    handoff.require(isinstance(ref, dict) and ref.get("ref") == f"refs/tags/{tag}"
                    and ref.get("object", {}).get("type") == "tag"
                    and ref.get("object", {}).get("sha") == object_sha, "Created tag ref differs")
    value = github.json(f"repos/{REPOSITORY}/git/tags/{object_sha}")
    handoff.require(isinstance(value, dict) and value.get("sha") == object_sha and value.get("tag") == tag
                    and value.get("object", {}).get("type") == "commit"
                    and value.get("object", {}).get("sha") == source
                    and value.get("message", "").rstrip("\n") == message.rstrip("\n"),
                    "Created annotated tag does not peel to the exact source")
    return value


def require_capability_main_protection(inspection: dict) -> list[dict]:
    # Bind the experiment to the CURRENT credential's explicit bypass capability.
    # GitHub hides bypass_actors without ruleset write access. Missing is unknown,
    # not an empty global actor inventory; retain the raw snapshot unchanged.
    # Do not infer a pull-request ruleset from GH013: classic protection can own it.
    rulesets = inspection.get("rulesets")
    if not isinstance(rulesets, list):
        raise OperatorRefusal("capability_rulesets_unavailable")
    protecting = []
    for value in rulesets:
        if not (isinstance(value, dict) and handoff.positive(value.get("id"))
                and value.get("target") == "branch" and value.get("enforcement") == "active"
                and value.get("source_type") == "Repository" and value.get("source") == REPOSITORY
                and value.get("conditions") == {"ref_name": {"include": ["refs/heads/main"], "exclude": []}}
                and value.get("current_user_can_bypass") == "never"
                and isinstance(value.get("rules"), list)
                and any(isinstance(rule, dict) and rule.get("type") == "merge_queue" for rule in value["rules"])):
            continue
        visibility = "not_disclosed"
        if "bypass_actors" in value:
            # An explicit null, malformed value, or nonempty inventory is not
            # the documented omission and remains non-qualifying.
            if type(value["bypass_actors"]) is not list or value["bypass_actors"]:
                continue
            visibility = "observed_empty"
        protecting.append({"ruleset_id": value["id"], "current_user_can_bypass": "never",
                           "bypass_actor_inventory_visibility": visibility})
    if not protecting:
        raise OperatorRefusal("capability_current_credential_not_protected")
    return sorted(protecting, key=lambda value: value["ruleset_id"])


def qualify_capability(github: handoff.GitHub, native: atomic.NativeGit,
                       run_id: int, main: str, inspection: dict, *,
                       diagnostics: RefusalDiagnostics | None = None) -> dict:
    diagnostics = diagnostics or RefusalDiagnostics()
    diagnostics.enter("capability_protection")
    protection = require_capability_main_protection(inspection)
    diagnostics.enter("capability_ancestor")
    parents = handoff.git("show", "-s", "--format=%P", main, deadline=github.deadline).split()
    handoff.require(len(parents) == 1 and handoff.SHA.fullmatch(parents[0]) is not None,
                    "Capability needs a real distinct first-parent ancestor")
    ancestor = parents[0]
    handoff.git("merge-base", "--is-ancestor", ancestor, main, deadline=github.deadline)
    handoff.require(not handoff.git("diff", "--name-only", "--no-renames", ancestor, main, "--",
                                    ".github/workflows", deadline=github.deadline),
                    "Capability ancestor must have identical workflow files; use the separate version-only change")
    tag = f"v-release-capability-{run_id}-1"
    intent_tag = f"v-release-capability-intent-{run_id}-1"
    diagnostics.enter("capability_tag_absence")
    handoff.require(github.json(f"repos/{REPOSITORY}/git/ref/tags/{tag}", absent=True) is None
                    and github.json(f"repos/{REPOSITORY}/git/ref/tags/{intent_tag}", absent=True) is None,
                    "Capability audit or retained intent ref already exists")
    bindings = (f"Handoff-Contract: {handoff.TAG_HANDOFF_CONTRACT}\n"
                f"Main-Check-Scope: {handoff.MAIN_CHECK_SCOPE}\n"
                f"Audit-Tag: {tag}\nOperator-Run: {run_id}\nOperator-Attempt: 1\n"
                f"Operator-Source: {main}\nAncestor-Source: {ancestor}\n"
                f"Operator-Not-After: {github.deadline.strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
                f"Rulesets-SHA256: {inspection['rulesets_sha256']}\n")
    intent_message = "Non-release exclusive capability intent\n\n" + bindings
    diagnostics.enter("capability_intent_object")
    intent_object = create_tag_object(github, intent_tag, ancestor, intent_message)
    message = ("Non-release create-only tag capability qualification\n\n" + bindings
               + f"Intent-Ref: refs/tags/{intent_tag}\nIntent-Object: {intent_object['sha']}\n")
    diagnostics.enter("capability_tag_object")
    obj = create_tag_object(github, tag, ancestor, message)
    handoff.require(github.main()["commit"]["sha"] == main, "Main changed before capability comparison")
    # Model an admitted A -> A no-op that has become stale at current C.
    # The transport binds discovery to C without proposing an A -> C update.
    diagnostics.enter("capability_negative")
    negative = native.exchange(atomic.transaction_spec(ancestor, main, tag, obj["sha"],
                                                        f"capability-negative-{run_id}-1"))
    handoff.require(negative["decision"] in {"confirmed_stale_main_refusal", "confirmed_main_policy_refusal"},
                    "Negative capability evidence was not admitted")
    diagnostics.enter("capability_negative_readback")
    handoff.require(github.main()["commit"]["sha"] == main
                    and github.json(f"repos/{REPOSITORY}/git/ref/tags/{tag}", absent=True) is None,
                    "Negative atomic capability transaction unexpectedly changed a ref")
    diagnostics.enter("capability_before_positive")
    handoff.require(inspect_repository(github) == (run_id, main, inspection),
                    "Operator context or repository rules changed before the positive tag reservation")
    diagnostics.enter("capability_intent_reservation")
    intent_reservation = github.create_tag_ref(intent_tag, intent_object["sha"])
    diagnostics.enter("capability_intent_readback")
    read_exact_tag(github, intent_tag, intent_object["sha"], ancestor, intent_message)
    handoff.remaining(github.deadline)
    handoff.require(github.main()["commit"]["sha"] == main, "Main changed after capability intent reservation")
    handoff.require(inspect_repository(github) == (run_id, main, inspection),
                    "Operator context or repository rules changed after capability intent reservation")
    diagnostics.enter("capability_positive")
    # The native negative remains evidence of a real stale/policy refusal only.
    # GitHub rejects even a current-main no-op under the required merge queue.
    # This separately versioned contract reserves ONLY the absent annotated tag.
    read_exact_tag(github, intent_tag, intent_object["sha"], ancestor, intent_message)
    positive = github.create_tag_ref(tag, obj["sha"])
    diagnostics.enter("capability_positive_readback")
    read_exact_tag(github, tag, obj["sha"], ancestor, message)
    read_exact_tag(github, intent_tag, intent_object["sha"], ancestor, intent_message)
    handoff.require(github.main()["commit"]["sha"] == main, "Main changed during capability qualification")
    diagnostics.enter("capability_final_inspection")
    final_run, final_source, final_inspection = inspect_repository(github)
    handoff.require((final_run, final_source, final_inspection) == (run_id, main, inspection),
                    "Operator context or repository rules changed during capability qualification")
    handoff.remaining(github.deadline)
    return {"schema": "marty.release-tag-capability/v5", "status": "success", "repository": REPOSITORY,
            "tag_handoff_contract": handoff.TAG_HANDOFF_CONTRACT,
            "ref_creation_scope": handoff.REF_CREATION_SCOPE, "main_check_scope": handoff.MAIN_CHECK_SCOPE,
            "tag_alone_authorizes_publication": False,
            "operator_run_id": run_id, "operator_run_attempt": 1, "operator_source_sha": main,
            "ancestor_source_sha": ancestor, "audit_tag": tag, "tag_object_sha": obj["sha"],
            "intent_tag": intent_tag, "intent_object_sha": intent_object["sha"],
            "intent_ref_creation": intent_reservation,
            "main_protection_ruleset_ids": [value["ruleset_id"] for value in protection],
            "main_protection_scope": "current_workflow_credential",
            "main_protection_observations": protection,
            "negative_probe_scope": "stale_or_policy_refusal_only",
            "negative_transaction": transaction_summary(negative), "positive_ref_creation": positive,
            "main_before_sha": main, "main_after_sha": main, "completed_at": utc_now(), **inspection}


def verify_crypto(assets: Path, request: dict, gh: Path, cosign: Path, deadline: datetime,
                  observations: list[dict] | None = None) -> None:
    if __package__:
        from . import verify_installer_provenance as provenance
    else:
        import verify_installer_provenance as provenance
    code, names = handoff.command([
        "bash", "-c", 'source "$1"; operator_release_require_local_assets; printf "%s\\n" "${OPERATOR_SIGNED_INPUTS[@]}"',
        "operator-assets", str(ROOT / "scripts/operator-release-assets.sh")], cwd=assets,
        timeout=handoff.remaining(deadline))
    handoff.require(code == 0, "Original release checksum or allowlist verification failed")
    subjects = names.decode("ascii").splitlines()
    handoff.require(len(subjects) == 13 and len(set(subjects)) == 13, "Original release subject set changed")
    full = assets / "install.sh.provenance.jsonl"

    def bounded_crypto(arguments: list[str]) -> str:
        # Preserve the existing verifier's credential/proxy-free private HOME
        # and output ceiling, additionally cap the entire process group at the
        # remaining absolute handoff deadline.
        with tempfile.TemporaryDirectory(prefix="marty-handoff-crypto-") as temporary:
            environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR") if key in os.environ}
            environment.update(HOME=temporary, USERPROFILE=temporary, GH_CONFIG_DIR=temporary,
                               XDG_CONFIG_HOME=temporary, XDG_CACHE_HOME=temporary,
                               GH_PROMPT_DISABLED="1", GH_HOST="github.com")
            code, raw = handoff.command(arguments, maximum=provenance.MAX_OUTPUT,
                                        timeout=handoff.remaining(deadline), cwd=Path(temporary), environment=environment)
            handoff.require(code == 0, "Original publication crypto verifier failed")
            return raw.decode("utf-8")

    for name in subjects:
        provenance.verify_subject(assets / name, full, gh=gh, workflow=handoff.CD_WORKFLOW,
                                  source_sha=request["source_sha"], run_id=request["run_id"], run_attempt=1,
                                  cosign=cosign, signature_bundle=assets / (name + ".sigstore.json"),
                                  runner=bounded_crypto)
        if observations is not None:
            observations.append({"subject": name, "source_sha": request["source_sha"],
                                 "run_id": request["run_id"], "run_attempt": 1,
                                 "cosign": "success", "exact_publication_attestation": "success"})
    # Reuse the complete original five-sidecar/inventory verifier unchanged.
    # The parent process-group deadline also bounds every child verifier.
    code, _ = handoff.command([
        sys.executable, str(ROOT / "scripts/stable_installer_assets.py"), "--phase", "verify-published",
        "--assets", str(assets), "--source-sha", request["source_sha"], "--tag", request["tag"], "--gh", str(gh)],
        timeout=handoff.remaining(deadline))
    handoff.require(code == 0, "Original stable installer proof verification failed")
    if observations is not None:
        observations.append({"verifier": "stable_installer_assets.py --phase verify-published",
                             "subjects": 5, "status": "success"})


def promoted_digests(transaction: dict, deadline: datetime) -> None:
    for role, image in IMAGE_URIS.items():
        code, raw = handoff.command(["docker", "buildx", "imagetools", "inspect", "--raw",
                                     f"{image}:{transaction['version']}"], timeout=handoff.remaining(deadline, 60))
        handoff.require(code == 0 and handoff.sha256(raw) == transaction["images"][role]["digest"],
                        f"Promoted {role} digest differs from the qualified transaction")


def create_qualified_tag(github: handoff.GitHub, native: atomic.NativeGit, operator_run: int, main: str, cd_run: int,
                         claim_run: str, gh: Path, cosign: Path, inspection: dict) -> dict:
    if __package__:
        from .stable_publication_checkpoint import (
            CHECKPOINT_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, load_checkpoint, request_digest,
        )
    else:
        from stable_publication_checkpoint import (
            CHECKPOINT_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, load_checkpoint, request_digest,
        )
    require_capability_main_protection(inspection)
    raw_run = github.json(f"repos/{REPOSITORY}/actions/runs/{cd_run}")
    handoff.require(isinstance(raw_run, dict) and handoff.SHA.fullmatch(raw_run.get("head_sha", "")) is not None,
                    "Original candidate source is unavailable")
    source = raw_run["head_sha"]
    waiting_run(github, cd_run, source)
    artifact_name = f"stack-release-publication-inputs-{cd_run}-1"
    artifact = github.artifact(cd_run, artifact_name, source)
    with tempfile.TemporaryDirectory(prefix="marty-operator-handoff-") as temporary:
        directory = Path(temporary)
        archive = directory / "checkpoint.zip"
        github.download(artifact, archive)
        checkpoint = directory / "checkpoint"
        handoff.extract_archive(archive, checkpoint, set(CHECKPOINT_FILES),
                                maximum=MAX_TOTAL_BYTES, limits=MAX_FILE_BYTES)
        request = load_checkpoint(checkpoint)
        request_deadline = handoff.timestamp(request["not_after"])
        github.deadline = min(github.deadline, request_deadline) if github.deadline is not None else request_deadline
        handoff.require(request["run_id"] == cd_run and request["source_sha"] == source
                        and request["claim_run_id"] == claim_run and request["protected_main_commit"] == main,
                        "Publication checkpoint differs from this candidate, claim or protected main")
        request_sha = request_digest(checkpoint)
        intent_tag = handoff.release_intent_tag(request["tag"])
        # This permanent per-version owner fences all later production writes,
        # including a different operator after an unknown production outcome.
        # An existing owner is never adopted, even by an identical invocation.
        handoff.require(github.json(f"repos/{REPOSITORY}/git/ref/tags/{intent_tag}", absent=True) is None,
                        "A retained original operator already owns this release version")
        transaction = validate_resume(
            handoff.decode(handoff.bounded_file(checkpoint / "assets/release-transaction.json", 65536)),
            repository=REPOSITORY, source_sha=source, stack_lock=ROOT / "release/stack-lock.json",
            claim_run_id=claim_run, required_state="promoted")
        authority = gate_authority(handoff.bounded_file(checkpoint / "official-interoperability.json"),
                                   transaction, run_id=cd_run, current_attempt=1)
        handoff.git("fetch", "--no-tags", "origin", source, main, deadline=github.deadline)
        require_review_only_history(source, main, cd_run, 1, authority["review_required"],
                                    record_sha256=authority["record_sha256"],
                                    timeout_seconds=handoff.remaining(github.deadline, 30))
        claim = github.run(int(claim_run), ".github/workflows/prepare-stack-tag.yml", source)
        handoff.require(claim.get("status") == "completed" and claim.get("conclusion") == "success",
                        "Original exact-source release claim did not succeed")
        proof = github.artifact(int(claim_run), f"stack-release-claim-{request['tag']}", source)
        handoff.require(proof["size_in_bytes"] <= 1024 * 1024, "Original claim proof is oversized")
        github.download(proof, directory / "claim.zip")
        handoff.extract_archive(directory / "claim.zip", directory / "claim",
                                {"release-transaction.json", "stack-tag-evidence.json"}, maximum=1024 * 1024)
        seed = validate_resume(handoff.decode(handoff.bounded_file(directory / "claim/release-transaction.json", 65536)),
                               repository=REPOSITORY, source_sha=source, stack_lock=ROOT / "release/stack-lock.json",
                               claim_run_id=claim_run, required_state="claimed")
        handoff.require(seed["transaction_id"] == transaction["transaction_id"], "Original claim transaction differs")
        verify_crypto(checkpoint / "assets", request, gh, cosign, github.deadline, github.crypto)
        load_checkpoint(checkpoint)
        promoted_digests(transaction, github.deadline)
        handoff.require(github.json(f"repos/{REPOSITORY}/git/ref/tags/{request['tag']}", absent=True) is None
                        and github.json(f"repos/{REPOSITORY}/releases/tags/{request['tag']}", absent=True) is None,
                        "An immutable tag or release already owns the coordinate")
        handoff.require(github.artifact(cd_run, artifact_name, source) == artifact,
                        "Publication checkpoint changed during verification")
        waiting_run(github, cd_run, source)
        handoff.require(github.main()["commit"]["sha"] == main, "Protected main changed before tag creation")
        handoff.remaining(github.deadline)
        intent_message = handoff.intent_message(request, request_sha, artifact, operator_run)
        intent_object = create_tag_object(github, intent_tag, source, intent_message)
        waiting_run(github, cd_run, source)
        handoff.require(github.main()["commit"]["sha"] == main, "Protected main changed before intent reservation")
        intent_reservation = github.create_tag_ref(intent_tag, intent_object["sha"])
        read_exact_tag(github, intent_tag, intent_object["sha"], source, intent_message)
        handoff.remaining(github.deadline)
        # No production mutation is permitted until ownership was created by
        # THIS invocation and confirmed. An unknown owner acquisition stops
        # here; it cannot have sent the production reference request.
        waiting_run(github, cd_run, source)
        handoff.require(github.main()["commit"]["sha"] == main, "Protected main changed after intent reservation")
        handoff.require(inspect_repository(github) == (operator_run, main, inspection),
                        "Operator context or repository rules changed after intent reservation")
        message = handoff.tag_message(request, request_sha, artifact, operator_run,
                                      intent_object_sha=intent_object["sha"])
        tag_object = create_tag_object(github, request["tag"], source, message)
        # No automatic retry. If the result is lost, preserve the immutable
        # object/ref and require exact API inspection before any later action.
        waiting_run(github, cd_run, source)
        handoff.require(github.main()["commit"]["sha"] == main, "Protected main changed before tag reservation")
        read_exact_tag(github, intent_tag, intent_object["sha"], source, intent_message)
        reservation = github.create_tag_ref(request["tag"], tag_object["sha"])
        read_exact_tag(github, request["tag"], tag_object["sha"], source, message)
        read_exact_tag(github, intent_tag, intent_object["sha"], source, intent_message)
        handoff.require(github.main()["commit"]["sha"] == main, "Main changed after tag reservation")
        waiting_run(github, cd_run, source)
        final_run, final_source, final_inspection = inspect_repository(github)
        handoff.require((final_run, final_source, final_inspection) == (operator_run, main, inspection),
                        "Operator context or repository rules changed during tag creation")
        handoff.remaining(github.deadline)
        return {
            "schema": handoff.TAG_RESULT_SCHEMA, "status": "success", "mode": "create-qualified-tag",
            "tag_handoff_contract": handoff.TAG_HANDOFF_CONTRACT,
            "ref_creation_scope": handoff.REF_CREATION_SCOPE, "main_check_scope": handoff.MAIN_CHECK_SCOPE,
            "tag_alone_authorizes_publication": False, "tag_ref_creation": reservation,
            "intent_tag": intent_tag, "intent_object_sha": intent_object["sha"],
            "intent_ref_creation": intent_reservation,
            "repository": REPOSITORY, "operator_run_id": operator_run, "operator_run_attempt": 1,
            "operator_source_sha": main, "source_sha": source, "candidate_run_id": cd_run,
            "candidate_run_attempt": 1, "claim_run_id": claim_run, "tag": request["tag"],
            "protected_main_commit": main, "request_sha256": request_sha,
            "checkpoint_artifact_id": artifact["id"], "checkpoint_artifact_sha256": artifact["digest"],
            "tag_object_sha": tag_object["sha"], "tag_commit_sha": source,
            "completed_at": utc_now(), "crypto_verified": True, "main_before_sha": main, "main_after_sha": main,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["inspect", "qualify-capability", "create-qualified-tag"], default="inspect")
    parser.add_argument("--promotion-run-id", default="")
    parser.add_argument("--claim-run-id", default="")
    parser.add_argument("--gh", type=Path)
    parser.add_argument("--cosign", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = {"schema": "marty.release-tag-operator-refusal/v1", "status": "refused", "mode": args.mode,
              "repository": REPOSITORY, "automatic_retry_or_cleanup_performed": False}
    github = handoff.GitHub(deadline=datetime.now(timezone.utc) + timedelta(minutes=10))
    native = None
    journal = None
    exit_code = 1
    diagnostics = RefusalDiagnostics()

    def observations() -> dict:
        run = os.environ.get("GITHUB_RUN_ID", "")
        source = os.environ.get("GITHUB_SHA", "")
        return {"schema": "marty.release-tag-operator-observations/v3", "repository": REPOSITORY,
                "tag_handoff_contract": handoff.TAG_HANDOFF_CONTRACT,
                "ref_creation_scope": handoff.REF_CREATION_SCOPE, "main_check_scope": handoff.MAIN_CHECK_SCOPE,
                "mode": args.mode, "operator_run_id": run if re.fullmatch(r"[1-9][0-9]*", run) else "",
                "operator_run_attempt": "1" if os.environ.get("GITHUB_RUN_ATTEMPT") == "1" else "",
                "operator_source_sha": source if handoff.SHA.fullmatch(source) else "",
                "rest_api_mutations": github.mutations, "git_transactions": native.transactions if native else [],
                "crypto": github.crypto, "automatic_retry_or_cleanup_performed": False}

    def persist() -> None:
        handoff.require(journal is not None, "Operator audit is unavailable")
        journal.write(observations())

    try:
        handoff.require(not args.output.exists() and not args.output.is_symlink(), "Operator output already exists")
        audit = args.output.with_name("operator-api-receipt.json")
        handoff.require(audit != args.output, "Operator result and audit paths must differ")
        journal = ObservationJournal(audit)
        native = atomic.NativeGit(runner=handoff.command, deadline=lambda: github.deadline, persist=persist)
        github.observer = persist
        persist()
        diagnostics.enter("repository_inspection")
        operator_run, source, inspection = inspect_repository(github)
        diagnostics.enter("mode_validation")
        if args.mode in {"inspect", "qualify-capability"}:
            handoff.require(not args.promotion_run_id and not args.claim_run_id and args.gh is None and args.cosign is None,
                            "Capability inspection does not accept candidate or executable overrides")
            if args.mode == "inspect":
                result = {"schema": "marty.release-tag-inspection/v1", "status": "inspected", "repository": REPOSITORY,
                          "operator_run_id": operator_run, "operator_run_attempt": 1, "operator_source_sha": source,
                          "read_only": True, "completed_at": utc_now(), **inspection}
            else:
                result = qualify_capability(github, native, operator_run, source, inspection, diagnostics=diagnostics)
        else:
            handoff.require(re.fullmatch(r"[1-9][0-9]*", args.promotion_run_id) is not None
                            and re.fullmatch(r"[1-9][0-9]*", args.claim_run_id) is not None
                            and handoff.positive(int(args.promotion_run_id)) and handoff.positive(int(args.claim_run_id))
                            and args.gh is not None and args.cosign is not None,
                            "Qualified tag creation requires exact run IDs and admitted verifier binaries")
            diagnostics.enter("qualified_tag")
            result = create_qualified_tag(github, native, operator_run, source, int(args.promotion_run_id), args.claim_run_id,
                                          args.gh.resolve(strict=True), args.cosign.resolve(strict=True), inspection)
        exit_code = 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        # Errors are classifications only. Never echo command output, credentials
        # or redirected archive URLs. An unknown mutation outcome stays unknown.
        result["error_type"] = type(error).__name__
        result["refusal_stage"] = diagnostics.stage
        result["refusal_reason"] = refusal_reason(error)
        result["completed_at"] = utc_now()
        print(f"Release tag operator refused at {diagnostics.stage} ({result['refusal_reason']}); "
              "inspect its bound receipt. No automatic mutation retry or cleanup.")
    finally:
        if journal is not None:
            try:
                persist()
            except (OSError, ValueError):
                exit_code = 1
                result = {"schema": "marty.release-tag-operator-refusal/v1", "status": "refused", "mode": args.mode,
                          "repository": REPOSITORY, "error_type": "ObservationError", "completed_at": utc_now(),
                          "refusal_stage": "observation_finalization", "refusal_reason": "observation_write_failed",
                          "automatic_retry_or_cleanup_performed": False}
                print("Release tag operator could not preserve its complete audit; no automatic retry is allowed.")
            finally:
                journal.close()
    if not args.output.exists() and not args.output.is_symlink():
        try:
            with args.output.open("xb") as output:
                output.write(handoff.encoded(result))
        except OSError:
            return 1
    else:
        return 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
