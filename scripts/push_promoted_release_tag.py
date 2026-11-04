#!/usr/bin/env python3
"""Create one qualified annotated tag through an exact native operator workflow.

The default inspect mode is read-only. Production ref creation requires the
original CD attempt to be waiting on an authenticated, byte-exact checkpoint.
No mode changes main, overwrites a tag, retries an ambiguous mutation, signs a
candidate payload, or publishes a release.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

if __package__:
    from . import release_tag_handoff as handoff
    from .release_review_main import gate_authority, require_review_only_history
    from .release_transaction import IMAGE_URIS, validate_resume
else:
    import release_tag_handoff as handoff
    from release_review_main import gate_authority, require_review_only_history
    from release_transaction import IMAGE_URIS, validate_resume

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = handoff.REPOSITORY
ZERO = "0" * 40
MUTATION = "mutation($input: UpdateRefsInput!) { updateRefs(input: $input) { clientMutationId } }"
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
LANES = frozenset({"oid4vci-issuer", "oid4vp-final", "oid4vp-url-query", "oid4vp-mdoc", "haip", "w3c-v2", "eudi"})


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
                                  "rulesets": details, "rulesets_sha256": handoff.sha256(handoff.encoded(details))}


def validate_waiting_jobs(jobs: list[dict], run_id: int, source: str) -> None:
    handoff.require(jobs and all(handoff.positive(job.get("id")) for job in jobs)
                    and len({job["id"] for job in jobs}) == len(jobs), "CD job listing is ambiguous")
    for job in jobs:
        handoff.require(handoff.positive(job.get("run_id")) and job["run_id"] == run_id
                        and type(job.get("run_attempt")) is int and job["run_attempt"] == 1
                        and job.get("head_sha") == source, "CD job belongs to another invocation")
    names = [job.get("name") for job in jobs]
    handoff.require(MANDATORY_JOBS <= set(names), "CD transitive prerequisite jobs are missing")
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


def atomic_request(main_before: str, main_after: str, tag: str, tag_object: str,
                   client_id: str) -> dict:
    handoff.require(all(handoff.SHA.fullmatch(value) is not None
                        for value in (main_before, main_after, tag_object)), "Invalid atomic object identity")
    handoff.require(handoff.TAG.fullmatch(tag) is not None
                    or re.fullmatch(r"v-release-capability-[1-9][0-9]*-1", tag) is not None,
                    "Atomic ref is outside the closed tag contract")
    return {"query": MUTATION, "variables": {"input": {
        "repositoryId": handoff.REPOSITORY_NODE, "clientMutationId": client_id,
        "refUpdates": [
            {"name": "refs/heads/main", "beforeOid": main_before, "afterOid": main_after, "force": False},
            {"name": f"refs/tags/{tag}", "beforeOid": ZERO, "afterOid": tag_object, "force": False},
        ],
    }}}


def graph_result(github: handoff.GitHub, request: dict) -> tuple[int, dict]:
    status, raw = github.response("graphql", method="POST", payload=request)
    value = handoff.decode(raw)
    handoff.require(isinstance(value, dict), "Atomic GitHub response is malformed; outcome is unknown")
    return status, value


def require_graph_success(status: int, value: dict, client_id: str) -> None:
    data = value.get("data")
    updated = data.get("updateRefs") if isinstance(data, dict) else None
    handoff.require(status == 200 and not value.get("errors")
                    and isinstance(updated, dict) and updated.get("clientMutationId") == client_id,
                    "Atomic ref mutation did not return exact success; outcome must be inspected, never replayed")


def stale_main_rejection(status: int, value: dict, before: str, current: str) -> bool:
    if status != 200 or value.get("data") not in (None, {"updateRefs": None}):
        return False
    errors = value.get("errors")
    if not isinstance(errors, list) or len(errors) != 1 or not isinstance(errors[0], dict):
        return False
    message = errors[0].get("message")
    if not isinstance(message, str) or len(message) > 2048:
        return False
    lower = message.lower()
    main_named = "refs/heads/main" in lower or re.search(r"\bmain\b", lower) is not None
    explicit_before = "before" in lower and ("oid" in lower or "sha" in lower) and any(
        word in lower for word in ("match", "expected", "stale", "changed"))
    explicit_values = before in lower and current in lower and any(word in lower for word in ("expected", "match", "stale"))
    return bool(main_named and (explicit_before or explicit_values))


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


def qualify_capability(github: handoff.GitHub, run_id: int, main: str, inspection: dict) -> dict:
    parents = handoff.git("show", "-s", "--format=%P", main, deadline=github.deadline).split()
    handoff.require(len(parents) == 1 and handoff.SHA.fullmatch(parents[0]) is not None,
                    "Capability needs a real distinct first-parent ancestor")
    ancestor = parents[0]
    handoff.git("merge-base", "--is-ancestor", ancestor, main, deadline=github.deadline)
    handoff.require(not handoff.git("diff", "--name-only", "--no-renames", ancestor, main, "--",
                                    ".github/workflows", deadline=github.deadline),
                    "Capability ancestor must have identical workflow files; use the separate version-only change")
    tag = f"v-release-capability-{run_id}-1"
    handoff.require(github.json(f"repos/{REPOSITORY}/git/ref/tags/{tag}", absent=True) is None,
                    "Capability audit ref already exists")
    message = ("Non-release atomic-ref capability qualification\n\n"
               f"Operator-Run: {run_id}\nOperator-Attempt: 1\n"
               f"Operator-Source: {main}\nAncestor-Source: {ancestor}\n"
               f"Rulesets-SHA256: {inspection['rulesets_sha256']}\n")
    obj = create_tag_object(github, tag, ancestor, message)
    handoff.require(github.main()["commit"]["sha"] == main, "Main changed before capability comparison")
    negative = atomic_request(ancestor, main, tag, obj["sha"], f"capability-negative-{run_id}-1")
    status, refusal = graph_result(github, negative)
    # A generic error, permission refusal or non-fast-forward rejection is not
    # evidence that the server enforced the beforeOid assertion.
    handoff.require(stale_main_rejection(status, refusal, ancestor, main),
                    "Capability did not return an attributable stale-main precondition refusal")
    handoff.require(github.main()["commit"]["sha"] == main
                    and github.json(f"repos/{REPOSITORY}/git/ref/tags/{tag}", absent=True) is None,
                    "Negative atomic capability transaction unexpectedly changed a ref")
    positive_id = f"capability-positive-{run_id}-1"
    positive = atomic_request(main, main, tag, obj["sha"], positive_id)
    status, response = graph_result(github, positive)
    require_graph_success(status, response, positive_id)
    read_exact_tag(github, tag, obj["sha"], ancestor, message)
    handoff.require(github.main()["commit"]["sha"] == main, "Main changed during capability qualification")
    return {"schema": "marty.release-tag-capability/v1", "status": "success", "repository": REPOSITORY,
            "operator_run_id": run_id, "operator_run_attempt": 1, "operator_source_sha": main,
            "ancestor_source_sha": ancestor, "audit_tag": tag, "tag_object_sha": obj["sha"],
            "negative_request": negative, "negative_response": refusal,
            "positive_request": positive, "positive_response": response,
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


def create_qualified_tag(github: handoff.GitHub, operator_run: int, main: str, cd_run: int,
                         claim_run: str, gh: Path, cosign: Path) -> dict:
    if __package__:
        from .stable_publication_checkpoint import (
            CHECKPOINT_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, load_checkpoint, request_digest,
        )
    else:
        from stable_publication_checkpoint import (
            CHECKPOINT_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, load_checkpoint, request_digest,
        )
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
        message = handoff.tag_message(request, request_sha, artifact, operator_run)
        tag_object = create_tag_object(github, request["tag"], source, message)
        # No automatic retry. If the result is lost, preserve the immutable
        # object/ref and require exact API inspection before any later action.
        waiting_run(github, cd_run, source)
        handoff.require(github.main()["commit"]["sha"] == main, "Protected main changed before atomic tag handoff")
        client_id = f"release-tag-{operator_run}-1"
        status, response = graph_result(github, atomic_request(main, main, request["tag"], tag_object["sha"], client_id))
        require_graph_success(status, response, client_id)
        read_exact_tag(github, request["tag"], tag_object["sha"], source, message)
        handoff.require(github.main()["commit"]["sha"] == main, "Main changed after atomic tag creation")
        waiting_run(github, cd_run, source)
        handoff.remaining(github.deadline)
        return {
            "schema": "marty.release-tag-handoff-result/v1", "status": "success", "mode": "create-qualified-tag",
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
    try:
        handoff.require(not args.output.exists() and not args.output.is_symlink(), "Operator output already exists")
        operator_run, source, inspection = inspect_repository(github)
        if args.mode in {"inspect", "qualify-capability"}:
            handoff.require(not args.promotion_run_id and not args.claim_run_id and args.gh is None and args.cosign is None,
                            "Capability inspection does not accept candidate or executable overrides")
            if args.mode == "inspect":
                result = {"schema": "marty.release-tag-inspection/v1", "status": "inspected", "repository": REPOSITORY,
                          "operator_run_id": operator_run, "operator_run_attempt": 1, "operator_source_sha": source,
                          "read_only": True, "completed_at": utc_now(), **inspection}
            else:
                result = qualify_capability(github, operator_run, source, inspection)
        else:
            handoff.require(re.fullmatch(r"[1-9][0-9]*", args.promotion_run_id) is not None
                            and re.fullmatch(r"[1-9][0-9]*", args.claim_run_id) is not None
                            and handoff.positive(int(args.promotion_run_id)) and handoff.positive(int(args.claim_run_id))
                            and args.gh is not None and args.cosign is not None,
                            "Qualified tag creation requires exact run IDs and admitted verifier binaries")
            result = create_qualified_tag(github, operator_run, source, int(args.promotion_run_id), args.claim_run_id,
                                          args.gh.resolve(strict=True), args.cosign.resolve(strict=True))
        args.output.write_bytes(handoff.encoded(result))
        return 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        # Errors are classifications only. Never echo command output, credentials
        # or redirected archive URLs. An unknown mutation outcome stays unknown.
        result["error_type"] = type(error).__name__
        result["completed_at"] = utc_now()
        if not args.output.exists() and not args.output.is_symlink():
            args.output.write_bytes(handoff.encoded(result))
        print("Release tag operator refused; inspect its bound receipt. No automatic mutation retry or cleanup.")
        return 1
    finally:
        audit = args.output.with_name("operator-api-receipt.json")
        if not audit.exists() and not audit.is_symlink():
            audit.write_bytes(handoff.encoded({
                "schema": "marty.release-tag-operator-observations/v1", "repository": REPOSITORY,
                "mode": args.mode, "operator_run_id": os.environ.get("GITHUB_RUN_ID", ""),
                "operator_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
                "operator_source_sha": os.environ.get("GITHUB_SHA", ""),
                "mutations": github.mutations, "crypto": github.crypto,
                "automatic_retry_or_cleanup_performed": False,
            }))


if __name__ == "__main__":
    raise SystemExit(main())
