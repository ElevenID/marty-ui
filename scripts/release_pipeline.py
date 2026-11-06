#!/usr/bin/env python3
"""Run the existing release producers from one protected-main request.

Each job owns a fixed stage and an exclusive journal. Dispatches use the current
GitHub API's returned run ID exactly once; polling is read-only. Child workflows
retain their own claims, qualification, signing and publication permissions.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

if __package__:
    from . import release_tag_handoff as transport
    from .ci.check_release_preflight import check as source_preflight
else:
    import release_tag_handoff as transport
    from ci.check_release_preflight import check as source_preflight

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/release-pipeline.yml"
PUBLISHER = ".github/workflows/publish-stable-candidate.yml"
WEB = ".github/workflows/production-web-release.yml"
PHASE_MINUTES = {"qualify": 330, "nightly": 330, "stable": 330, "stable-publish": 45,
                 "web-application": 100, "web-website": 100, "web-compose": 40}
DISPATCH = {
    "full-ci": (".github/workflows/ci.yml", {"canvas_migrated_base_pilot"}, {"CI Gate"}),
    "nightly-claim": (".github/workflows/prepare-nightly-claim.yml", {"source_sha"}, {"claim"}),
    "nightly-release": (".github/workflows/nightly-release.yml", {"claim_run_id", "publish_cloudflare_addon"},
                        {"admit", "prepare-native", "prepare-installation", "runtime-happy-path", "sign-release", "publish"}),
    "stable-claim": (".github/workflows/prepare-stack-tag.yml", {"source_sha", "tag"},
                     {"Validate exact main and persist the no-write claim"}),
    "stable-release": (".github/workflows/cd.yml",
                       {"claim_run_id", "publication_contract", "selfhost_public_profile",
                        "publish_cloudflare_addon", "selfhost_external_images_json"},
                       {"official-gate-evidence", "qualify-release", "publish-manifest"}),
    "stable-publisher": (PUBLISHER, {"candidate_run_id"}, {"intake", "publish"}),
    "web-application": (WEB, {"mode", "stack_release_tag", "expected_source_sha"}, {"release"}),
    "web-website": (WEB, {"mode", "expected_source_sha"}, {"release"}),
    "web-compose": (WEB, {"mode", "website_run_id", "website_run_attempt", "application_run_id",
                          "application_run_attempt", "expected_source_sha"}, {"compose"}),
}
ACTIVE = {"queued", "in_progress", "waiting", "pending", "requested"}
TITLE_SETTLE_SECONDS = 30
IMAGE = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}\Z")
STOP_MESSAGES = {
    "invalid_image_pins": "Stable release requires bounded external image pins",
    "invalid_image_reference": "Every external image must be an exact registry/repository@sha256 reference",
    "invalid_channel": "Select nightly, stable or both",
    "invalid_release_options": "Release profile or production-web selection is invalid",
    "web_requires_stable": "Production web requires the stable release in this request",
    "invalid_image_override": "External image override must be JSON text",
    "image_roster_changed": "External image override must preserve the source-controlled service and repository roster",
    "invalid_pipeline_identity": "Invalid release pipeline identity",
    "stage_deadline_exceeded": "Release pipeline stage exceeded its fixed deadline",
    "source_changed": "Protected main changed; this release request cannot select new source",
    "invalid_child_run_id": "A positive exact workflow run ID is required",
    "child_identity_mismatch": "Child run differs from the exact original workflow, source or attempt",
    "child_outside_stage_window": "Child run predates this release request or exceeds its stage window",
    "child_title_mismatch": "Child run belongs to another automatic continuation or web mode",
    "child_jobs_mismatch": "Child job evidence belongs to another invocation",
    "required_job_ambiguous": "Required release job is missing or ambiguous",
    "required_job_failed": "Required release job failed or was skipped",
    "child_workflow_failed": "Original child workflow did not succeed",
    "child_state_unknown": "Child workflow has an unknown state",
    "dispatch_already_consumed": "Release stage has already consumed this dispatch",
    "dispatch_inputs_mismatch": "Release dispatch inputs differ from their fixed stage",
    "dispatch_unconfirmed": "Workflow dispatch was not confirmed by the current API; do not retry",
    "dispatch_missing_identity": "Workflow dispatch returned no exact run ID; do not search for a substitute",
    "dispatch_foreign_urls": "Workflow dispatch returned foreign run URLs",
    "publisher_listing_invalid": "Automatic publisher listing is incomplete or ambiguous",
    "publisher_ambiguous": "More than one automatic publisher claims this original candidate",
    "nightly_not_requested": "Nightly was not requested",
    "stable_not_requested": "Stable was not requested",
    "web_not_requested": "Production web was not requested",
    "checkout_mismatch": "Pipeline checkout differs from its exact source",
    "pipeline_not_running": "Original release pipeline is not running",
    "github_read_failed": "GitHub read failed; no request was retried",
    "invalid_json": "Evidence was not bounded valid JSON",
    "protected_main_unverified": "Protected main could not be authenticated",
    "transport_rejected": "GitHub transport or evidence failed validation",
    "io_timeout": "An I/O operation timed out; preserve any uncertain dispatch",
    "io_error": "An I/O operation failed; no dispatch was retried",
    "invalid_data": "Release context or evidence has an invalid shape or value",
}
OPERATIONS = {
    "validate_context", "validate_checkout", "load_configuration", "source_preflight",
    "read_pipeline_run", "create_stage_journal", "execute_stage", "write_stage_outputs",
    "check_deadline", "check_protected_main", "read_child_run", "validate_child_run",
    "read_child_jobs", "validate_child_jobs", "wait_child", "prepare_dispatch",
    "record_dispatch_intent", "dispatch_workflow", "record_dispatch_response",
    "validate_dispatch_response", "record_dispatch_acknowledgment", "record_child_success",
    "find_stable_publisher", "record_stable_publisher", "finalize_stage",
}


class PipelineError(transport.HandoffError):
    """A coordinator refusal with a source-controlled public explanation."""
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(STOP_MESSAGES[code])


def require(condition: bool, code: str) -> None:
    if not condition:
        raise PipelineError(code)


def stop_diagnostic(error: Exception, stage: str, operation: str, *, child_run_id: int | None = None,
                    expected_source_sha: str | None = None, observed_main_sha: str | None = None) -> dict:
    """Project failures onto bounded public facts, never arbitrary exception text."""
    code = "invalid_data"
    http_status = None
    if isinstance(error, PipelineError) and type(error.code) is str and error.code in STOP_MESSAGES:
        code = error.code
    elif isinstance(error, transport.HandoffError):
        # Transport exceptions may contain response-derived values. Only these
        # exact fixed messages and a three-digit HTTP status are admitted.
        message = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else ""
        if len(message) > 256:
            message = ""
        match = re.fullmatch(r"GitHub read failed with HTTP ([1-5][0-9]{2})", message)
        if match:
            code, http_status = "github_read_failed", int(match[1])
        elif message in {"JSON exceeds its transport bound", "JSON contains duplicate keys",
                         "Non-finite JSON", "JSON is malformed"}:
            code = "invalid_json"
        elif message == "Authorization requires authenticated protected main":
            code = "protected_main_unverified"
        else:
            code = "transport_rejected"
    elif isinstance(error, TimeoutError):
        code = "io_timeout"
    elif isinstance(error, OSError):
        code = "io_error"
    result = {"schema": "marty.release-pipeline-stop/v1", "code": code,
              "message": STOP_MESSAGES[code],
              "stage": stage if type(stage) is str and stage in PHASE_MINUTES else "unknown",
              "operation": operation if type(operation) is str and operation in OPERATIONS else "unknown"}
    if transport.positive(child_run_id):
        result["child_run_id"] = child_run_id
    if isinstance(expected_source_sha, str) and transport.SHA.fullmatch(expected_source_sha):
        result["expected_source_sha"] = expected_source_sha
    if code == "source_changed" and isinstance(observed_main_sha, str) and transport.SHA.fullmatch(observed_main_sha):
        result["observed_main_sha"] = observed_main_sha
    if http_status is not None:
        result["http_status"] = http_status
    return result


def report_stop(diagnostic: dict) -> None:
    print("::error title=Release pipeline stopped::" + transport.encoded(diagnostic).decode().rstrip("\n"),
          flush=True)


def image_map(raw: bytes) -> dict[str, str]:
    require(0 < len(raw) <= 8192, "invalid_image_pins")
    pins = transport.decode(raw)
    require(isinstance(pins, dict) and 0 < len(pins) <= 32
            and all(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name)
                    and isinstance(image, str) and IMAGE.fullmatch(image) for name, image in pins.items()),
            "invalid_image_reference")
    return pins


def configuration(channel: str, external_images: str, profile: str, production_web: str,
                  *, root: Path = ROOT) -> dict:
    require(channel in {"nightly", "stable", "both"}, "invalid_channel")
    require(profile in {"tester", "full"} and production_web in {"true", "false"},
            "invalid_release_options")
    require(production_web == "false" or channel in {"stable", "both"},
            "web_requires_stable")
    if channel in {"stable", "both"}:
        defaults_raw = transport.bounded_file(root / "release/external-images.json", maximum=8192)
        defaults = image_map(defaults_raw)
        require(isinstance(external_images, str), "invalid_image_override")
        external_images = external_images or defaults_raw.decode("utf-8")
        pins = image_map(external_images.encode("utf-8"))
        require(set(pins) == set(defaults)
                and all(pins[name].split("@", 1)[0] == defaults[name].split("@", 1)[0] for name in pins),
                "image_roster_changed")
        # The child CD checks the actual rendered Compose model before builds.
        # These defaults remove per-release copying; they do not assert that the
        # images passed this candidate's runtime qualification.
    return {"channel": channel, "external_images": external_images, "profile": profile,
            "production_web": production_web == "true"}


class Pipeline:
    def __init__(self, phase: str, run_id: int, source: str, created_at: str, tag: str, plan: dict,
                 journal: Path, *, github: transport.GitHub | None = None,
                 now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 sleep: Callable[[float], None] = time.sleep) -> None:
        require(phase in PHASE_MINUTES and transport.positive(run_id)
                and isinstance(source, str) and transport.SHA.fullmatch(source)
                and isinstance(tag, str) and transport.TAG.fullmatch(tag), "invalid_pipeline_identity")
        self.phase, self.run_id, self.source, self.tag, self.plan = phase, run_id, source, tag, plan
        self.operation = "create_stage_journal"
        self.child_run_id: int | None = None
        self.observed_main_sha: str | None = None
        self.now, self.sleep = now, sleep
        self.created = transport.timestamp(created_at)
        self.deadline = now() + timedelta(minutes=PHASE_MINUTES[phase])
        self.github = github or transport.GitHub()
        self.github.deadline = self.deadline
        self.record = {"schema": "marty.release-pipeline-stage/v1", "repository": transport.REPOSITORY,
                       "pipeline_run_id": run_id, "pipeline_run_attempt": 1, "source_sha": source,
                       "stage": phase, "channel": plan["channel"], "stable_tag": tag,
                       "not_after": self.deadline.strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "status": "running", "steps": []}
        # A second process cannot replay a stage with an existing journal.
        self.stream = journal.open("xb")
        os.fchmod(self.stream.fileno(), 0o600)
        self.persist()

    def persist(self) -> None:
        self.stream.seek(0)
        self.stream.truncate()
        self.stream.write(transport.encoded(self.record))
        self.stream.flush()
        os.fsync(self.stream.fileno())

    def finish(self, success: bool, outputs: dict | None = None) -> None:
        self.operation = "finalize_stage"
        self.record["status"] = "success" if success else "stopped"
        if outputs is not None:
            self.record["outputs"] = outputs
        self.persist()
        self.stream.close()

    def stop(self, error: Exception) -> None:
        diagnostic = stop_diagnostic(error, self.phase, self.operation, child_run_id=self.child_run_id,
                                     expected_source_sha=self.source, observed_main_sha=self.observed_main_sha)
        self.record["failure"] = diagnostic
        # Preserve the original public diagnosis even if flushing or closing the
        # journal fails. A secondary error must not replace it with a traceback.
        report_stop(diagnostic)
        journal_failed = False
        try:
            self.finish(False)
        except Exception:
            journal_failed = True
        finally:
            try:
                self.stream.close()
            except Exception:
                journal_failed = True
        if journal_failed:
            print("::warning title=Release pipeline journal incomplete::"
                  "The stopped-stage journal could not be finalized. Preserve the preceding error and last saved journal.",
                  flush=True)

    def current(self) -> None:
        self.operation = "check_deadline"
        require(self.now() < self.deadline, "stage_deadline_exceeded")
        self.operation = "check_protected_main"
        self.observed_main_sha = None
        main_sha = self.github.main()["commit"]["sha"]
        if isinstance(main_sha, str) and transport.SHA.fullmatch(main_sha):
            self.observed_main_sha = main_sha
        require(main_sha == self.source, "source_changed")

    def run(self, run_id: int, workflow: str, *, event: str = "workflow_dispatch", title: str | None = None) -> dict:
        self.operation = "read_child_run"
        require(transport.positive(run_id), "invalid_child_run_id")
        self.child_run_id = run_id
        value = self.github.json(f"repos/{transport.REPOSITORY}/actions/runs/{run_id}")
        self.operation = "validate_child_run"
        require(isinstance(value, dict) and type(value.get("id")) is int and value["id"] == run_id
                and value.get("path") == workflow and value.get("event") == event
                and value.get("head_branch") == "main" and value.get("head_sha") == self.source
                and type(value.get("run_attempt")) is int and value["run_attempt"] == 1
                and value.get("repository", {}).get("id") == transport.REPOSITORY_ID
                and value.get("repository", {}).get("full_name") == transport.REPOSITORY,
                "child_identity_mismatch")
        require(self.created <= transport.timestamp(value["created_at"]) <= self.deadline,
                "child_outside_stage_window")
        require(title is None or value.get("display_title") == title,
                "child_title_mismatch")
        return value

    def jobs_succeeded(self, run_id: int, required: set[str]) -> bool:
        self.operation = "read_child_jobs"
        jobs = self.github.pages(f"repos/{transport.REPOSITORY}/actions/runs/{run_id}/attempts/1/jobs", "jobs")
        self.operation = "validate_child_jobs"
        require(jobs and all(type(job.get("run_id")) is int and job["run_id"] == run_id
                            and type(job.get("run_attempt")) is int and job["run_attempt"] == 1
                            and job.get("head_sha") == self.source for job in jobs),
                "child_jobs_mismatch")
        ready = True
        for name in required:
            matching = [job for job in jobs if job.get("name") == name]
            require(len(matching) == 1, "required_job_ambiguous")
            job = matching[0]
            if job.get("status") in ACTIVE and job.get("conclusion") is None:
                ready = False
            else:
                require(job.get("status") == "completed" and job.get("conclusion") == "success",
                        "required_job_failed")
        return ready

    def wait(self, run_id: int, workflow: str, jobs: set[str], *, event: str = "workflow_dispatch",
             title: str | None = None, settle_title: bool = False) -> dict:
        self.child_run_id = run_id if transport.positive(run_id) else None
        title_deadline = (min(self.deadline, self.now() + timedelta(seconds=TITLE_SETTLE_SECONDS))
                          if settle_title and title is not None else None)
        while True:
            self.current()
            run = self.run(run_id, workflow, event=event, title=None if title_deadline is not None else title)
            if title_deadline is not None:
                # A slow read cannot turn an expired grace period into acceptance.
                require(self.now() < title_deadline, "child_title_mismatch")
                # Only the just-acknowledged child may briefly lack its rendered
                # run title. All other identity checks above remain immediate.
                if run.get("display_title") != title:
                    require(self.now() < title_deadline and run.get("status") in ACTIVE
                            and run.get("conclusion") is None, "child_title_mismatch")
                    self.operation = "wait_child"
                    self.sleep(min(15.0, max(0.0, (title_deadline - self.now()).total_seconds())))
                    continue
                title_deadline = None  # Once observed, the exact title must not drift.
            self.operation = "wait_child"
            if run.get("status") == "completed":
                require(run.get("conclusion") == "success", "child_workflow_failed")
                if self.jobs_succeeded(run_id, jobs):
                    return run
            else:
                require(run.get("status") in ACTIVE and run.get("conclusion") is None,
                        "child_state_unknown")
            self.sleep(min(15.0, max(0.0, (self.deadline - self.now()).total_seconds())))

    def dispatch(self, name: str, inputs: dict, *, title: str | None = None) -> int:
        self.operation = "prepare_dispatch"
        self.child_run_id = None
        require(name in DISPATCH and all(step["name"] != name for step in self.record["steps"]),
                "dispatch_already_consumed")
        workflow, keys, jobs = DISPATCH[name]
        require(isinstance(inputs, dict) and set(inputs) == keys, "dispatch_inputs_mismatch")
        self.current()
        endpoint = f"repos/{transport.REPOSITORY}/actions/workflows/{Path(workflow).name}/dispatches"
        payload = {"ref": "main", "inputs": inputs}
        step = {"name": name, "workflow": workflow, "request": payload, "outcome": "unknown"}
        self.record["steps"].append(step)
        self.operation = "record_dispatch_intent"
        self.persist()  # Must precede the one POST, including an uncertain response.
        self.operation = "dispatch_workflow"
        status, raw = self.github.response(endpoint, method="POST", payload=payload)
        if type(status) is int:
            step["http_status"] = status
        step["outcome"] = "response_received"
        self.operation = "record_dispatch_response"
        self.persist()
        self.operation = "validate_dispatch_response"
        require(type(status) is int and status == 200,
                "dispatch_unconfirmed")
        details = transport.decode(raw)
        require(isinstance(details, dict) and transport.positive(details.get("workflow_run_id")),
                "dispatch_missing_identity")
        run_id = details["workflow_run_id"]
        require(details.get("run_url") == f"https://api.github.com/repos/{transport.REPOSITORY}/actions/runs/{run_id}"
                and details.get("html_url") == f"https://github.com/{transport.REPOSITORY}/actions/runs/{run_id}",
                "dispatch_foreign_urls")
        step.update(outcome="dispatch_confirmed", run_id=run_id, run_attempt=1)
        self.child_run_id = run_id
        self.operation = "record_dispatch_acknowledgment"
        self.persist()
        print(transport.encoded({"event": "child_dispatch_confirmed", "stage": self.phase,
                                 "step": name, "workflow": workflow, "run_id": run_id,
                                 "run_attempt": 1}).decode(), end="", flush=True)
        self.wait(run_id, workflow, jobs, title=title, settle_title=True)
        step["outcome"] = "success"
        self.operation = "record_child_success"
        self.persist()
        return run_id

    def stable_publisher(self, candidate: int) -> int:
        self.wait(candidate, DISPATCH["stable-release"][0], DISPATCH["stable-release"][2])
        require(not any(step["name"] == "stable-publisher" for step in self.record["steps"]),
                "dispatch_already_consumed")
        title = f"Publish stable candidate {candidate}"
        self.current()
        self.child_run_id = None
        self.operation = "find_stable_publisher"
        self.persist()
        # Reuse a unique existing automatic continuation, but do not depend on
        # a completion event from a token-dispatched workflow being delivered.
        listing = self.github.json(f"repos/{transport.REPOSITORY}/actions/workflows/{Path(PUBLISHER).name}/runs"
                                   f"?event=workflow_run&head_sha={self.source}&branch=main&per_page=100")
        require(isinstance(listing, dict) and type(listing.get("total_count")) is int
                and 0 <= listing["total_count"] <= 100 and isinstance(listing.get("workflow_runs"), list)
                and len(listing["workflow_runs"]) == listing["total_count"]
                and all(isinstance(run, dict) and transport.positive(run.get("id")) for run in listing["workflow_runs"])
                and len({run["id"] for run in listing["workflow_runs"]}) == listing["total_count"],
                "publisher_listing_invalid")
        matches = [run for run in listing["workflow_runs"] if run.get("display_title") == title]
        require(len(matches) <= 1, "publisher_ambiguous")
        if matches:
            run_id = matches[0]["id"]
            step = {"name": "stable-publisher", "workflow": PUBLISHER, "event": "workflow_run",
                    "candidate_run_id": candidate, "outcome": "observed", "run_id": run_id, "run_attempt": 1}
            self.record["steps"].append(step)
            self.child_run_id = run_id
            self.operation = "record_stable_publisher"
            self.persist()
            self.wait(run_id, PUBLISHER, {"intake", "publish"}, event="workflow_run", title=title)
            step["outcome"] = "success"
            self.operation = "record_child_success"
            self.persist()
            return run_id
        # The existing publisher serializes both supported entry points by tag
        # and authenticates matching ownership/assets if a late automatic run races.
        # Never rediscover or dispatch again after an uncertain acknowledgement.
        return self.dispatch("stable-publisher", {"candidate_run_id": str(candidate)}, title=title)

    def wait_publisher(self, run_id: int, candidate: int) -> dict:
        require(transport.positive(run_id), "invalid_child_run_id")
        run = self.github.json(f"repos/{transport.REPOSITORY}/actions/runs/{run_id}")
        event = run.get("event") if isinstance(run, dict) else None
        require(event in {"workflow_run", "workflow_dispatch"}, "child_identity_mismatch")
        return self.wait(run_id, PUBLISHER, {"intake", "publish"}, event=event,
                         title=f"Publish stable candidate {candidate}")

    def execute(self, *, ci_run_id: int | None = None, stable_run_id: int | None = None,
                publisher_run_id: int | None = None, application_run_id: int | None = None,
                website_run_id: int | None = None) -> dict:
        self.operation = "execute_stage"
        if self.phase == "qualify":
            return {"ci_run_id": self.dispatch("full-ci", {"canvas_migrated_base_pilot": False}), "stable_tag": self.tag}
        self.wait(ci_run_id, DISPATCH["full-ci"][0], DISPATCH["full-ci"][2])
        self.operation = "execute_stage"
        if self.phase == "nightly":
            require(self.plan["channel"] in {"nightly", "both"}, "nightly_not_requested")
            claim = self.dispatch("nightly-claim", {"source_sha": self.source})
            release = self.dispatch("nightly-release", {"claim_run_id": str(claim), "publish_cloudflare_addon": False})
            return {"nightly_claim_run_id": claim, "nightly_run_id": release}
        require(self.plan["channel"] in {"stable", "both"}, "stable_not_requested")
        if self.phase == "stable":
            claim = self.dispatch("stable-claim", {"source_sha": self.source, "tag": self.tag})
            release = self.dispatch("stable-release", {"claim_run_id": str(claim), "publication_contract": "v2",
                                    "selfhost_public_profile": self.plan["profile"], "publish_cloudflare_addon": False,
                                    "selfhost_external_images_json": self.plan["external_images"]})
            return {"stable_claim_run_id": claim, "stable_run_id": release, "stable_tag": self.tag}
        if self.phase == "stable-publish":
            return {"publisher_run_id": self.stable_publisher(stable_run_id)}
        require(self.plan["production_web"], "web_not_requested")
        self.wait(stable_run_id, DISPATCH["stable-release"][0], DISPATCH["stable-release"][2])
        self.wait_publisher(publisher_run_id, stable_run_id)
        if self.phase == "web-application":
            return {"application_run_id": self.dispatch("web-application", {"mode": "combined",
                    "stack_release_tag": self.tag, "expected_source_sha": self.source})}
        if self.phase == "web-website":
            return {"website_run_id": self.dispatch("web-website", {"mode": "website", "expected_source_sha": self.source})}
        self.wait(application_run_id, WEB, {"release"}, title=f"Production web combined from {self.source}")
        self.wait(website_run_id, WEB, {"release"}, title=f"Production web website from {self.source}")
        return {"composition_run_id": self.dispatch("web-compose", {"mode": "compose",
                "application_run_id": str(application_run_id), "application_run_attempt": "1",
                "website_run_id": str(website_run_id), "website_run_attempt": "1",
                "expected_source_sha": self.source})}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=tuple(PHASE_MINUTES))
    parser.add_argument("--journal", type=Path, required=True)
    for name in ("ci-run-id", "stable-run-id", "publisher-run-id", "application-run-id", "website-run-id"):
        parser.add_argument("--" + name, type=int)
    args = parser.parse_args()
    pipeline = None
    source = None
    operation = "validate_context"
    try:
        run_id, source = transport.exact_context(WORKFLOW)
        operation = "validate_checkout"
        require(transport.git("rev-parse", "HEAD^{commit}") == source, "checkout_mismatch")
        operation = "load_configuration"
        plan = configuration(os.environ.get("RELEASE_CHANNEL", ""), os.environ.get("SELFHOST_EXTERNAL_IMAGES_JSON", ""),
                             os.environ.get("SELFHOST_PUBLIC_PROFILE", "full"), os.environ.get("PRODUCTION_WEB", "false"))
        operation = "source_preflight"
        preflight = source_preflight(ROOT, source, require_eligible=True)
        operation = "read_pipeline_run"
        github = transport.GitHub()
        parent = github.run(run_id, WORKFLOW, source)
        require(parent.get("status") == "in_progress", "pipeline_not_running")
        operation = "create_stage_journal"
        pipeline = Pipeline(args.phase, run_id, source, parent["created_at"], "v" + preflight["stack_version"],
                            plan, args.journal, github=github)
        outputs = pipeline.execute(ci_run_id=args.ci_run_id, stable_run_id=args.stable_run_id,
                                   publisher_run_id=args.publisher_run_id, application_run_id=args.application_run_id,
                                   website_run_id=args.website_run_id)
        pipeline.finish(True, outputs)
        pipeline = None
        operation = "write_stage_outputs"
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            for name, value in outputs.items():
                stream.write(f"{name}={value}\n")
        print(transport.encoded(outputs).decode(), end="")
    except (OSError, ValueError, KeyError, TypeError) as error:
        if pipeline is not None:
            pipeline.stop(error)
        else:
            report_stop(stop_diagnostic(error, args.phase, operation, expected_source_sha=source))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
