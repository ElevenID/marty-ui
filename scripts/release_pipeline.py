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
    "web-application": (WEB, {"mode", "stack_release_tag", "expected_source_sha"}, {"release"}),
    "web-website": (WEB, {"mode", "expected_source_sha"}, {"release"}),
    "web-compose": (WEB, {"mode", "website_run_id", "website_run_attempt", "application_run_id",
                          "application_run_attempt", "expected_source_sha"}, {"compose"}),
}
ACTIVE = {"queued", "in_progress", "waiting", "pending", "requested"}
IMAGE = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}\Z")
require = transport.require


def image_map(raw: bytes) -> dict[str, str]:
    require(0 < len(raw) <= 8192, "Stable release requires bounded external image pins")
    pins = transport.decode(raw)
    require(isinstance(pins, dict) and 0 < len(pins) <= 32
            and all(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name)
                    and isinstance(image, str) and IMAGE.fullmatch(image) for name, image in pins.items()),
            "Every external image must be an exact registry/repository@sha256 reference")
    return pins


def configuration(channel: str, external_images: str, profile: str, production_web: str,
                  *, root: Path = ROOT) -> dict:
    require(channel in {"nightly", "stable", "both"}, "Select nightly, stable or both")
    require(profile in {"tester", "full"} and production_web in {"true", "false"},
            "Release profile or production-web selection is invalid")
    require(production_web == "false" or channel in {"stable", "both"},
            "Production web requires the stable release in this request")
    if channel in {"stable", "both"}:
        defaults_raw = transport.bounded_file(root / "release/external-images.json", maximum=8192)
        defaults = image_map(defaults_raw)
        require(isinstance(external_images, str), "External image override must be JSON text")
        external_images = external_images or defaults_raw.decode("utf-8")
        pins = image_map(external_images.encode("utf-8"))
        require(set(pins) == set(defaults)
                and all(pins[name].split("@", 1)[0] == defaults[name].split("@", 1)[0] for name in pins),
                "External image override must preserve the source-controlled service and repository roster")
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
                and isinstance(tag, str) and transport.TAG.fullmatch(tag), "Invalid release pipeline identity")
        self.phase, self.run_id, self.source, self.tag, self.plan = phase, run_id, source, tag, plan
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
        self.record["status"] = "success" if success else "stopped"
        if outputs is not None:
            self.record["outputs"] = outputs
        self.persist()
        self.stream.close()

    def current(self) -> None:
        require(self.now() < self.deadline, "Release pipeline stage exceeded its fixed deadline")
        require(self.github.main()["commit"]["sha"] == self.source,
                "Protected main changed; this release request cannot select new source")

    def run(self, run_id: int, workflow: str, *, event: str = "workflow_dispatch", title: str | None = None) -> dict:
        require(transport.positive(run_id), "A positive exact workflow run ID is required")
        value = self.github.json(f"repos/{transport.REPOSITORY}/actions/runs/{run_id}")
        require(isinstance(value, dict) and type(value.get("id")) is int and value["id"] == run_id
                and value.get("path") == workflow and value.get("event") == event
                and value.get("head_branch") == "main" and value.get("head_sha") == self.source
                and type(value.get("run_attempt")) is int and value["run_attempt"] == 1
                and value.get("repository", {}).get("id") == transport.REPOSITORY_ID
                and value.get("repository", {}).get("full_name") == transport.REPOSITORY,
                "Child run differs from the exact original workflow, source or attempt")
        require(self.created <= transport.timestamp(value["created_at"]) <= self.deadline,
                "Child run predates this release request or exceeds its stage window")
        require(title is None or value.get("display_title") == title,
                "Child run belongs to another automatic continuation or web mode")
        return value

    def jobs_succeeded(self, run_id: int, required: set[str]) -> bool:
        jobs = self.github.pages(f"repos/{transport.REPOSITORY}/actions/runs/{run_id}/attempts/1/jobs", "jobs")
        require(jobs and all(type(job.get("run_id")) is int and job["run_id"] == run_id
                            and type(job.get("run_attempt")) is int and job["run_attempt"] == 1
                            and job.get("head_sha") == self.source for job in jobs),
                "Child job evidence belongs to another invocation")
        ready = True
        for name in required:
            matching = [job for job in jobs if job.get("name") == name]
            require(len(matching) == 1, "Required release job is missing or ambiguous")
            job = matching[0]
            if job.get("status") in ACTIVE and job.get("conclusion") is None:
                ready = False
            else:
                require(job.get("status") == "completed" and job.get("conclusion") == "success",
                        "Required release job failed or was skipped")
        return ready

    def wait(self, run_id: int, workflow: str, jobs: set[str], *, event: str = "workflow_dispatch",
             title: str | None = None) -> dict:
        while True:
            self.current()
            run = self.run(run_id, workflow, event=event, title=title)
            if run.get("status") == "completed":
                require(run.get("conclusion") == "success", "Original child workflow did not succeed")
                if self.jobs_succeeded(run_id, jobs):
                    return run
            else:
                require(run.get("status") in ACTIVE and run.get("conclusion") is None,
                        "Child workflow has an unknown state")
            self.sleep(min(15.0, max(0.0, (self.deadline - self.now()).total_seconds())))

    def dispatch(self, name: str, inputs: dict) -> int:
        require(name in DISPATCH and all(step["name"] != name for step in self.record["steps"]),
                "Release stage has already consumed this dispatch")
        workflow, keys, jobs = DISPATCH[name]
        require(isinstance(inputs, dict) and set(inputs) == keys, "Release dispatch inputs differ from their fixed stage")
        self.current()
        endpoint = f"repos/{transport.REPOSITORY}/actions/workflows/{Path(workflow).name}/dispatches"
        payload = {"ref": "main", "inputs": inputs}
        step = {"name": name, "workflow": workflow, "request": payload, "outcome": "unknown"}
        self.record["steps"].append(step)
        self.persist()  # Must precede the one POST, including an uncertain response.
        status, raw = self.github.response(endpoint, method="POST", payload=payload)
        if type(status) is int:
            step["http_status"] = status
        step["outcome"] = "response_received"
        self.persist()
        require(type(status) is int and status == 200,
                "Workflow dispatch was not confirmed by the current API; do not retry")
        details = transport.decode(raw)
        require(isinstance(details, dict) and transport.positive(details.get("workflow_run_id")),
                "Workflow dispatch returned no exact run ID; do not search for a substitute")
        run_id = details["workflow_run_id"]
        require(details.get("run_url") == f"https://api.github.com/repos/{transport.REPOSITORY}/actions/runs/{run_id}"
                and details.get("html_url") == f"https://github.com/{transport.REPOSITORY}/actions/runs/{run_id}",
                "Workflow dispatch returned foreign run URLs")
        step.update(outcome="dispatch_confirmed", run_id=run_id, run_attempt=1)
        self.persist()
        self.wait(run_id, workflow, jobs)
        step["outcome"] = "success"
        self.persist()
        return run_id

    def stable_publisher(self, candidate: int) -> int:
        self.wait(candidate, DISPATCH["stable-release"][0], DISPATCH["stable-release"][2])
        title = f"Publish stable candidate {candidate}"
        step = {"name": "stable-publisher", "workflow": PUBLISHER, "event": "workflow_run",
                "candidate_run_id": candidate, "outcome": "waiting"}
        self.record["steps"].append(step)
        self.persist()
        while True:
            self.current()
            listing = self.github.json(f"repos/{transport.REPOSITORY}/actions/workflows/{Path(PUBLISHER).name}/runs"
                                       f"?event=workflow_run&head_sha={self.source}&branch=main&per_page=100")
            require(isinstance(listing, dict) and type(listing.get("total_count")) is int
                    and 0 <= listing["total_count"] <= 100 and isinstance(listing.get("workflow_runs"), list)
                    and len(listing["workflow_runs"]) == listing["total_count"]
                    and all(isinstance(run, dict) and transport.positive(run.get("id")) for run in listing["workflow_runs"])
                    and len({run["id"] for run in listing["workflow_runs"]}) == listing["total_count"],
                    "Automatic publisher listing is incomplete or ambiguous")
            matches = [run for run in listing["workflow_runs"] if run.get("display_title") == title]
            require(len(matches) <= 1, "More than one automatic publisher claims this original candidate")
            if matches:
                run_id = matches[0]["id"]
                step.update(run_id=run_id, run_attempt=1, outcome="observed")
                self.persist()
                self.wait(run_id, PUBLISHER, {"intake", "publish"}, event="workflow_run", title=title)
                step["outcome"] = "success"
                self.persist()
                return run_id
            self.sleep(min(15.0, max(0.0, (self.deadline - self.now()).total_seconds())))

    def execute(self, *, ci_run_id: int | None = None, stable_run_id: int | None = None,
                publisher_run_id: int | None = None, application_run_id: int | None = None,
                website_run_id: int | None = None) -> dict:
        if self.phase == "qualify":
            return {"ci_run_id": self.dispatch("full-ci", {"canvas_migrated_base_pilot": False}), "stable_tag": self.tag}
        self.wait(ci_run_id, DISPATCH["full-ci"][0], DISPATCH["full-ci"][2])
        if self.phase == "nightly":
            require(self.plan["channel"] in {"nightly", "both"}, "Nightly was not requested")
            claim = self.dispatch("nightly-claim", {"source_sha": self.source})
            release = self.dispatch("nightly-release", {"claim_run_id": str(claim), "publish_cloudflare_addon": False})
            return {"nightly_claim_run_id": claim, "nightly_run_id": release}
        require(self.plan["channel"] in {"stable", "both"}, "Stable was not requested")
        if self.phase == "stable":
            claim = self.dispatch("stable-claim", {"source_sha": self.source, "tag": self.tag})
            release = self.dispatch("stable-release", {"claim_run_id": str(claim), "publication_contract": "v2",
                                    "selfhost_public_profile": self.plan["profile"], "publish_cloudflare_addon": False,
                                    "selfhost_external_images_json": self.plan["external_images"]})
            return {"stable_claim_run_id": claim, "stable_run_id": release, "stable_tag": self.tag}
        if self.phase == "stable-publish":
            return {"publisher_run_id": self.stable_publisher(stable_run_id)}
        require(self.plan["production_web"], "Production web was not requested")
        self.wait(stable_run_id, DISPATCH["stable-release"][0], DISPATCH["stable-release"][2])
        self.wait(publisher_run_id, PUBLISHER, {"intake", "publish"}, event="workflow_run",
                  title=f"Publish stable candidate {stable_run_id}")
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
    try:
        run_id, source = transport.exact_context(WORKFLOW)
        require(transport.git("rev-parse", "HEAD^{commit}") == source, "Pipeline checkout differs from its exact source")
        plan = configuration(os.environ.get("RELEASE_CHANNEL", ""), os.environ.get("SELFHOST_EXTERNAL_IMAGES_JSON", ""),
                             os.environ.get("SELFHOST_PUBLIC_PROFILE", "full"), os.environ.get("PRODUCTION_WEB", "false"))
        preflight = source_preflight(ROOT, source, require_eligible=True)
        github = transport.GitHub()
        parent = github.run(run_id, WORKFLOW, source)
        require(parent.get("status") == "in_progress", "Original release pipeline is not running")
        pipeline = Pipeline(args.phase, run_id, source, parent["created_at"], "v" + preflight["stack_version"],
                            plan, args.journal, github=github)
        outputs = pipeline.execute(ci_run_id=args.ci_run_id, stable_run_id=args.stable_run_id,
                                   publisher_run_id=args.publisher_run_id, application_run_id=args.application_run_id,
                                   website_run_id=args.website_run_id)
        pipeline.finish(True, outputs)
        pipeline = None
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            for name, value in outputs.items():
                stream.write(f"{name}={value}\n")
        print(transport.encoded(outputs).decode(), end="")
    except (OSError, ValueError, KeyError, TypeError):
        if pipeline is not None:
            pipeline.finish(False)
        print("Release pipeline stopped; preserve its journal and original child runs. No dispatch was retried.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
