"""Unattended orchestration controls; all GitHub responses are synthetic."""
from __future__ import annotations

import copy
import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import release_pipeline as pipeline

SOURCE = "a" * 40
PINS = json.dumps({"edge": "docker.io/library/nginx@sha256:" + "b" * 64,
                   "postgres": "docker.io/library/postgres@sha256:" + "c" * 64,
                   "redis": "docker.io/library/redis@sha256:" + "d" * 64})


class FakeGitHub:
    """Independent fixed response fixtures, with no real transport available."""
    def __init__(self) -> None:
        self.source = SOURCE
        self.created = datetime.now(timezone.utc).replace(microsecond=0)
        self.runs: dict[int, dict] = {}
        self.job_names: dict[int, list[str]] = {}
        self.posts: list[tuple[str, dict]] = []
        self.reads: list[str] = []
        self.next_id = 200
        self.after_post = None
        self.lost_response = False
        self.status = 200
        self.bad_details = None
        self.skipped_job = None
        self.main_sha = SOURCE
        self.publisher_ids: list[int] = []

    def add(self, run_id: int, workflow: str, *, event="workflow_dispatch", title=None, jobs=None) -> dict:
        value = {"id": run_id, "path": workflow, "event": event, "head_branch": "main",
                 "head_sha": SOURCE, "run_attempt": 1, "status": "completed", "conclusion": "success",
                 "created_at": self.created.strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "repository": {"id": pipeline.transport.REPOSITORY_ID, "full_name": pipeline.transport.REPOSITORY},
                 "display_title": title or "synthetic"}
        self.runs[run_id] = value
        self.job_names[run_id] = jobs or []
        return value

    def main(self):
        self.reads.append("main")
        return {"commit": {"sha": self.main_sha}}

    def response(self, endpoint: str, *, method: str, payload: dict):
        assert method == "POST"
        assert endpoint.startswith("repos/ElevenID/marty-ui/actions/workflows/")
        assert endpoint.endswith("/dispatches")
        assert set(payload) == {"ref", "inputs"} and payload["ref"] == "main"
        self.posts.append((endpoint, copy.deepcopy(payload)))
        workflow = ".github/workflows/" + endpoint.split("/workflows/", 1)[1].split("/", 1)[0]
        names = {
            ".github/workflows/ci.yml": ["CI Gate"],
            ".github/workflows/prepare-nightly-claim.yml": ["claim"],
            ".github/workflows/prepare-stack-tag.yml": ["Validate exact main and persist the no-write claim"],
            ".github/workflows/nightly-release.yml": ["admit", "prepare-native", "prepare-installation", "runtime-happy-path", "sign-release", "publish"],
            ".github/workflows/cd.yml": ["official-gate-evidence", "qualify-release", "publish-manifest"],
            pipeline.PUBLISHER: ["intake", "publish"],
            ".github/workflows/production-web-release.yml": ["compose" if payload["inputs"].get("mode") == "compose" else "release"],
        }[workflow]
        run_id = self.next_id
        self.next_id += 1
        title = f"Publish stable candidate {payload["inputs"]["candidate_run_id"]}" if workflow == pipeline.PUBLISHER else None
        self.add(run_id, workflow, jobs=names, title=title)
        if self.after_post:
            self.after_post(self.runs[run_id])
        if self.lost_response:
            raise TimeoutError("synthetic acknowledgement lost after server accepted dispatch")
        details = {"workflow_run_id": run_id,
                   "run_url": f"https://api.github.com/repos/ElevenID/marty-ui/actions/runs/{run_id}",
                   "html_url": f"https://github.com/ElevenID/marty-ui/actions/runs/{run_id}"}
        return self.status, pipeline.transport.encoded(self.bad_details if self.bad_details is not None else details)

    def json(self, path: str):
        self.reads.append(path)
        if "/workflows/publish-stable-candidate.yml/runs?" in path:
            return {"total_count": len(self.publisher_ids), "workflow_runs": [self.runs[number] for number in self.publisher_ids]}
        match = re.fullmatch(r"repos/ElevenID/marty-ui/actions/runs/([1-9][0-9]*)", path)
        assert match is not None, path
        return copy.deepcopy(self.runs[int(match[1])])

    def pages(self, path: str, key: str):
        self.reads.append(path)
        assert key == "jobs"
        match = re.fullmatch(r"repos/ElevenID/marty-ui/actions/runs/([1-9][0-9]*)/attempts/1/jobs", path)
        assert match is not None, path
        run_id = int(match[1])
        return [{"id": 10000 + index, "name": name, "run_id": run_id, "run_attempt": 1,
                 "head_sha": SOURCE, "status": "completed", "conclusion": "skipped" if name == self.skipped_job else "success"}
                for index, name in enumerate(self.job_names[run_id])]


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.github = FakeGitHub()
        self.plan = pipeline.configuration("both", PINS, "full", "true")
        self.github.add(50, ".github/workflows/ci.yml", jobs=["CI Gate"])
        self.github.add(60, ".github/workflows/cd.yml", jobs=["official-gate-evidence", "qualify-release", "publish-manifest"])

    def driver(self, phase: str, *, name="journal.json") -> pipeline.Pipeline:
        value = pipeline.Pipeline(phase, 123, SOURCE, self.github.created.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                  "v1.2.3", self.plan, self.root / name, github=self.github)
        self.addCleanup(lambda: None if value.stream.closed else value.stream.close())
        return value

    def run_main(self, *, name="cli-journal.json", context_error=None) -> tuple[int, str, Path]:
        journal = self.root / name
        parent = {"status": "in_progress", "created_at": self.github.created.strftime("%Y-%m-%dT%H:%M:%SZ")}
        output = io.StringIO()
        with mock.patch.object(sys, "argv", ["release_pipeline.py", "qualify", "--journal", str(journal)]), \
                mock.patch.dict(pipeline.os.environ, {"RELEASE_CHANNEL": "both", "SELFHOST_EXTERNAL_IMAGES_JSON": PINS,
                                "SELFHOST_PUBLIC_PROFILE": "full", "PRODUCTION_WEB": "true",
                                "GITHUB_OUTPUT": str(self.root / "outputs")}), \
                mock.patch.object(pipeline.transport, "exact_context", return_value=(123, SOURCE), side_effect=context_error), \
                mock.patch.object(pipeline.transport, "git", return_value=SOURCE), \
                mock.patch.object(pipeline, "source_preflight", return_value={"stack_version": "1.2.3"}), \
                mock.patch.object(pipeline.transport, "GitHub", return_value=self.github), \
                mock.patch.object(self.github, "run", create=True, return_value=parent), redirect_stdout(output):
            status = pipeline.main()
        return status, output.getvalue(), journal

    def test_configuration_refuses_floating_or_incomplete_stable_pins_and_unrequested_web(self) -> None:
        for pins in ("null", "[]", '{"redis":"redis:latest"}',
                     json.dumps({"redis": json.loads(PINS)["redis"]}),
                     json.dumps({**json.loads(PINS), "mail": "docker.io/library/redis@sha256:" + "d" * 64}),
                     json.dumps({**json.loads(PINS), "edge": "docker.io/foreign/nginx@sha256:" + "b" * 64}),
                     '{"edge":"docker.io/library/nginx@sha256:' + "f" * 64 + '","edge":"foreign"}'):
            with self.subTest(pins=pins), self.assertRaises(ValueError):
                pipeline.configuration("stable", pins, "full", "false")
        with self.assertRaises(ValueError):
            pipeline.configuration("nightly", "", "full", "true")
        self.assertEqual(pipeline.configuration("nightly", "", "full", "false")["channel"], "nightly")

    def test_stable_defaults_use_the_source_pins_and_pass_existing_compose_service_validation(self) -> None:
        from scripts import build_selfhost_image_lock as image_lock

        plan = pipeline.configuration("both", "", "full", "false")
        self.assertEqual(plan["external_images"], (ROOT / "release/external-images.json").read_bytes().decode("utf-8"))
        pins = json.loads(plan["external_images"])
        self.assertEqual(set(pins), {"edge", "postgres", "redis"})
        base = ROOT / "docker-compose.selfhost.prod.yml"
        override = ROOT / "docker-compose.selfhost.bundle.override.yml"
        services = image_lock._compose_services(base)
        # Match CD's pre-build shape check; this does not claim image provenance
        # or runtime success and never resolves or pulls an image.
        for name in image_lock.KEYCLOAK_SERVICES:
            services[name]["image"] = image_lock.release_transaction.IMAGE_URIS["keycloak"] + "@sha256:" + "0" * 64
        image_lock.preflight_external_images({"services": services}, pins, base, override)
        self.assertEqual(pipeline.configuration("stable", PINS, "full", "false")["external_images"], PINS)

    def test_missing_or_invalid_source_defaults_fail_before_a_release_request(self) -> None:
        with self.assertRaises((OSError, ValueError)):
            pipeline.configuration("stable", "", "full", "false", root=self.root)
        (self.root / "release").mkdir()
        path = self.root / "release/external-images.json"
        for raw in (b"{}", b"null", b'{"edge":"nginx:latest"}', b"x" * 8193):
            with self.subTest(raw=raw[:40]):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    pipeline.configuration("stable", "", "full", "false", root=self.root)

    def test_full_ci_and_each_claim_producer_use_exact_returned_ids_without_manual_inputs(self) -> None:
        ci = self.driver("qualify", name="ci.json")
        self.assertEqual(ci.execute(), {"ci_run_id": 200, "stable_tag": "v1.2.3"})
        self.assertEqual(self.github.posts[-1][1]["inputs"], {"canvas_migrated_base_pilot": False})
        nightly = self.driver("nightly", name="nightly.json")
        self.assertEqual(nightly.execute(ci_run_id=200), {"nightly_claim_run_id": 201, "nightly_run_id": 202})
        self.assertEqual(self.github.posts[-1][1]["inputs"], {"claim_run_id": "201", "publish_cloudflare_addon": False})
        stable = self.driver("stable", name="stable.json")
        self.assertEqual(stable.execute(ci_run_id=200), {"stable_claim_run_id": 203, "stable_run_id": 204, "stable_tag": "v1.2.3"})
        self.assertEqual(self.github.posts[-1][1]["inputs"], {
            "claim_run_id": "203", "publication_contract": "v2", "selfhost_public_profile": "full",
            "publish_cloudflare_addon": False, "selfhost_external_images_json": PINS})
        self.assertEqual([path.split("/workflows/")[1] for path, _ in self.github.posts],
                         ["ci.yml/dispatches", "prepare-nightly-claim.yml/dispatches", "nightly-release.yml/dispatches",
                          "prepare-stack-tag.yml/dispatches", "cd.yml/dispatches"])

    def test_failed_ci_or_claim_prevents_the_next_producer(self) -> None:
        driver = self.driver("nightly")
        self.github.runs[50]["conclusion"] = "failure"
        with self.assertRaises(ValueError):
            driver.execute(ci_run_id=50)
        self.assertEqual(self.github.posts, [])
        self.github.runs[50]["conclusion"] = "success"
        self.github.after_post = lambda run: run.update(conclusion="failure")
        with self.assertRaises(ValueError):
            driver.execute(ci_run_id=50)
        self.assertEqual(len(self.github.posts), 1)
        self.assertIn("prepare-nightly-claim.yml", self.github.posts[0][0])

    def test_lost_acknowledgement_is_retained_and_never_replayed_or_discovered(self) -> None:
        driver = self.driver("qualify")
        self.github.lost_response = True
        with self.assertRaises(TimeoutError):
            driver.execute()
        saved = json.loads((self.root / "journal.json").read_bytes())
        self.assertEqual(saved["steps"][0]["outcome"], "unknown")
        self.assertNotIn("run_id", saved["steps"][0])
        with self.assertRaisesRegex(ValueError, "already consumed"):
            driver.execute()
        with self.assertRaises(FileExistsError):
            self.driver("qualify")
        self.assertEqual(len(self.github.posts), 1)
        self.assertFalse(any("/actions/runs/" in path for path in self.github.reads))

    def test_legacy_response_permission_failure_and_foreign_run_fail_closed(self) -> None:
        for index, change in enumerate(({"status": 204}, {"status": 403}, {"status": 500},
                                        {"bad_details": {"workflow_run_id": True}},
                                        {"after_post": lambda run: run.update(head_sha="b" * 40)},
                                        {"after_post": lambda run: run.update(path=".github/workflows/foreign.yml")},
                                        {"after_post": lambda run: run.update(run_attempt=2)},
                                        {"after_post": lambda run: run.update(event="push")})):
            with self.subTest(change=list(change)):
                self.github = FakeGitHub()
                for key, value in change.items():
                    setattr(self.github, key, value)
                driver = self.driver("qualify", name=f"invalid-{index}.json")
                with self.assertRaises(ValueError):
                    driver.execute()
                self.assertEqual(len(self.github.posts), 1)

    def publisher(self, number=70, *, event="workflow_run", title="Publish stable candidate 60") -> None:
        self.github.add(number, pipeline.PUBLISHER, event=event, title=title, jobs=["intake", "publish"])
        self.github.publisher_ids.append(number)

    def test_acknowledged_child_waits_for_active_title_convergence(self) -> None:
        driver = self.driver("stable-publish")
        self.publisher(event="workflow_dispatch", title="default workflow title")
        child = self.github.runs[70]
        child.update(status="queued", conclusion=None)
        sleeps = []
        def advance(seconds):
            sleeps.append(seconds)
            child.update(status="completed", conclusion="success", display_title="Publish stable candidate 60")
        driver.sleep = advance
        run = driver.wait(70, pipeline.PUBLISHER, {"intake", "publish"},
                          title="Publish stable candidate 60")
        self.assertEqual(run["id"], 70)
        self.assertEqual(len(sleeps), 1)
        self.assertEqual(self.github.posts, [])

    def test_wrong_terminal_title_stops_without_wait_or_dispatch(self) -> None:
        driver = self.driver("stable-publish")
        self.publisher(event="workflow_dispatch", title="Publish stable candidate 61")
        driver.sleep = mock.Mock(side_effect=AssertionError("must not wait"))
        with self.assertRaises(pipeline.PipelineError) as caught:
            driver.wait(70, pipeline.PUBLISHER, {"intake", "publish"},
                        title="Publish stable candidate 60")
        self.assertEqual(caught.exception.code, "child_title_mismatch")
        self.assertEqual(self.github.posts, [])

    def test_pending_title_does_not_extend_deadline_or_relax_child_identity(self) -> None:
        for mutation in (None, "head_sha", "run_attempt", "path", "event"):
            with self.subTest(mutation=mutation):
                driver = self.driver("stable-publish", name=f"title-{mutation}.json")
                self.publisher(event="workflow_dispatch", title="default workflow title")
                child = self.github.runs[70]
                child.update(status="in_progress", conclusion=None)
                if mutation is not None:
                    child[mutation] = 2 if mutation == "run_attempt" else "foreign"
                clock = [driver.deadline - timedelta(seconds=1)]
                driver.now = lambda: clock[0]
                driver.sleep = lambda seconds: clock.__setitem__(0, clock[0] + timedelta(seconds=seconds))
                expected = "stage_deadline_exceeded" if mutation is None else "child_identity_mismatch"
                with self.assertRaises(pipeline.PipelineError) as caught:
                    driver.wait(70, pipeline.PUBLISHER, {"intake", "publish"},
                                title="Publish stable candidate 60")
                self.assertEqual(caught.exception.code, expected)
                self.assertEqual(self.github.posts, [])

    def test_automatic_publisher_is_observed_without_any_second_dispatch(self) -> None:
        self.publisher()
        driver = self.driver("stable-publish")
        self.assertEqual(driver.execute(ci_run_id=50, stable_run_id=60), {"publisher_run_id": 70})
        self.assertEqual(self.github.posts, [])
        self.assertEqual(driver.record["steps"][0]["candidate_run_id"], 60)

    def test_absent_automatic_publisher_uses_one_exact_existing_publisher_dispatch(self) -> None:
        driver = self.driver("stable-publish")
        self.assertEqual(driver.execute(ci_run_id=50, stable_run_id=60), {"publisher_run_id": 200})
        self.assertEqual(self.github.posts, [("repos/ElevenID/marty-ui/actions/workflows/publish-stable-candidate.yml/dispatches",
                                             {"ref": "main", "inputs": {"candidate_run_id": "60"}})])
        self.assertEqual(driver.record["steps"][0]["run_id"], 200)

    def test_publisher_dispatch_never_substitutes_a_late_automatic_run(self) -> None:
        self.github.after_post = lambda _run: self.publisher()
        driver = self.driver("stable-publish")
        self.assertEqual(driver.execute(ci_run_id=50, stable_run_id=60), {"publisher_run_id": 200})
        self.assertEqual(len(self.github.posts), 1)
        self.assertEqual(driver.record["steps"][0]["run_id"], 200)

    def test_ambiguous_observed_publishers_refuse_without_dispatch(self) -> None:
        self.publisher()
        self.publisher(71)
        with self.assertRaises(ValueError):
            self.driver("stable-publish").execute(ci_run_id=50, stable_run_id=60)
        self.assertEqual(self.github.posts, [])

    def test_publisher_wrong_identity_skipped_or_failed_cannot_continue(self) -> None:
        for index, changes in enumerate(({"event": "workflow_run"}, {"head_sha": "b" * 40},
                                         {"run_attempt": 2}, {"display_title": "Publish stable candidate 61"},
                                         {"conclusion": "failure"}, {"skip": True})):
            with self.subTest(changes=changes):
                self.github.posts.clear()
                self.github.after_post = lambda run: run.update({k: v for k, v in changes.items() if k != "skip"})
                self.github.skipped_job = "publish" if changes.get("skip") else None
                with self.assertRaises(ValueError):
                    self.driver("stable-publish", name=f"publisher-invalid-{index}.json").execute(ci_run_id=50, stable_run_id=60)
                self.assertEqual(len(self.github.posts), 1)

    def test_uncertain_publisher_acknowledgment_never_replays_or_rediscovers(self) -> None:
        driver = self.driver("stable-publish")
        self.github.lost_response = True
        with self.assertRaises(TimeoutError):
            driver.execute(ci_run_id=50, stable_run_id=60)
        saved = json.loads((self.root / "journal.json").read_bytes())
        self.assertEqual(saved["steps"][0]["outcome"], "unknown")
        self.assertNotIn("run_id", saved["steps"][0])
        listings = sum("/workflows/publish-stable-candidate.yml/runs?" in path for path in self.github.reads)
        with self.assertRaisesRegex(ValueError, "already consumed"):
            driver.execute(ci_run_id=50, stable_run_id=60)
        self.assertEqual(len(self.github.posts), 1)
        self.assertEqual(listings, sum("/workflows/publish-stable-candidate.yml/runs?" in path for path in self.github.reads))

    def test_web_continuation_admits_the_exact_dispatched_publisher(self) -> None:
        self.publisher(event="workflow_dispatch")
        output = self.driver("web-application").execute(ci_run_id=50, stable_run_id=60, publisher_run_id=70)
        self.assertEqual(output, {"application_run_id": 200})
        self.assertEqual(self.github.posts[0][1]["inputs"]["mode"], "combined")

    def test_main_drift_and_stage_deadline_cannot_select_new_source_or_extend_a_wait(self) -> None:
        driver = self.driver("qualify")
        self.github.main_sha = "b" * 40
        with self.assertRaises(ValueError):
            driver.execute()
        self.assertEqual(self.github.posts, [])
        self.github.main_sha = SOURCE
        original_deadline = driver.deadline
        driver.now = lambda: original_deadline
        with self.assertRaises(ValueError):
            driver.execute()
        self.assertEqual(driver.deadline, original_deadline)
        self.assertEqual(self.github.posts, [])

    def test_main_drift_after_acknowledgment_retains_the_original_child_and_specific_stop(self) -> None:
        driver = self.driver("qualify")
        deadline = driver.deadline
        journal = self.root / "journal.json"
        self.github.after_post = lambda run: run.update(status="in_progress", conclusion=None)
        output = io.StringIO()
        fsynced_steps = []
        actual_fsync, actual_print = pipeline.os.fsync, print

        def sync(fd):
            actual_fsync(fd)
            fsynced_steps.append(json.loads(journal.read_bytes())["steps"][-1])

        def print_after_sync(*args, **kwargs):
            if args and '"event":"child_dispatch_confirmed"' in args[0]:
                self.assertEqual(fsynced_steps[-1]["outcome"], "dispatch_confirmed")
                self.assertEqual(fsynced_steps[-1]["run_id"], 200)
                self.assertEqual(fsynced_steps[-1]["run_attempt"], 1)
            actual_print(*args, **kwargs)

        def advance_main(_seconds):
            # The child is still running. Its acknowledgment must already be
            # visible, rather than waiting for the final stage artifact.
            acknowledgment = json.loads(output.getvalue().splitlines()[0])
            self.assertEqual(acknowledgment["run_id"], 200)
            self.github.main_sha = "b" * 40

        driver.sleep = advance_main
        with redirect_stdout(output), mock.patch.object(pipeline.os, "fsync", side_effect=sync), \
                mock.patch("builtins.print", side_effect=print_after_sync):
            with self.assertRaises(pipeline.PipelineError) as caught:
                driver.execute()
            driver.stop(caught.exception)

        saved = json.loads(journal.read_bytes())
        self.assertEqual(saved["status"], "stopped")
        self.assertEqual(saved["source_sha"], SOURCE)
        self.assertEqual(saved["steps"][0]["outcome"], "dispatch_confirmed")
        self.assertEqual(saved["steps"][0]["run_id"], 200)
        self.assertEqual(saved["failure"], {
            "schema": "marty.release-pipeline-stop/v1", "code": "source_changed",
            "message": "Protected main changed; this release request cannot select new source",
            "stage": "qualify", "operation": "check_protected_main", "child_run_id": 200,
            "expected_source_sha": SOURCE, "observed_main_sha": "b" * 40,
        })
        lines = output.getvalue().splitlines()
        self.assertEqual(json.loads(lines[0])["event"], "child_dispatch_confirmed")
        self.assertEqual(json.loads(lines[1].split("::", 2)[2]), saved["failure"])
        self.assertEqual(len(self.github.posts), 1)
        self.assertEqual(driver.deadline, deadline)

    def test_invalid_or_lost_dispatch_acknowledgments_never_report_or_repeat_a_child(self) -> None:
        private = "ghp_synthetic_secret\n::error::injected https://example.invalid/?sig=private"
        cases = ("lost", "malformed-json", "missing-id", "foreign-urls", "http-refusal")
        for case in cases:
            with self.subTest(case=case):
                self.github = FakeGitHub()
                original_response = self.github.response

                def response(endpoint, *, method, payload):
                    status, raw = original_response(endpoint, method=method, payload=payload)
                    if case == "lost":
                        raise TimeoutError(private)
                    if case == "malformed-json":
                        return status, private.encode()
                    if case == "missing-id":
                        return status, pipeline.transport.encoded({"message": private})
                    if case == "foreign-urls":
                        return status, pipeline.transport.encoded({"workflow_run_id": 200,
                                      "run_url": private, "html_url": private})
                    return 403, private.encode()

                self.github.response = response
                status, output, journal = self.run_main(name=f"stopped-{case}.json")
                saved = json.loads(journal.read_bytes())
                self.assertEqual(status, 1)
                self.assertEqual(len(self.github.posts), 1)
                self.assertNotIn("child_dispatch_confirmed", output)
                self.assertNotIn("child_run_id", saved["failure"])
                self.assertNotIn("run_id", saved["steps"][0])
                self.assertNotIn(private, output)
                self.assertNotIn("ghp_synthetic_secret", output)
                self.assertNotIn("example.invalid", output)
                self.assertNotIn("ghp_synthetic_secret", journal.read_text())
                self.assertEqual(saved["steps"][0]["outcome"], "unknown" if case == "lost" else "response_received")
                self.assertEqual(saved["failure"]["code"], {
                    "lost": "io_timeout", "malformed-json": "invalid_json", "missing-id": "dispatch_missing_identity",
                    "foreign-urls": "dispatch_foreign_urls", "http-refusal": "dispatch_unconfirmed",
                }[case])
                self.assertEqual(saved["failure"]["operation"],
                                 "dispatch_workflow" if case == "lost" else "validate_dispatch_response")
                self.assertEqual(saved["status"], "stopped")

    def test_original_stop_is_reported_when_journal_finalization_also_fails(self) -> None:
        private = "https://example.invalid/private?sig=do-not-print"
        for error in (OSError(private), RuntimeError(private)):
            with self.subTest(error=type(error).__name__):
                self.github = FakeGitHub()
                self.github.after_post = lambda _run: setattr(self.github, "main_sha", "b" * 40)
                with mock.patch.object(pipeline.Pipeline, "finish", side_effect=error) as finish:
                    status, output, journal = self.run_main(name=f"unfinished-{type(error).__name__}.json")
                finish.assert_called_once_with(False)
                self.assertEqual(status, 1)
                lines = output.splitlines()
                self.assertEqual(json.loads(lines[0])["event"], "child_dispatch_confirmed")
                diagnostic = json.loads(lines[1].split("::", 2)[2])
                self.assertEqual(diagnostic["code"], "source_changed")
                self.assertEqual(diagnostic["child_run_id"], 200)
                self.assertIn("::warning title=Release pipeline journal incomplete::", lines[2])
                self.assertNotIn(private, output)
                self.assertNotIn("Traceback", output)
                self.assertEqual(len(self.github.posts), 1)
                self.assertEqual(json.loads(journal.read_bytes())["steps"][0]["outcome"], "dispatch_confirmed")

    def test_failure_before_journal_creation_has_a_bounded_safe_annotation(self) -> None:
        private = "ghp_synthetic_secret\n::error::injected https://example.invalid/?sig=private"
        status, output, journal = self.run_main(context_error=ValueError(private))
        self.assertEqual(status, 1)
        self.assertFalse(journal.exists())
        self.assertEqual(self.github.posts, [])
        self.assertNotIn(private, output)
        self.assertNotIn("ghp_synthetic_secret", output)
        self.assertNotIn("example.invalid", output)
        diagnostic = json.loads(output.strip().split("::", 2)[2])
        self.assertEqual(diagnostic["code"], "invalid_data")
        self.assertEqual(diagnostic["operation"], "validate_context")
        self.assertNotIn("expected_source_sha", diagnostic)
        self.assertLess(len(output), 1024)

    def test_diagnostics_admit_only_fixed_messages_and_bounded_public_fields(self) -> None:
        private = "private-token\n::error::injected https://example.invalid/?sig=" + "x" * 10000
        errors = (ValueError(private), OSError(private), TimeoutError(private),
                  pipeline.transport.HandoffError(private), KeyError({"secret": private}))
        for error in errors:
            with self.subTest(error=type(error).__name__):
                diagnostic = pipeline.stop_diagnostic(error, private, private, child_run_id=True,
                                                      expected_source_sha=private, observed_main_sha=private)
                raw = pipeline.transport.encoded(diagnostic)
                self.assertLess(len(raw), 1024)
                self.assertEqual(set(diagnostic), {"schema", "code", "message", "stage", "operation"})
                self.assertEqual(diagnostic["stage"], "unknown")
                self.assertEqual(diagnostic["operation"], "unknown")
                self.assertNotIn(b"private-token", raw)
                self.assertNotIn(b"https://", raw)
        for code in pipeline.STOP_MESSAGES:
            error = pipeline.PipelineError(code)
            error.args = (private,)
            diagnostic = pipeline.stop_diagnostic(error, "qualify", "check_protected_main", child_run_id=200,
                                                  expected_source_sha=SOURCE, observed_main_sha="b" * 40)
            self.assertEqual(diagnostic["code"], code)
            self.assertEqual(diagnostic["message"], pipeline.STOP_MESSAGES[code])
            self.assertLess(len(pipeline.transport.encoded(diagnostic)), 1024)
        diagnostic = pipeline.stop_diagnostic(pipeline.transport.HandoffError("GitHub read failed with HTTP 503"),
                                              "qualify", "read_child_run", child_run_id=200)
        self.assertEqual(diagnostic["code"], "github_read_failed")
        self.assertEqual(diagnostic["http_status"], 503)

    def test_web_composition_uses_exact_original_producer_ids_and_attempts(self) -> None:
        self.publisher()
        self.github.add(80, pipeline.WEB, title=f"Production web combined from {SOURCE}", jobs=["release"])
        self.github.add(81, pipeline.WEB, title=f"Production web website from {SOURCE}", jobs=["release"])
        driver = self.driver("web-compose")
        self.assertEqual(driver.execute(ci_run_id=50, stable_run_id=60, publisher_run_id=70,
                                        application_run_id=80, website_run_id=81), {"composition_run_id": 200})
        self.assertEqual(self.github.posts[0][1]["inputs"], {"mode": "compose", "application_run_id": "80",
                         "application_run_attempt": "1", "website_run_id": "81", "website_run_attempt": "1",
                         "expected_source_sha": SOURCE})

    def test_every_web_dispatch_binds_the_child_before_a_main_advance_can_select_new_source(self) -> None:
        for phase in ("web-application", "web-website", "web-compose"):
            with self.subTest(phase=phase):
                self.github = FakeGitHub()
                self.github.add(50, ".github/workflows/ci.yml", jobs=["CI Gate"])
                self.github.add(60, ".github/workflows/cd.yml", jobs=["official-gate-evidence", "qualify-release", "publish-manifest"])
                self.publisher()
                self.github.add(80, pipeline.WEB, title=f"Production web combined from {SOURCE}", jobs=["release"])
                self.github.add(81, pipeline.WEB, title=f"Production web website from {SOURCE}", jobs=["release"])
                # main can advance after current() but before GitHub resolves
                # ref=main. The child receives S before it starts, and its own
                # initial source guard can reject S2 before any publication.
                self.github.after_post = lambda run: run.update(head_sha="b" * 40, conclusion="failure")
                driver = self.driver(phase, name=f"source-race-{phase}.json")
                with self.assertRaises(ValueError):
                    driver.execute(ci_run_id=50, stable_run_id=60, publisher_run_id=70,
                                   application_run_id=80, website_run_id=81)
                self.assertEqual(len(self.github.posts), 1)
                self.assertEqual(self.github.posts[0][1]["inputs"]["expected_source_sha"], SOURCE)

    def test_wrong_web_mode_cannot_be_composed(self) -> None:
        self.publisher()
        self.github.add(80, pipeline.WEB, title=f"Production web website from {SOURCE}", jobs=["release"])
        self.github.add(81, pipeline.WEB, title=f"Production web website from {SOURCE}", jobs=["release"])
        driver = self.driver("web-compose")
        with self.assertRaises(ValueError):
            driver.execute(ci_run_id=50, stable_run_id=60, publisher_run_id=70, application_run_id=80, website_run_id=81)
        self.assertEqual(self.github.posts, [])


class WorkflowContractTests(unittest.TestCase):
    def load(self, relative: str) -> dict:
        return yaml.load((ROOT / relative).read_text(), Loader=yaml.BaseLoader)

    def test_only_orchestration_permissions_and_bounded_jobs_are_added(self) -> None:
        workflow = self.load(pipeline.WORKFLOW)
        self.assertEqual(set(workflow["on"]), {"workflow_dispatch"})
        self.assertEqual(workflow["permissions"], {})
        self.assertEqual(workflow["concurrency"]["cancel-in-progress"], "false")
        self.assertEqual(set(workflow["jobs"]), {"full-ci", "nightly", "stable", "stable-publish",
                                                "web-application", "web-website", "web-compose"})
        for name, job in workflow["jobs"].items():
            with self.subTest(job=name):
                self.assertLess(int(job["timeout-minutes"]), 360)
                self.assertEqual(job["permissions"], {"contents": "read", "actions": "write"})
                uploads = [step for step in job["steps"] if step.get("uses", "").startswith("actions/upload-artifact@")]
                self.assertEqual(len(uploads), 1)
                self.assertEqual(uploads[0]["if"], "always()")
                checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
                self.assertEqual(checkout["with"]["ref"], "${{ github.sha }}")
                self.assertEqual(checkout["with"]["persist-credentials"], "false")

    def test_declared_child_inputs_and_required_jobs_match_the_actual_workflows(self) -> None:
        for name, (path, keys, required_jobs) in pipeline.DISPATCH.items():
            with self.subTest(stage=name):
                workflow = self.load(path)
                self.assertTrue(keys <= set(workflow["on"]["workflow_dispatch"]["inputs"]))
                actual = {job.get("name", key) for key, job in workflow["jobs"].items()}
                self.assertTrue(required_jobs <= actual, (name, required_jobs - actual))
        publisher = self.load(pipeline.PUBLISHER)
        self.assertEqual(publisher["run-name"], "Publish stable candidate ${{ inputs.candidate_run_id || github.event.workflow_run.id }}")
        self.assertEqual(publisher["on"]["workflow_run"], {"workflows": ["Stack release"], "branches": ["main"], "types": ["completed"]})
        self.assertEqual(set(publisher["jobs"]), {"intake", "publish"})


if __name__ == "__main__":
    unittest.main()
