"""Focused source-input admission coverage for the AWS diagnostic runner."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("split_web_aws", ROOT / "scripts/qualify_split_web_aws.py")
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class WebsiteStageIdentityTests(unittest.TestCase):
    def test_development_tests_do_not_inherit_the_production_revision(self):
        plan = {stage["name"]: stage for stage in runner.stages(
            (Path("/source/marty"), Path("/source/website"), Path("/home/marty/q/e")), {})}
        self.assertNotIn("MARTY_WEBSITE_SOURCE_SHA", plan["website-tests"]["environment"])
        self.assertEqual(plan["website-development-build"]["environment"]["MARTY_WEBSITE_SOURCE_SHA"], "development")
        for name in ("website-production-prerender", "website-image", "website-image-nginx",
                     "website-finalize", "website-release-plan"):
            with self.subTest(stage=name):
                self.assertEqual(plan[name]["environment"]["MARTY_WEBSITE_SOURCE_SHA"], runner.WEBSITE_SHA)


class DotenvAdmissionTests(unittest.TestCase):
    def test_exact_baseline_is_admitted_and_other_dotenv_inputs_are_refused(self):
        # The real tracked b109 inputs previously made every AWS preflight fail.
        runner.validate_dotenv_inputs(ROOT, runner.MARTY_REVIEWED_DOTENV)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ui").mkdir()
            for relative in runner.MARTY_REVIEWED_DOTENV:
                shutil.copyfile(ROOT / relative, root / relative)
            runner.validate_dotenv_inputs(root, runner.MARTY_REVIEWED_DOTENV)
            for relative in (".env", ".env.local", "ui/.env.local", "ui/.env.production"):
                with self.subTest(unreviewed=relative):
                    candidate = root / relative
                    candidate.write_text("VITE_API_URL=https://unreviewed.invalid\n")
                    with self.assertRaisesRegex(ValueError, "not an admitted test input"):
                        runner.validate_dotenv_inputs(root, runner.MARTY_REVIEWED_DOTENV)
                    candidate.unlink()
            with self.assertRaisesRegex(ValueError, "not an admitted test input"):
                runner.validate_dotenv_inputs(root, {})
            (root / "ui/.env.test").write_text("VITE_API_URL=https://changed.invalid\n")
            with self.assertRaisesRegex(ValueError, "Reviewed dotenv input bytes differ"):
                runner.validate_dotenv_inputs(root, runner.MARTY_REVIEWED_DOTENV)


class TrackedModeAdmissionTests(unittest.TestCase):
    def test_exact_git_modes_pass_and_umask_variants_fail_without_chmod(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "LICENSE"
            executable = root / "entry.sh"
            source.write_text("fixture license\n")
            executable.write_text("#!/bin/sh\n")
            source.chmod(0o644)
            executable.chmod(0o755)
            records = "100644 blob " + "a" * 40 + "\tLICENSE\0" + "100755 blob " + "b" * 40 + "\tentry.sh\0"
            runner.validate_tracked_source_modes(root, records)
            for candidate, mode, original in ((source, 0o600, 0o644), (source, 0o664, 0o644),
                                               (executable, 0o700, 0o755), (executable, 0o775, 0o755)):
                with self.subTest(path=candidate.name, mode=oct(mode)):
                    candidate.chmod(mode)
                    with self.assertRaisesRegex(ValueError, "Tracked source mode differs from Git"):
                        runner.validate_tracked_source_modes(root, records)
                    self.assertEqual(candidate.stat().st_mode & 0o777, mode)
                    candidate.chmod(original)


class ChromeTemporaryDirectoryAdmissionTests(unittest.TestCase):
    def test_short_ascii_and_exact_sixty_byte_bases_are_admitted(self):
        for evidence in (Path("/home/marty/q3/e"), Path("/" + "a" * 48), Path("/" + "a" * 49)):
            with self.subTest(evidence=evidence):
                selected = runner.chrome_temporary_directory(evidence)
                self.assertEqual(selected, evidence / "temporary")
                self.assertLessEqual(len(str(selected).encode("utf-8")), 60)
        self.assertEqual(len(str(runner.chrome_temporary_directory(Path("/" + "a" * 49))).encode()), 60)

    def test_overlong_ascii_and_actual_failed_attempt_are_refused(self):
        for evidence in (Path("/" + "a" * 50),
                         Path("/home/marty/development/split-web-20261121-retry-2/evidence")):
            with self.subTest(evidence=evidence), self.assertRaisesRegex(ValueError, "maximum is 60"):
                runner.chrome_temporary_directory(evidence)

    def test_limit_counts_utf8_bytes_instead_of_characters(self):
        accepted = Path("/" + "é" * 24 + "a")
        refused = Path("/" + "é" * 25)
        self.assertEqual(len(str(runner.chrome_temporary_directory(accepted)).encode("utf-8")), 60)
        self.assertLess(len(str(refused / "temporary")), 60)
        with self.assertRaisesRegex(ValueError, "61 UTF-8 bytes; maximum is 60"):
            runner.chrome_temporary_directory(refused)

    def test_direct_preflight_and_run_refuse_before_tools_or_evidence_creation(self):
        roots = (Path("/source/marty"), Path("/source/website"), Path("/" + "a" * 50))
        with mock.patch.object(runner, "capture", side_effect=AssertionError("must not inspect host tools")), \
                mock.patch.object(Path, "mkdir", side_effect=AssertionError("must not create evidence")):
            for operation in (lambda: runner.preflight(SimpleNamespace(), roots),
                              lambda: runner.run(SimpleNamespace(), roots, {}, {}, {})):
                with self.subTest(operation=operation), self.assertRaisesRegex(ValueError, "maximum is 60"):
                    operation()

    def test_cli_plan_admits_short_path_and_preflight_refuses_long_utf8_without_writes(self):
        with tempfile.TemporaryDirectory(prefix="sq-") as directory:
            root = Path(directory).resolve()
            (root / "m").mkdir()
            (root / "w").mkdir()
            common = ["--marty-root", str(root / "m"), "--website-root", str(root / "w"),
                      "--docker-socket", "/run/user/1001/docker.sock"]
            short = root / "e"
            result = subprocess.run([sys.executable, str(ROOT / "scripts/qualify_split_web_aws.py"),
                                     "plan", *common, "--evidence-root", str(short)],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "plan-only")
            self.assertFalse(short.exists())
            long = root / ("é" * 30)
            result = subprocess.run([sys.executable, str(ROOT / "scripts/qualify_split_web_aws.py"),
                                     "preflight", *common, "--evidence-root", str(long)],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            refusal = json.loads(result.stderr)
            self.assertEqual(refusal["status"], "refused")
            self.assertIn("maximum is 60", refusal["reason"])
            self.assertFalse(long.exists())


if __name__ == "__main__":
    unittest.main()
