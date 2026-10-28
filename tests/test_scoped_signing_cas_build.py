"""Pure closed-profile controls; no compiler, Docker or beta operation."""
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
build = importlib.import_module("scoped_native_build")
shared = importlib.import_module("scoped_native_runtime")
profiles = importlib.import_module("scoped_native_profiles")


def selected():
    profile = profiles.SIGNING_CAS
    return {"buildProfile": profile.name, "profileSourceSha256": shared.sha(Path(profiles.__file__)),
            "uiRevision": profile.ui_revision, "coreRevision": shared.CORE_REVISION,
            "roleBinaries": dict(profile.roles), "releaseQualified": False, "recordingQualified": False}


class SigningCasBuildTests(unittest.TestCase):
    def test_exact_profile_cannot_expand_roles_sources_or_authority(self):
        plan = selected()
        shared.selected_sources(plan, profiles.SIGNING_CAS.name)
        for edit in [lambda p: p["roleBinaries"].update(flow="marty-flow"),
                     lambda p: p["roleBinaries"].pop("signing-keys"),
                     lambda p: p.update(uiRevision=shared.UI_REVISION),
                     lambda p: p.update(coreRevision="f" * 40),
                     lambda p: p.update(profileSourceSha256="f" * 64),
                     lambda p: p.update(releaseQualified=True)]:
            invalid = copy.deepcopy(plan)
            edit(invalid)
            with self.assertRaises(ValueError):
                shared.selected_sources(invalid, profiles.SIGNING_CAS.name)
        with self.assertRaises(ValueError):
            shared.selected_sources(plan)
        with self.assertRaises(ValueError):
            build.render_recipe("caller-selected-packages")

    def test_two_real_outputs_keep_locked_offline_production_feature_boundary(self):
        recipe = build.render_recipe(profiles.SIGNING_CAS.name)
        argv = build.cargo_arguments(profiles.SIGNING_CAS.name)
        self.assertEqual(argv.count("--bin"), 2)
        self.assertEqual(argv[argv.index("-p") + 1], "marty-signing-keys")
        self.assertIn("--locked", argv)
        self.assertIn("--offline", argv)
        self.assertNotIn("--features", argv)
        self.assertNotIn("--no-default-features", argv)
        self.assertNotIn("/target/debug/marty-flow", recipe)
        self.assertIn("assert len(services)==2", recipe)
        self.assertIn("assert not features&guard.FORBIDDEN_FEATURES", recipe)
        for delimiter in ("BOUNDARY", "ARTIFACTS"):
            code = recipe.split("<<'" + delimiter + "'\n", 1)[1].split("\n" + delimiter, 1)[0]
            compile(code, "source-only-" + delimiter, "exec")

    def test_existing_passport_recipe_and_three_package_scope_are_byte_unchanged(self):
        self.assertEqual(hashlib.sha256(build.render_recipe().encode()).hexdigest(),
                         "0bcabfd96c88d32da0d91eae60e71eb8a54600caa9d9382903c3d1b8461fdd38")
        self.assertEqual(build.cargo_arguments(), build.CARGO_ARGV)
        self.assertEqual(set(shared.ROLE_BINARIES), {"flow", "gateway", "issuance-native"})

    def test_owned_builder_identity_and_resources_are_scoped_without_image_build(self):
        plan = selected()
        run = "11111111-1111-4111-8111-111111111111"
        plan.update(runId=run, containerName=profiles.SIGNING_CAS.container_prefix + run,
                    sources={"ui": {"directory": "C:/owned/ui"}, "core": {"directory": "D:/owned/core"}},
                    outputDirectory="C:/owned/output", recipe={"path": "C:/owned/recipe.sh"},
                    builderImage="sha256:" + "a" * 64)
        args = build.build_arguments(plan, profiles.SIGNING_CAS.name)
        for key, value in [("--memory", "2g"), ("--memory-swap", "4g"), ("--cpus", "1"),
                           ("--pull", "never"), ("--network", "none")]:
            self.assertEqual(args[args.index(key) + 1], value)
        self.assertIn("elevenid.owner=d02-signing-cas-native", args)
        self.assertNotIn("build", args)
        plan["containerName"] = "marty-d12-" + run
        with self.assertRaises(ValueError):
            build.build_arguments(plan, profiles.SIGNING_CAS.name)

    def test_unsupported_directory_barrier_still_refuses_before_build_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir()
            plan = selected()
            plan.update(executionOperatorSha256=build.sha(Path(build.__file__)), engineId="SOURCE_ONLY",
                        runId="11111111-1111-4111-8111-111111111111")
            prepared = root / "prepared.json"
            prepared.write_text(json.dumps(plan))
            calls = []

            def run(*args):
                calls.append(args)
                if "inspect" in args:
                    return SimpleNamespace(stdout=json.dumps([{"Id": "SOURCE_ONLY", "Os": "linux", "Architecture": "amd64"}]))
                return SimpleNamespace(stdout="SOURCE_ONLY")

            plan["builderImage"] = "SOURCE_ONLY"
            prepared.write_text(json.dumps(plan))
            helper = SimpleNamespace(__file__="SOURCE_ONLY_HELPER", VOLUMES=build.VOLUMES,
                                     run=run, resources=lambda *args: {"sourceOnly": True})
            original_sha = build.sha
            with mock.patch.object(build, "verify", return_value=(root, output)), \
                    mock.patch.object(build, "sha", side_effect=lambda p: build.REVIEWED_BUILD_HELPER_SHA256 if str(p) == helper.__file__ else original_sha(p)), \
                    mock.patch.object(shared, "sync_parent", return_value={"supported": False}), \
                    mock.patch.dict(os.environ, {"DOCKER_CONTEXT": "desktop-linux"}):
                with self.assertRaisesRegex(ValueError, "DURABLE_INTENT_AND_JOURNAL_REQUIRED"):
                    build.start(shared.ref(prepared), helper, lambda args: b"", profiles.SIGNING_CAS.name)
            self.assertFalse(any("run" in args for args in calls))
            journal = json.loads((root / "build-state.json").read_bytes())
            self.assertEqual(journal["state"], "BUILD_DURABILITY_BLOCKED_NO_DOCKER_DISPATCH")


if __name__ == "__main__":
    unittest.main()
