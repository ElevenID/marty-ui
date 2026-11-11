"""Pure admission controls; these neither build nor contact a runtime."""
import sys
from pathlib import Path
import unittest
import os
import tempfile
import json
import hashlib
from copy import deepcopy

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scoped_native_build as build
import scoped_native_profiles as profiles
import scoped_native_runtime as shared
import scoped_beta_binary_overlay as overlay


class CanvasScopedJobBuildTests(unittest.TestCase):
    def plan(self):
        profile = profiles.CANVAS_SCOPED_JOBS
        return {"buildProfile": profile.name, "profileSourceSha256": shared.sha(Path(profiles.__file__)),
                "uiRevision": profile.ui_revision, "coreRevision": profile.core_revision,
                "roleBinaries": dict(profile.roles), "releaseQualified": False, "recordingQualified": False}

    def test_exact_issuer_and_deployed_core_scope(self):
        profile = profiles.CANVAS_SCOPED_JOBS
        shared.selected_sources(self.plan(), profile.name)
        self.assertEqual(build.build_scope(profile.name)["coreRevision"], profile.core_revision)
        self.assertEqual(build.cargo_arguments(profile.name), ["cargo", "build", "--locked", "--offline",
            "--message-format=json", "-p", "marty-issuance-service", "--bin", "marty-issuance-service"])

    def test_foreign_core_or_extra_role_is_refused(self):
        for key, value in [("coreRevision", shared.CORE_REVISION),
                           ("roleBinaries", {"issuance-native": "marty-issuance-service", "gateway": "marty-gateway"})]:
            plan = self.plan()
            plan[key] = value
            with self.assertRaises(ValueError):
                shared.selected_sources(plan, profiles.CANVAS_SCOPED_JOBS.name)

    def test_unknown_profile_is_refused(self):
        with self.assertRaises(ValueError):
            build.build_scope("canvas-arbitrary")

    def test_prior_profiles_keep_original_core(self):
        for profile in (None, profiles.SIGNING_CAS.name, profiles.SIGNING_CAS_NO_TRANSFORM.name):
            self.assertEqual(build.build_scope(profile)["coreRevision"], shared.CORE_REVISION)

    def test_closed_issuer_renderer_changes_only_native_bind_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "issuer"
            candidate.write_bytes(b"source-test-only")
            binaries = {"issuance-native": shared.ref(candidate)}
            mount = {"type": "bind", "source": "C:/frozen/old", "target": "/usr/local/bin/marty-issuance-service",
                     "read_only": True, "bind": {"create_host_path": False, "propagation": "rprivate"}}
            before = {"services": {"issuance-native": {"image": "same", "volumes": [mount]},
                                   "issuance": {"image": "same", "volumes": [deepcopy(mount)]}}}
            rendered = overlay.binary_overlay(binaries, profiles.CANVAS_SCOPED_JOBS.name, before=before)
            self.assertEqual(set(rendered["services"]), {"issuance-native"})
            after = deepcopy(before)
            after["services"]["issuance-native"]["volumes"] = rendered["services"]["issuance-native"]["volumes"]
            overlay.validate_delta(before, after, binaries, profiles.CANVAS_SCOPED_JOBS.name)
            self.assertEqual(after["services"]["issuance"], before["services"]["issuance"])
            with self.assertRaises(ValueError):
                overlay.binary_overlay(binaries, profiles.CANVAS_SCOPED_JOBS.name, selected_roles=["issuance"], before=before)

    def test_scoped_no_start_uses_supported_up_grammar_and_preserves_legacy_defaults(self):
        arguments = ["docker", "compose", "--project-name", "elevenid-beta", "--project-directory", "C:/frozen", "-f", "C:/frozen/base.yml"]
        actual = overlay.compose_recreate_arguments(arguments, None, profiles.CANVAS_SCOPED_JOBS.name,
                                                   ["issuance-native"], no_start=True)
        self.assertEqual(actual[len(arguments):], ["up", "--no-start", "--no-build", "--no-deps", "--pull", "never", "--force-recreate", "issuance-native"])
        default = overlay.compose_recreate_arguments(arguments, "C:/frozen/overlay.yml")
        self.assertIn("--detach", default)
        self.assertNotIn("--no-start", default)
        for change in (arguments[:3] + ["foreign"] + arguments[4:], arguments + ["up", "--detach"]):
            with self.assertRaises(ValueError):
                overlay.compose_recreate_arguments(change, None, profiles.CANVAS_SCOPED_JOBS.name, no_start=True)

    @unittest.skipUnless(os.name == "nt", "Windows MAX_PATH regression")
    def test_long_tracked_export_is_included_in_actual_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            relative = "/".join(["tracked" * 5] * 7) + "/source.txt"
            target = Path("\\\\?\\" + str(root / "export" / relative))
            target.parent.mkdir(parents=True)
            raw = b"exact Git bytes\n"
            target.write_bytes(raw)
            inventory = root / "inventory.json"
            inventory.write_text(json.dumps([{"path": relative, "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest()}]))
            oid = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            tree = b"100644 blob " + oid.encode() + b"\t" + relative.encode() + b"\0"
            build.verify_export("repository", "revision", root / "export", shared.ref(inventory), lambda _: tree)
            target.write_bytes(b"foreign bytes")
            with self.assertRaises(ValueError):
                build.verify_export("repository", "revision", root / "export", shared.ref(inventory), lambda _: tree)
            # TemporaryDirectory's ordinary rmtree has the same Windows limit.
            target.unlink()
            current = target.parent
            extended_root = Path("\\\\?\\" + str(root))
            while current != extended_root:
                current.rmdir()
                current = current.parent


if __name__ == "__main__":
    unittest.main()
