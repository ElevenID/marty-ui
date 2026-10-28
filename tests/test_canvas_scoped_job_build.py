"""Pure admission controls; these neither build nor contact a runtime."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scoped_native_build as build
import scoped_native_profiles as profiles
import scoped_native_runtime as shared


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


if __name__ == "__main__":
    unittest.main()
