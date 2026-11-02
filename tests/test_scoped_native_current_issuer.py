"""Focused closed current-issuer native build controls."""
import json
import math
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scoped_native_build as build


PROFILE = build.CURRENT_ISSUER_READY_PROFILE
IMAGE = "sha256:" + "a" * 64
RUN = "11111111-1111-4111-8111-111111111111"


def plan():
    scope = build.build_scope(PROFILE)
    return {
        "buildProfile": PROFILE,
        "profileSourceSha256": build.sha(Path(build.__file__).with_name("scoped_native_profiles.py")),
        "uiRevision": scope["uiRevision"],
        "coreRevision": scope["coreRevision"],
        "roleBinaries": scope["roles"],
        "releaseQualified": False,
        "recordingQualified": False,
        "runId": RUN,
        "containerName": scope["prefix"] + RUN,
        "sources": {
            "ui": {"directory": "/owned/ui"},
            "core": {"directory": "/owned/core"},
        },
        "outputDirectory": "/owned/out",
        "recipe": {"path": "/owned/build.sh"},
        "builderImage": IMAGE,
    }


def created_row(p):
    return {
        "Id": "b" * 64,
        "Image": IMAGE,
        "Name": "/" + p["containerName"],
        "State": {"Status": "created"},
        "Config": {"Entrypoint": ["/bin/sh"], "Cmd": ["/build.sh"],
                   "Labels": {"elevenid.owner": "current-issuer-ready-native", "elevenid.run": RUN}},
        "HostConfig": {
            "Memory": 2 * 1024 ** 3, "MemorySwap": 2 * 1024 ** 3,
            "PidsLimit": 64, "NetworkMode": "none", "Privileged": False,
            "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"],
            "NanoCpus": 10 ** 9, "CpuQuota": 0, "CpuPeriod": 0,
        },
        "Mounts": [
            {"Destination": d, "Type": "bind", "RW": rw, "Source": source}
            for d, rw, source in (("/src/ui", False, "/owned/ui"),
                                  ("/build/core", False, "/owned/core"),
                                  ("/out", True, "/owned/out"),
                                  ("/build.sh", False, "/owned/build.sh"))
        ] + [
            {"Destination": d, "Type": "volume", "Name": name, "RW": True}
            for d, name in (("/cargo", "ui-canvas-cargo"),
                            ("/target", "d05-rust-target-20261026"))
        ],
    }


class Helper:
    def __init__(self, row):
        self.row = row

    def run(self, *args):
        return type("Result", (), {"stdout": json.dumps([self.row])})()


class CurrentIssuerProfileTests(unittest.TestCase):
    def test_exact_two_service_source_and_recipe(self):
        scope = build.build_scope(PROFILE)
        self.assertEqual(scope["uiRevision"], "5d22484685fc6c8723e419e656252385c0db3654")
        self.assertEqual(scope["coreRevision"], "4320b5fa1c6f41231ee0aa2bc57d8008549f67ac")
        self.assertEqual(tuple(scope["roles"].values()), ("marty-signing-keys", "marty-gateway"))
        self.assertIn("--bin marty-signing-keys", build.render_recipe(PROFILE))
        self.assertIn("--bin marty-gateway", build.render_recipe(PROFILE))

    def test_compact_signing_profile_preserves_spare_and_exact_caps(self):
        compact = build.CURRENT_ISSUER_POLICY_COMPACT_PROFILE
        scope = build.build_scope(compact)
        self.assertEqual(scope["uiRevision"], "4c99781ca5807494826e0ee0f8d63ee0fc5ad91d")
        self.assertEqual(scope["roles"], {"signing-keys": "marty-signing-keys"})
        self.assertEqual(scope["volumes"], build.build_scope(PROFILE)["volumes"])
        self.assertEqual(build.current_issuer_limits(compact),
                         ("1536m", 1536 * 1024 ** 2, 1536 * 1024 + math.ceil(1.1 * 1024 * 1024)))
        self.assertEqual(build.current_issuer_limits(PROFILE),
                         ("2g", 2 * 1024 ** 3, int(3.1 * 1024 * 1024)))
        self.assertGreaterEqual(build.current_issuer_limits(compact)[2] / 1024 ** 2 - 1.5, 1.1)
        p = plan()
        p.update(buildProfile=compact, uiRevision=scope["uiRevision"],
                 coreRevision=scope["coreRevision"], roleBinaries=scope["roles"],
                 containerName=scope["prefix"] + RUN)
        args = build.build_arguments(p, compact)
        self.assertEqual(args[args.index("--memory") + 1], "1536m")
        self.assertEqual(args[args.index("--memory-swap") + 1], "1536m")
        self.assertEqual(args[args.index("--pids-limit") + 1], "64")
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertEqual(args[args.index("--cpus") + 1], "1")
        self.assertIn("--lib current_issuer_validation_tests::", build.render_recipe(compact))
        row = created_row(p)
        row["HostConfig"]["Memory"] = row["HostConfig"]["MemorySwap"] = 1536 * 1024 ** 2
        build.current_issuer_created_identity(Helper(row), p, row["Id"], profile=compact)
        row["HostConfig"]["MemorySwap"] = 2 * 1024 ** 3
        with self.assertRaisesRegex(ValueError, "CURRENT_ISSUER_CREATED_LIMITS_CHANGED"):
            build.current_issuer_created_identity(Helper(row), p, row["Id"], profile=compact)

    def test_compact_host_gate_rejects_below_2point6g(self):
        compact = build.CURRENT_ISSUER_POLICY_COMPACT_PROFILE
        class Capacity:
            def __init__(self, kib):
                self.kib = kib
            def run(self, *args):
                return type("Result", (), {"stdout": str(self.kib)})()
        threshold = build.current_issuer_limits(compact)[2]
        with patch.object(build.shutil, "disk_usage", return_value=type("Disk", (), {"free": 9 * 1024 ** 3})()):
            build.current_issuer_capacity(Capacity(threshold), Path("."), compact)
            with self.assertRaisesRegex(ValueError, "CURRENT_ISSUER_HOST_HEADROOM_REQUIRED"):
                build.current_issuer_capacity(Capacity(threshold - 1), Path("."), compact)
            with self.assertRaisesRegex(ValueError, "CURRENT_ISSUER_HOST_HEADROOM_REQUIRED"):
                build.current_issuer_capacity(Capacity(threshold), Path("."), PROFILE)

    def test_each_focused_test_receipt_requires_one_real_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            (out / "focused-rust-test.exit-code").write_text("0")
            (out / "focused-rust-test.stdout.txt").write_text(
                "test result: ok. 4 passed; 0 failed; 0 ignored; 278 filtered out;\n")
            (out / "focused-rust-test.stderr.txt").write_text("")
            row = build.focused_rust_test_receipt(
                out, "focused-rust-test", "current_issuer_validation_tests::", 4)
            self.assertEqual(row["exitCode"], 0)
            (out / "focused-rust-test.stdout.txt").write_text(
                "test result: ok. 0 passed; 0 failed; 282 filtered out;\n")
            with self.assertRaisesRegex(ValueError, "FOCUSED_SIGNING_POLICY_TEST_REQUIRED"):
                build.focused_rust_test_receipt(out, "focused-rust-test", row["name"], 4)

    def test_recipe_requires_exact_lf_bytes_for_linux_shell(self):
        recipe = build.render_recipe("current-issuer-policy-signing-only")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "build.sh"
            path.write_bytes(recipe.encode())
            build.exact_recipe_bytes(path, "current-issuer-policy-signing-only")
            path.write_bytes(recipe.replace("\n", "\r\n").encode())
            with self.assertRaisesRegex(ValueError, "THREE_ROLE_RECIPE_CHANGED"):
                build.exact_recipe_bytes(path, "current-issuer-policy-signing-only")

    def test_policy_signing_profile_reuses_closed_builder_without_gateway(self):
        one = "current-issuer-policy-signing-only"
        scope = build.build_scope(one)
        self.assertEqual(scope["uiRevision"], "4c99781ca5807494826e0ee0f8d63ee0fc5ad91d")
        self.assertEqual(scope["coreRevision"], "4320b5fa1c6f41231ee0aa2bc57d8008549f67ac")
        self.assertEqual(scope["roles"], {"signing-keys": "marty-signing-keys"})
        self.assertEqual(scope["owner"], "current-issuer-ready-native")
        recipe = build.render_recipe(one)
        self.assertIn("--bin marty-signing-keys", recipe)
        self.assertNotIn("--bin marty-gateway", recipe)
        self.assertIn("cargo test -p marty-signing-keys --lib current_issuer_validation_tests:: --locked --offline -j1", recipe)
        self.assertIn("focused-rust-test.exit-code", recipe)
        self.assertNotIn("signer-capability-rust-test.exit-code", recipe)
        self.assertNotIn("focused-rust-test.exit-code", build.render_recipe(PROFILE))
        p = plan()
        p.update(buildProfile=one, uiRevision=scope["uiRevision"],
                 coreRevision=scope["coreRevision"], roleBinaries=scope["roles"],
                 containerName=scope["prefix"] + RUN)
        args = build.build_arguments(p, one)
        self.assertEqual(args[args.index("--memory-swap") + 1], "2g")
        self.assertEqual(args[args.index("--pids-limit") + 1], "64")
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertEqual(args[args.index("--cpus") + 1], "1")
        row = created_row(p)
        build.current_issuer_created_identity(Helper(row), p, row["Id"])
        row["Mounts"][0]["Source"] = "/foreign/ui"
        with self.assertRaisesRegex(ValueError, "CURRENT_ISSUER_CREATED_MOUNTS_CHANGED"):
            build.current_issuer_created_identity(Helper(row), p, row["Id"])

    def test_only_new_profile_has_no_swap_and_bounded_pids(self):
        p = plan()
        args = build.build_arguments(p, PROFILE)
        self.assertEqual(args[args.index("--memory-swap") + 1], "2g")
        self.assertEqual(args[args.index("--pids-limit") + 1], "64")
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertEqual(args[args.index("--cpus") + 1], "1")
        old = build.build_scope("d02-signing-cas")
        p.update(buildProfile="d02-signing-cas", uiRevision=old["uiRevision"],
                 coreRevision=old["coreRevision"], roleBinaries=old["roles"],
                 containerName=old["prefix"] + RUN)
        legacy = build.build_arguments(p, "d02-signing-cas")
        self.assertEqual(legacy[legacy.index("--memory-swap") + 1], "4g")
        self.assertNotIn("--pids-limit", legacy)

    def test_created_identity_and_limits_reject_drift(self):
        p = plan()
        row = created_row(p)
        build.current_issuer_created_identity(Helper(row), p, row["Id"])
        for field, value in (("MemorySwap", 4 * 1024 ** 3), ("PidsLimit", 0),
                             ("NetworkMode", "bridge")):
            changed = created_row(p)
            changed["HostConfig"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "CURRENT_ISSUER_CREATED_LIMITS_CHANGED"):
                build.current_issuer_created_identity(Helper(changed), p, changed["Id"])
        changed = created_row(p)
        changed["Mounts"][0]["RW"] = True
        with self.assertRaisesRegex(ValueError, "CURRENT_ISSUER_CREATED_MOUNTS_CHANGED"):
            build.current_issuer_created_identity(Helper(changed), p, changed["Id"])
        changed = created_row(p)
        changed["Mounts"][0]["Source"] = "/foreign/ui"
        with self.assertRaisesRegex(ValueError, "CURRENT_ISSUER_CREATED_MOUNTS_CHANGED"):
            build.current_issuer_created_identity(Helper(changed), p, changed["Id"])
        changed = created_row(p)
        changed["Mounts"].append(dict(changed["Mounts"][0]))
        with self.assertRaisesRegex(ValueError, "CURRENT_ISSUER_CREATED_MOUNTS_CHANGED"):
            build.current_issuer_created_identity(Helper(changed), p, changed["Id"])
        changed = created_row(p)
        changed["Config"]["Cmd"] = ["/wrong.sh"]
        with self.assertRaisesRegex(ValueError, "CURRENT_ISSUER_CREATED_IDENTITY_CHANGED"):
            build.current_issuer_created_identity(Helper(changed), p, changed["Id"])

    def test_legacy_start_keeps_one_run_ack_and_no_created_journal(self):
        old = build.build_scope("d02-signing-cas")
        p = plan()
        p.update(buildProfile="d02-signing-cas", uiRevision=old["uiRevision"],
                 coreRevision=old["coreRevision"], roleBinaries=old["roles"],
                 containerName=old["prefix"] + RUN, engineId="engine",
                 executionOperatorSha256="operator")

        class Store:
            def __init__(self):
                self.states = []

            def exclusive(self, name, value):
                return {"fileFsync": True}

            def state(self, value):
                self.states.append(value["state"])
                return {"fileFsync": True}

        class LegacyHelper:
            VOLUMES = build.VOLUMES
            __file__ = "reviewed-helper"

            def __init__(self):
                self.calls = []

            def run(self, *args):
                self.calls.append(args)
                if args[1:3] == ("--context", "desktop-linux") and "info" in args:
                    value = "engine"
                elif args[:3] == ("docker", "image", "inspect"):
                    value = json.dumps([{"Id": IMAGE, "Os": "linux", "Architecture": "amd64"}])
                elif "run" in args:
                    value = "b" * 64
                else:
                    raise AssertionError(args)
                return type("Result", (), {"stdout": value})()

            def resources(self, private, image):
                return {"hostAvailableKiB": 4 * 1024 ** 2}

        with tempfile.TemporaryDirectory() as tmp:
            prepared = Path(tmp) / "plan.json"
            prepared.write_text(json.dumps(p))
            output = Path(tmp) / "out"
            output.mkdir()
            store, helper = Store(), LegacyHelper()
            with patch.object(build, "read_ref", return_value=prepared), \
                 patch.object(build, "verify", return_value=(Path(tmp), output)), \
                 patch.object(build, "build_journal", return_value=store), \
                 patch.object(build, "sha", side_effect=lambda path: "operator" if Path(path) == Path(build.__file__) else build.REVIEWED_BUILD_HELPER_SHA256), \
                 patch.object(build, "durable_barrier", return_value=True), \
                 patch.object(build, "build_arguments", return_value=["docker", "--context", "desktop-linux", "run", "--detach"]), \
                 patch.dict(build.os.environ, {"DOCKER_CONTEXT": "desktop-linux"}):
                build.start({"path": str(prepared), "sha256": "a" * 64}, helper, None, "d02-signing-cas")
            self.assertEqual(store.states, ["RESOURCE_CHECK_INTENT", "RESOURCE_CHECK_READY",
                                            "BUILD_CREATE_INTENT", "BUILD_RUNNING"])
            self.assertEqual(sum("run" in call for call in helper.calls), 1)
            self.assertEqual(sum("create" in call or "start" in call for call in helper.calls), 0)


if __name__ == "__main__":
    unittest.main()
