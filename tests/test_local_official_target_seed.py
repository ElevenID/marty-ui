"""Focused source-only cache-copy controls; Docker and the real cache stay untouched."""
import importlib
from pathlib import Path
import json
import sys
import tempfile
import unittest
import uuid
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
seed = importlib.import_module("seed_local_official_native_target")


class TargetSeedTests(unittest.TestCase):
    def test_independent_byte_manifest_detects_changed_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "source", root / "target"
            (source / "release").mkdir(parents=True)
            (target / "release").mkdir(parents=True)
            (source / "release/marty-flow").write_bytes(b"original")
            (target / "release/marty-flow").write_bytes(b"original")
            self.assertEqual(seed.manifest(source), seed.manifest(target))
            (target / "release/marty-flow").write_bytes(b"changed")
            self.assertNotEqual(seed.manifest(source), seed.manifest(target))

    def test_daemon_bind_path_refuses_delimiter(self):
        if sys.platform != "win32":
            self.skipTest("Windows Docker Desktop bind spelling")
        with self.assertRaisesRegex(ValueError, "DOCKER_BIND_PATH_REFUSED"):
            seed.daemon_path(Path("C:/bad,path"))

    def test_stale_seed_receipt_refuses_before_docker(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt = Path(tmp) / "seed.json"
            receipt.write_text(json.dumps({"state": "COPIED_AND_READBACK_MATCHED",
                                           "targetVolume": seed.VOLUME,
                                           "operatorSha256": "f" * 64}))
            with mock.patch.object(seed, "transport", side_effect=AssertionError("Docker called")):
                with self.assertRaisesRegex(ValueError, "SEED_RECEIPT_OR_OPERATOR_CHANGED"):
                    seed.inspect_target(receipt)

    def test_exact_windows_source_mount_accepts_only_readonly_flow_binary(self):
        source = Path("C:/Users/maree/.codex/builds/marty-demo-native-cache-20261021/target")
        flow = str(source / "release/marty-flow").replace("/", "\\")
        accepted = [{"Mounts": [{"Type": "bind", "Source": flow, "RW": False}]}]
        seed.checked_source_mounts(accepted, source)
        with self.assertRaisesRegex(ValueError, "SOURCE_CACHE_HAS_WRITER_OR_UNKNOWN_MOUNT"):
            seed.checked_source_mounts([{"Mounts": [{"Type": "bind", "Source": flow,
                                                        "RW": True}]}], source)
        with self.assertRaisesRegex(ValueError, "SOURCE_CACHE_HAS_WRITER_OR_UNKNOWN_MOUNT"):
            seed.checked_source_mounts([{"Mounts": [{"Type": "bind", "Source": str(source),
                                                        "RW": False}]}], source)

    def test_seed_requires_exact_published_source_before_allocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp) / "source-export.json"
            packet.write_text("{}")
            with mock.patch.object(seed, "transport", side_effect=AssertionError("Docker called")):
                with self.assertRaisesRegex(ValueError, "SEED_PRIVATE_SOURCE_PACKET_REQUIRED"):
                    seed.host(Path(tmp) / "receipt.json", True, packet, "0" * 64)

    def test_created_helper_with_wrong_mount_never_starts(self):
        with tempfile.TemporaryDirectory() as tmp:
            cid = "a" * 64
            name = "oid4vc-seed-" + str(uuid.uuid4())
            row = {"Id": cid, "Name": "/" + name, "Image": seed.IMAGE,
                   "Config": {"Labels": {"elevenid.owner": seed.OWNER}},
                   "State": {"Status": "created", "Running": False},
                   "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True,
                                  "Memory": 2 * 1024**3, "MemorySwap": 2 * 1024**3,
                                  "NanoCpus": 500000000, "PidsLimit": 32},
                   "Mounts": []}
            calls = []

            def response(_client, *args):
                calls.append(args[0])
                return cid if args[0] == "create" else json.dumps([row])

            with mock.patch.object(seed, "docker_output", side_effect=response):
                with self.assertRaisesRegex(ValueError, "HELPER_MOUNT_SET_CHANGED"):
                    seed.owned_helper(object(), name, "--inside-inspect",
                                      [(seed.VOLUME, "/target", True)], "2g",
                                      Path(tmp) / "intent.json", 10)
            self.assertEqual(calls, ["create", "inspect"])
            self.assertTrue((Path(tmp) / "intent.created.json").is_file())
            self.assertTrue((Path(tmp) / "intent.inspected.json").is_file())

    def test_staged_operator_imports_shared_runtime_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            import subprocess
            for name in ("seed_local_official_native_target.py", "scoped_native_runtime.py"):
                source = Path(seed.__file__).with_name(name)
                (Path(tmp) / name).write_bytes(source.read_bytes())
            result = subprocess.run([sys.executable, "-c",
                                     "import sys;sys.path.insert(0,sys.argv[1]);"
                                     "import seed_local_official_native_target" , tmp],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
