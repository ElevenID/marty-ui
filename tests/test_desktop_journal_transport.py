"""Pure Desktop transport contract controls; never invokes Docker or WSL."""
import ast
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
transport = importlib.import_module("desktop_journal_transport")
journal = importlib.import_module("scoped_linux_journal")
RUN = "11111111-1111-4111-8111-111111111111"


def specification():
    return {"docker": {"path": transport.DOCKER, "sha256": transport.DOCKER_SHA}, "configDirectory": "C:/owned/docker-config",
            "context": "desktop-linux", "engineId": transport.ENGINE, "image": transport.IMAGE,
            "volumeName": "marty-d02-journal-" + RUN, "transportSha256": "a" * 64, "volumeProof": None}


def readonly_files():
    return [{"role": role, "path": "C:/Users/maree/.codex/private/owned/" + role + ".py",
             "alias": "/mnt/c/Users/maree/.codex/private/owned/" + role + ".py", "sha256": "a" * 64}
            for role in ("worker", "shared", "request")]


class DesktopTransportTests(unittest.TestCase):
    def test_worker_is_uid1000_networknone_64m_only_metadata_rw_and_three_files_ro(self):
        args = transport.helper_arguments(specification(), RUN, "d02-journal-" + RUN + "-test", ["/usr/bin/python3", "-I", "/worker"], readonly_files())
        self.assertEqual(args[args.index("--user") + 1], "1000:1000")
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertEqual(args[args.index("--memory") + 1], "64m")
        self.assertNotIn("--cap-add", args)
        self.assertIn("--pull=never", args)
        mounts = [args[i + 1] for i, value in enumerate(args) if value == "--mount"]
        self.assertEqual(len(mounts), 4)
        self.assertEqual(sum(x.endswith(",readonly") for x in mounts), 3)
        self.assertTrue(mounts[0].startswith("type=volume,src=marty-d02-journal-"))
        self.assertFalse(any("docker.sock" in x or "ui-canvas-cargo" in x or "target" in x for x in mounts))

    def test_engine_capability_prefix_is_normalized_without_expanding_scope(self):
        for values in [["CHOWN"], ["CAP_CHOWN"]]:
            transport.exact_capabilities(values, {"CHOWN"})
        for values in [["CAP_CHOWN", "CAP_SYS_ADMIN"], ["CAP_CHOWN", "CHOWN"], ["CAP_DAC_OVERRIDE"]]:
            with self.assertRaises(ValueError):
                transport.exact_capabilities(values, {"CHOWN"})
        for values in [["no-new-privileges"], ["no-new-privileges:true"]]:
            transport.exact_security_options(values)
        for values in [[], ["no-new-privileges:false"], ["no-new-privileges", "seccomp=unconfined"]]:
            with self.assertRaises(ValueError):
                transport.exact_security_options(values)

    def test_root_setup_has_only_chown_capability_and_no_host_files(self):
        args = transport.helper_arguments(specification(), RUN, "d02-journal-" + RUN + "-root", ["/usr/bin/python3", "-I", "-c", "SOURCE_ONLY"], root_setup=True)
        self.assertEqual(args[args.index("--user") + 1], "0:0")
        self.assertEqual(args[args.index("--cap-add") + 1], "CHOWN")
        self.assertEqual(args.count("--mount"), 1)
        with self.assertRaises(ValueError):
            transport.helper_arguments(specification(), RUN, "d02-journal-" + RUN + "-root", [], readonly_files(), root_setup=True)

    def test_unknown_engine_image_context_volume_or_fields_fail_closed(self):
        for edit in [lambda s: s.update(engineId="foreign"), lambda s: s.update(image="foreign"),
                     lambda s: s.update(context="default"), lambda s: s.update(volumeName="ui-canvas-cargo"),
                     lambda s: s.update(automaticFallback=True)]:
            changed = specification()
            edit(changed)
            with self.assertRaises(ValueError):
                transport.validate_spec(changed, RUN)

    def test_missing_extra_directory_or_foreign_readonly_file_role_is_refused(self):
        for files in [readonly_files()[:2], readonly_files() + [readonly_files()[0]],
                      [{**row, "role": "privateRoot"} if row["role"] == "request" else row for row in readonly_files()],
                      [{**row, "alias": "/var/run/docker.sock"} if row["role"] == "request" else row for row in readonly_files()]]:
            with self.assertRaises(ValueError):
                transport.helper_arguments(specification(), RUN, "d02-journal-" + RUN + "-test", [], files)

    def test_desktop_seam_does_not_call_wsl_and_reuses_response_barrier_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = object.__new__(journal.LinuxBuildJournal)
            store.private, store.run_id = root, RUN
            proof = {"root": str(journal.root_path(RUN)), "device": 1, "inode": 2, "uid": 1000, "mode": 448}
            store.specification = {"workerSha256": "a" * 64, "sharedSha256": "b" * 64, "rootProof": proof}
            barrier = {"fileFsync": True, "parentDirectory": {"supported": True, "synced": True}}
            value = {"scope": "SOURCE_ONLY"}
            def execute(file, digest, worker, shared, alias):
                request = json.loads(file.read_bytes())
                self.assertEqual(hashlib.sha256(file.read_bytes()).hexdigest(), digest)
                self.assertEqual(request["value"], value)
                response = {"ok": True, "rootProof": proof, "name": request["name"], "value": value,
                            "sha256": hashlib.sha256(journal.encoded(value)).hexdigest(), "barrier": barrier}
                return SimpleNamespace(returncode=0, stdout=json.dumps(response).encode(), stderr=b"")
            store.desktop_transport = SimpleNamespace(execute=execute)
            with mock.patch.object(journal, "client_path", return_value="/source-only/request"), mock.patch.object(journal.subprocess, "run", side_effect=AssertionError("No WSL")):
                self.assertEqual(store.exclusive("build-apply-intent.json", value), barrier)
            self.assertFalse(json.loads((root/"build-apply-intent.mirror.json").read_bytes())["windowsDurabilityClaimed"])
            self.assertFalse(list(root.glob("linux-journal-request-*")))

    def test_desktop_timeout_poison_retains_request_and_never_falls_back(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = object.__new__(journal.LinuxBuildJournal)
            store.private, store.run_id = root, RUN
            store.specification = {"workerSha256": "a" * 64, "sharedSha256": "b" * 64,
                "rootProof": {"root": str(journal.root_path(RUN)), "device": 1, "inode": 2, "uid": 1000, "mode": 448}}
            execute = mock.Mock(side_effect=subprocess.TimeoutExpired("SOURCE_ONLY_DESKTOP", 30))
            store.desktop_transport = SimpleNamespace(execute=execute)
            with mock.patch.object(journal, "client_path", return_value="/source-only/request"), mock.patch.object(journal.subprocess, "run", side_effect=AssertionError("No WSL")):
                with self.assertRaisesRegex(RuntimeError, "OUTCOME_UNKNOWN_NO_RETRY"):
                    store.state({"scope": "SOURCE_ONLY"})
                with self.assertRaisesRegex(ValueError, "PENDING_REQUEST_REQUIRES_RECONCILIATION"):
                    store.read("build-state.json")
            self.assertEqual(execute.call_count, 1)
            self.assertEqual(len(list(root.glob("linux-journal-request-*"))), 1)

    def test_existing_worker_and_request_schema_source_is_unchanged(self):
        file = Path(journal.__file__)
        # Digests reviewed against e4e946242; no historical Git object required in CI.
        expected = {'root_path': '8776013728682c4a3d52f62b4f8d5f69a9964a499462ba2ea666819336854c60', 'validate_request': '34bb84bb561c4eb753c3bd7014a10c14bd3f03cf2a41ff78f50fb4d9a69810cb', 'actual_root': 'ebb952b73c8edcf784e01386411474f8ab60ccd0c52290f15915e32944133b05', 'worker': 'b44a9e67c332d131b6102a1eae3e398f8cad1ad0bf094748f62d03b4472d7fec'}
        current = file.read_text()
        for name, digest in expected.items():
            node = next(n for n in ast.parse(current).body if isinstance(n, ast.FunctionDef) and n.name == name)
            self.assertEqual(hashlib.sha256(ast.get_source_segment(current, node).encode()).hexdigest(), digest)



if __name__ == "__main__":
    unittest.main()
