"""Source/owned-temp controls only; no WSL, Docker, compiler or beta call."""
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
journal = importlib.import_module("scoped_linux_journal")
build = importlib.import_module("scoped_native_build")
RUN = "11111111-1111-4111-8111-111111111111"
PROOF = {"root": str(journal.root_path(RUN)), "device": 2128, "inode": 1234, "uid": 1000, "mode": 0o700}
BARRIER = {"fileFsync": True, "parentDirectory": {"supported": True, "synced": True}}


def request():
    return {"schema": 1, "runId": RUN, "operation": "exclusive", "name": "build-apply-intent.json",
            "value": {"state": "SOURCE_ONLY"}, "rootProof": copy.deepcopy(PROOF),
            "workerSha256": "a" * 64, "sharedSha256": "b" * 64}


def source_store(private):
    # Transport fixture bypasses Windows ownership construction; actual source
    # entrypoint still checks that separately before any WSL request.
    store = object.__new__(journal.LinuxBuildJournal)
    store.private, store.run_id = private, RUN
    store.desktop_transport = None
    store.specification = {"rootProof": copy.deepcopy(PROOF), "workerSha256": "a" * 64, "sharedSha256": "b" * 64}
    return store


class LinuxJournalTests(unittest.TestCase):
    def test_linux_root_stays_posix_on_the_windows_controller(self):
        self.assertEqual(str(journal.root_path(RUN)),
                         "/home/canvasrunner/.codex/private/d02-build-journal-" + RUN)

    def test_closed_operations_filenames_and_payload_shape(self):
        journal.validate_request(request())
        for edit in [lambda r: r.update(operation="run"), lambda r: r.update(name="../../authority"),
                     lambda r: r.update(name="build-state.json"), lambda r: r.update(command="Docker"),
                     lambda r: r.update(value=None), lambda r: r.update(runId="not-owned"),
                     lambda r: r["rootProof"].update(uid=0), lambda r: r["rootProof"].update(inode=True)]:
            changed = request()
            edit(changed)
            with self.assertRaises(ValueError):
                journal.validate_request(changed)

    def test_replaced_directory_generation_refuses_before_any_write(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(journal, "HOME", Path(temporary)):
            root = journal.root_path(RUN)
            root.mkdir(parents=True)
            proof = {**PROOF, "root": str(root)}
            info = SimpleNamespace(st_dev=proof["device"], st_ino=proof["inode"] + 1,
                                   st_uid=1000, st_mode=stat.S_IFDIR | 0o700)
            with mock.patch.object(Path, "lstat", return_value=info):
                with self.assertRaisesRegex(ValueError, "JOURNAL_ROOT_REPLACED"):
                    journal.actual_root(proof, RUN)

    def test_timeout_retains_exact_request_and_never_retries_or_mirrors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = source_store(root)
            with mock.patch.object(journal, "client_path", return_value="/source-only/request"), \
                    mock.patch.dict(os.environ, {"SystemRoot": "C:/Windows"}), \
                    mock.patch.object(journal.subprocess, "run", side_effect=subprocess.TimeoutExpired("SOURCE_ONLY", 15)) as run:
                with self.assertRaisesRegex(RuntimeError, "OUTCOME_UNKNOWN_NO_RETRY"):
                    store.exclusive("build-apply-intent.json", {"state": "SOURCE_ONLY"})
                with self.assertRaisesRegex(ValueError, "PENDING_REQUEST_REQUIRES_RECONCILIATION"):
                    store.state({"state": "NO_RETRY_AFTER_UNKNOWN"})
                replacement = source_store(root)
                with self.assertRaisesRegex(ValueError, "PENDING_REQUEST_REQUIRES_RECONCILIATION"):
                    replacement.read("build-state.json")
                self.assertEqual(run.call_count, 1)
            self.assertEqual(len(list(root.glob("linux-journal-request-*.json"))), 1)
            self.assertEqual(list(root.glob("*.mirror.json")), [])

    def test_false_barrier_or_changed_reopen_hash_never_returns_authority(self):
        for change in ["barrier", "hash"]:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                store = source_store(root)
                value = {"state": "SOURCE_ONLY"}
                response = {"ok": True, "rootProof": PROOF, "name": "build-apply-intent.json", "value": value,
                            "sha256": hashlib.sha256(journal.encoded(value)).hexdigest(), "barrier": copy.deepcopy(BARRIER)}
                if change == "barrier":
                    response["barrier"]["parentDirectory"]["supported"] = False
                else:
                    response["sha256"] = "f" * 64
                result = SimpleNamespace(returncode=0, stdout=json.dumps(response).encode(), stderr=b"")
                with mock.patch.object(journal, "client_path", return_value="/source-only/request"), \
                        mock.patch.dict(os.environ, {"SystemRoot": "C:/Windows"}), \
                        mock.patch.object(journal.subprocess, "run", return_value=result):
                    with self.assertRaises(ValueError):
                        store.exclusive("build-apply-intent.json", value)
                self.assertEqual(list(root.glob("*.mirror.json")), [])

    def test_positive_write_is_explicit_mirror_and_reads_authoritative_worker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = source_store(root)
            value = {"state": "SOURCE_ONLY", "preparationSha256": "c" * 64}

            def run(args, **options):
                self.assertIs(options["stdin"], subprocess.DEVNULL)
                self.assertEqual(options["timeout"], 15)
                self.assertIn("-i", args)
                request_file = next(root.glob("linux-journal-request-*.json"))
                actual = json.loads(request_file.read_bytes())
                self.assertEqual(actual["rootProof"], PROOF)
                response = {"ok": True, "rootProof": PROOF, "name": actual["name"], "value": value,
                            "sha256": hashlib.sha256(journal.encoded(value)).hexdigest(), "barrier": BARRIER}
                return SimpleNamespace(returncode=0, stdout=json.dumps(response).encode(), stderr=b"")

            with mock.patch.object(journal, "client_path", return_value="/source-only/request"), \
                    mock.patch.dict(os.environ, {"SystemRoot": "C:/Windows"}), \
                    mock.patch.object(journal.subprocess, "run", side_effect=run):
                self.assertEqual(store.exclusive("build-apply-intent.json", value), BARRIER)
                mirror = root / "build-apply-intent.mirror.json"
                self.assertFalse(json.loads(mirror.read_bytes())["windowsDurabilityClaimed"])
                mirror.write_text(json.dumps({"value": {"state": "FALSE_MIRROR"}}))
                self.assertEqual(store.read("build-apply-intent.json"), value)
            self.assertEqual(list(root.glob("linux-journal-request-*.json")), [])

    def test_legacy_passport_cannot_select_linux_backend(self):
        with self.assertRaisesRegex(ValueError, "LINUX_JOURNAL_IS_D02_ONLY"):
            build.build_journal({"journalBackend": {}}, Path("SOURCE_ONLY"))


if __name__ == "__main__":
    unittest.main()
