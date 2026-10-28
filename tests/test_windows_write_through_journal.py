"""Owned temporary PUBLIC filesystem controls only; never a build or beta call."""
import importlib
import json
import os
from pathlib import Path
import sys
import uuid
import contextlib
import subprocess
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
writer = importlib.import_module("windows_write_through_journal")
shared = importlib.import_module("scoped_native_runtime")


@contextlib.contextmanager
def owned_public_directory():
    # Only a fresh UUID-named PUBLIC test directory is changed/removed.
    root = (Path.home() / ".codex/private").resolve()
    run_id = str(uuid.uuid4())
    directory = root / ("marty-d12-build-" + run_id)
    directory.mkdir()
    quoted = str(directory).replace("'", "''")
    script = "$ErrorActionPreference='Stop';$p='"+quoted+"';$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User;$a=Get-Acl -LiteralPath $p;$a.SetAccessRuleProtection($true,$false);foreach($r in @($a.Access)){$a.RemoveAccessRuleSpecific($r)};$a.SetOwner($sid);foreach($s in @($sid.Value,'S-1-5-18','S-1-5-32-544')){$id=[Security.Principal.SecurityIdentifier]::new($s);$r=[Security.AccessControl.FileSystemAccessRule]::new($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow');$a.AddAccessRule($r)};Set-Acl -LiteralPath $p -AclObject $a"
    subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], check=True, capture_output=True, timeout=10)
    identity = writer._directory_identity(directory)
    try:
        expected = {"root": str(root), "directory": str(directory), "runId": run_id,
                    "rootIdentity": writer._directory_identity(root), "directoryIdentity": identity,
                    "ownerSid": writer._read_acl(directory)["user"]}
        yield directory, writer.prove_owned_run_directory(expected), expected
    finally:
        assert writer._directory_identity(directory) == identity
        for child in directory.iterdir():
            assert child.name in {"public-intent.json", "public-journal.jsonl", "public-tail.jsonl"} and child.is_file() and not child.is_symlink()
            child.unlink()
        directory.rmdir()


class PrivateWriterControls(unittest.TestCase):
    def test_short_write_and_failed_flush_never_return_a_barrier(self):
        stream = mock.Mock()
        stream.write.return_value = 1
        flush = mock.Mock(return_value=True)
        with self.assertRaisesRegex(ValueError, "SHORT_WRITE"):
            writer.complete_write(stream, b"PUBLIC", flush)
        flush.assert_not_called()
        stream.write.return_value = 6
        flush.return_value = False
        with self.assertRaisesRegex(ValueError, "FLUSH_FAILED"):
            writer.complete_write(stream, b"PUBLIC", flush)

    def test_unknown_tail_identity_and_duplicate_fields_refuse_recovery(self):
        identity = {"device": 1, "inode": 2}
        frame = {"schema": writer.SCHEMA, "sequence": 1, "previousSha256": None,
                 "identity": identity, "payload": {"state": "PUBLIC"}}
        raw = json.dumps(frame).encode() + b"\n"
        self.assertEqual(writer.decode_events(raw, identity)[0]["payload"]["state"], "PUBLIC")
        for invalid in [raw[:-1], raw + b"partial", raw.replace(b'"sequence": 1', b'"sequence": 1, "sequence": 1')]:
            with self.assertRaises(ValueError):
                writer.decode_events(invalid, identity)
        with self.assertRaises(ValueError):
            writer.decode_events(raw, {"device": 1, "inode": 3})

    @unittest.skipUnless(os.name == "nt", "Actual Windows NTFS API control")
    def test_actual_ntfs_create_append_reopen_and_exclusive_collision(self):
        with owned_public_directory() as (parent, owned, expected):
            with self.assertRaises((ValueError, TypeError)):
                writer.NTFSWriteThroughFile(parent / "public-intent.json", expected, create_new=True)
            changed = dict(expected)
            changed["runId"] = str(uuid.uuid4())
            with self.assertRaises(ValueError):
                writer.prove_owned_run_directory(changed)
            intent = parent / "public-intent.json"
            instance = writer.NTFSWriteThroughFile(intent, owned, create_new=True)
            try:
                proof = instance.intent({"state": "PUBLIC_ONLY_INTENT"})
                self.assertTrue(proof["flushFileBuffers"])
                self.assertFalse(shared.durable_barrier(proof), "Build gate remains unchanged pending review")
                with self.assertRaises(OSError) as caught:
                    writer.NTFSWriteThroughFile(intent, owned, create_new=True)
                self.assertIn(caught.exception.winerror, {32, 80, 183})
                with self.assertRaisesRegex(ValueError, "INTENT_CANNOT_BECOME"):
                    instance.append({"state": "SHOULD_REFUSE"})
            finally:
                instance.close()
            self.assertEqual(json.loads(intent.read_bytes())["state"], "PUBLIC_ONLY_INTENT")
            journal = parent / "public-journal.jsonl"
            instance = writer.NTFSWriteThroughFile(journal, owned, create_new=True)
            identity = instance.identity
            try:
                instance.append({"state": "PUBLIC_INTENT"})
                instance.append({"state": "PUBLIC_ACK"})
                with self.assertRaises(OSError) as caught:
                    writer.NTFSWriteThroughFile(journal, owned, create_new=False)
                self.assertEqual(caught.exception.winerror, 32)
            finally:
                instance.close()
            reopened = writer.NTFSWriteThroughFile(journal, owned, create_new=False)
            try:
                self.assertEqual(reopened.identity, identity)
                proof = reopened.append({"state": "PUBLIC_TERMINAL"})
                self.assertEqual(proof["sequence"], 3)
            finally:
                reopened.close()
            last, _ = writer.decode_events(journal.read_bytes(), identity)
            self.assertEqual(last["payload"]["state"], "PUBLIC_TERMINAL")
            # A torn tail is retained; reopening cannot silently recover/replay.
            torn = parent / "public-tail.jsonl"
            instance = writer.NTFSWriteThroughFile(torn, owned, create_new=True)
            try:
                instance.append({"state": "PUBLIC_INTENT"})
            finally:
                instance.close()
            with torn.open("ab") as stream:
                stream.write(b"partial")
                stream.flush()
                os.fsync(stream.fileno())
            original = torn.read_bytes()
            with self.assertRaisesRegex(ValueError, "INCOMPLETE"):
                writer.NTFSWriteThroughFile(torn, owned, create_new=False)
            self.assertEqual(torn.read_bytes(), original)



if __name__ == "__main__":
    unittest.main()
