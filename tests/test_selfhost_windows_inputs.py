"""Synthetic-only private input controls, including actual Windows handles/ACLs."""
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import selfhost_windows_inputs as windows
from selfhost_operator_inputs import private_file

USER = "S-1-5-21-1-2-3-1001"
ALLOW = (USER, 0, 0x10, windows.FULL_CONTROL)
PUBLIC = "PUBLIC_SYNTHETIC_OPERATOR_INPUT\n"


def powershell(script):
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                    "$ErrorActionPreference='Stop';" + script],
                   capture_output=True, timeout=15, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))


@contextmanager
def private_fixture():
    with tempfile.TemporaryDirectory(prefix="marty-private-input-test-") as directory:
        root = Path(directory)
        quoted = str(root).replace("'", "''")
        powershell("$p='"+quoted+"';$u=[Security.Principal.WindowsIdentity]::GetCurrent().User;"
                   "$a=[Security.AccessControl.DirectorySecurity]::new();"
                   "$a.SetAccessRuleProtection($true,$false);$a.SetOwner($u);"
                   "foreach($s in @($u.Value,'S-1-5-18','S-1-5-32-544')){"
                   "$i=[Security.Principal.SecurityIdentifier]::new($s);"
                   "$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new("
                   "$i,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))};"
                   "[IO.Directory]::SetAccessControl($p,$a)")
        path = root / "operator.token"
        path.write_text(PUBLIC, encoding="utf-8")
        yield root, path


class AclPolicyTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "Non-Windows refusal")
    def test_exact_byte_reader_has_no_posix_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"SYNTHETIC\r\n")
            with self.assertRaisesRegex(ValueError, windows.REFUSAL):
                windows.read_private_bytes(path)

    @unittest.skipIf(os.name == "nt", "Non-Windows refusal")
    def test_private_initialization_is_not_a_posix_write_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"")
            with self.assertRaisesRegex(ValueError, windows.WRITE_REFUSAL):
                windows.write_empty_private_file(path, PUBLIC)
            self.assertEqual(path.read_bytes(), b"")

    def test_matching_file_index_on_another_volume_does_not_bind_the_handle(self):
        windows.checked_identity(5, (1 << 32) | 7, (5, (1 << 32) | 7))
        for expected in [(6, (1 << 32) | 7), (5, (2 << 32) | 7), (5, (1 << 32) | 8)]:
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, windows.REFUSAL):
                windows.checked_identity(5, (1 << 32) | 7, expected)

    def test_current_owner_only_or_trusted_machine_principals(self):
        windows.checked_acl(USER, USER, [ALLOW])
        windows.checked_acl(USER, USER, [ALLOW,
            ("S-1-5-18", 0, 0, windows.FULL_CONTROL),
            ("S-1-5-32-544", 0, 0, windows.FULL_CONTROL)])

    def test_broader_or_ambiguous_authority_is_rejected(self):
        for entries in [[], [ALLOW, ALLOW], [("S-1-1-0", 0, 0, windows.FULL_CONTROL)],
                        [ALLOW, ("S-1-5-32-545", 0, 0, windows.FULL_CONTROL)],
                        [(USER, 1, 0, windows.FULL_CONTROL)],
                        [(USER, 0, 8, windows.FULL_CONTROL)],
                        [(USER, 0, 0, 0x120089)],
                        [(USER, 5, 0, windows.FULL_CONTROL)]]:
            with self.subTest(entries=entries), self.assertRaisesRegex(ValueError, windows.REFUSAL):
                windows.checked_acl(USER, USER, entries)
        with self.assertRaisesRegex(ValueError, windows.REFUSAL):
            windows.checked_acl("S-1-5-18", USER, [ALLOW])


@unittest.skipUnless(os.name == "nt", "Actual NTFS handle/ACL integration")
class WindowsInputTests(unittest.TestCase):
    def test_explicit_asset_bound_and_exclusive_lock_do_not_relax_secret_reads(self):
        with private_fixture() as (_, path):
            raw = b'S' * (windows.MAX_BYTES + 1)
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, windows.REFUSAL):
                windows.read_private_bytes(path)
            with windows.hold_private_input(path, max_bytes=128 * 1024) as data:
                self.assertEqual(data, raw)
                with self.assertRaises(OSError): path.write_bytes(b'changed')
            path.write_bytes(b'')
            with windows.hold_private_input(path, exclusive=True):
                with self.assertRaisesRegex(ValueError, windows.REFUSAL):
                    with windows.hold_private_input(path, exclusive=True):
                        self.fail('second coordinator acquired the lock')
            with windows.hold_private_input(path, exclusive=True):
                pass
    def test_generation_holds_directory_and_files_until_the_action_finishes(self):
        with private_fixture() as (root, path):
            path = path.rename(root / "leaf")
            path.write_bytes(PUBLIC.encode("utf-8"))
            (root / "optional").write_bytes(b"")
            with windows.hold_private_generation(root, ["leaf", "optional"]) as data:
                self.assertEqual(data, {"leaf": PUBLIC.encode("utf-8"), "optional": b""})
                self.assertEqual(path.read_bytes(), data["leaf"])
                for operation in [lambda: path.write_bytes(b"replacement"), path.unlink,
                                  lambda: root.rename(root.with_name(root.name + "-moved"))]:
                    with self.assertRaises(OSError):
                        operation()
            # Closing the context releases both the file and directory handles.
            path.write_bytes(b"AFTER\r\n")
            self.assertEqual(windows.read_private_bytes(path), b"AFTER\r\n")

    def test_generation_rejects_partial_names_and_releases_on_caller_failure(self):
        with private_fixture() as (root, path):
            path = path.rename(root / "leaf")
            for names in [[], ["leaf", "leaf"], ["../leaf"], ["leaf:ads"], ["missing"],
                          ["LEAF"], ["leaf"] * 513]:
                with self.subTest(names=names[:2]), self.assertRaisesRegex(
                        ValueError, windows.REFUSAL):
                    with windows.hold_private_generation(root, names):
                        self.fail("invalid generation accepted")
            with self.assertRaisesRegex(RuntimeError, "SYNTHETIC_ACTION_FAILURE"):
                with windows.hold_private_generation(root, ["leaf"]):
                    raise RuntimeError("SYNTHETIC_ACTION_FAILURE")
            path.write_bytes(PUBLIC.encode("utf-8"))
            with windows.hold_private_generation(root, ["leaf"]) as data:
                self.assertEqual(data["leaf"], PUBLIC.encode("utf-8"))

    def test_generation_also_holds_ancestor_namespace_without_blocking_other_writes(self):
        with private_fixture() as (root, path):
            inner = root / "generation"
            inner.mkdir()
            path.rename(inner / "leaf")
            moved = root.with_name(root.name + "-moved")
            try:
                with windows.hold_private_generation(inner, ["leaf"]):
                    with self.assertRaises(OSError):
                        root.rename(moved)
                    # The non-generation ancestor remains usable by other work.
                    (root / "unrelated").write_bytes(b"SYNTHETIC_UNRELATED")
            finally:
                if moved.exists():
                    moved.rename(root)

    def test_generation_detects_directory_membership_and_acl_changes_on_exit(self):
        with private_fixture() as (root, path):
            path = path.rename(root / "leaf")
            path.write_bytes(PUBLIC.encode("utf-8"))
            with self.assertRaisesRegex(ValueError, windows.REFUSAL):
                with windows.hold_private_generation(root, ["leaf"]):
                    (root / "unexpected").write_bytes(b"PUBLIC_SYNTHETIC")
            (root / "unexpected").unlink()
            quoted = str(path).replace("'", "''")
            with self.assertRaisesRegex(ValueError, windows.REFUSAL):
                with windows.hold_private_generation(root, ["leaf"]):
                    powershell("$p='"+quoted+"';$a=Get-Acl -LiteralPath $p;"
                               "$s=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545');"
                               "$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new("
                               "$s,'Read','Allow'));[IO.File]::SetAccessControl($p,$a)")
            self.assertEqual(path.read_bytes(), PUBLIC.encode("utf-8"))

    def test_generation_rechecks_membership_even_when_the_caller_raises(self):
        with private_fixture() as (root, path):
            path.rename(root / "leaf")
            visits = []
            original = Path.iterdir
            def observed(directory):
                if directory == root:
                    visits.append(directory)
                return original(directory)
            with patch.object(Path, "iterdir", observed):
                with self.assertRaisesRegex(ValueError, windows.REFUSAL):
                    with windows.hold_private_generation(root, ["leaf"]):
                        (root / "unexpected").write_bytes(b"SYNTHETIC")
                        raise RuntimeError("SYNTHETIC_ACTION_FAILURE")
            self.assertEqual(len(visits), 2)
            # Failure closes all handles while preserving unexpected data.
            self.assertTrue((root / "unexpected").exists())
            (root / "leaf").write_bytes(b"AFTER_FAILURE")

    def test_byte_reader_preserves_line_endings_binary_empty_and_maximum(self):
        with private_fixture() as (_, path):
            for payload in [b"SYNTHETIC\r\nNEXT\rLAST\n", b"\xff\0", b"",
                            b"x" * windows.MAX_BYTES]:
                with self.subTest(size=len(payload)):
                    path.write_bytes(payload)
                    self.assertEqual(windows.read_private_bytes(path), payload)
            path.write_bytes(b"SYNTHETIC\r\nNEXT\rLAST\n")
            self.assertEqual(private_file(path), "SYNTHETIC\nNEXT\nLAST\n")
            path.write_bytes(b"\xff")
            with self.assertRaisesRegex(ValueError, windows.REFUSAL):
                private_file(path)

    def test_byte_reader_retains_privacy_bounds_and_handle_sharing_guards(self):
        with private_fixture() as (root, path):
            with path.open("r+b"):
                with self.assertRaisesRegex(ValueError, windows.REFUSAL):
                    windows.read_private_bytes(path)
            linked = root / "linked-input"
            os.link(path, linked)
            try:
                with self.assertRaisesRegex(ValueError, windows.REFUSAL):
                    windows.read_private_bytes(path)
            finally:
                linked.unlink()
            path.write_bytes(b"x" * (windows.MAX_BYTES + 1))
            with self.assertRaisesRegex(ValueError, windows.REFUSAL):
                windows.read_private_bytes(path)
            path.write_bytes(PUBLIC.encode("utf-8"))
            quoted = str(path).replace("'", "''")
            powershell("$p='"+quoted+"';$a=Get-Acl -LiteralPath $p;"
                       "$s=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545');"
                       "$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new("
                       "$s,'Read','Allow'));[IO.File]::SetAccessControl($p,$a)")
            with self.assertRaisesRegex(ValueError, windows.REFUSAL):
                windows.read_private_bytes(path)
            self.assertEqual(path.read_bytes(), PUBLIC.encode("utf-8"))

    def test_empty_private_file_initialization_preserves_utf8_and_refuses_overwrite(self):
        with private_fixture() as (_, path):
            path.write_bytes(b"")
            value = "PUBLIC_SYNTHETIC_\u03bb\n"
            windows.write_empty_private_file(path, value)
            self.assertEqual(path.read_bytes(), value.encode("utf-8"))
            self.assertEqual(private_file(path), value)
            with self.assertRaisesRegex(ValueError, windows.WRITE_REFUSAL):
                windows.write_empty_private_file(path, PUBLIC)
            self.assertEqual(path.read_bytes(), value.encode("utf-8"))

    def test_initialization_rejects_public_acl_before_writing_any_bytes(self):
        with private_fixture() as (_, path):
            path.write_bytes(b"")
            quoted = str(path).replace("'", "''")
            powershell("$p='"+quoted+"';$a=Get-Acl -LiteralPath $p;"
                       "$s=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545');"
                       "$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new("
                       "$s,'Read','Allow'));[IO.File]::SetAccessControl($p,$a)")
            with self.assertRaisesRegex(ValueError, windows.WRITE_REFUSAL):
                windows.write_empty_private_file(path, PUBLIC)
            self.assertEqual(path.read_bytes(), b"")

    def test_initialization_refuses_other_writers_hardlinks_and_invalid_payloads(self):
        with private_fixture() as (root, path):
            path.write_bytes(b"")
            with path.open("r+b"):
                with self.assertRaisesRegex(ValueError, windows.WRITE_REFUSAL):
                    windows.write_empty_private_file(path, PUBLIC)
            self.assertEqual(path.read_bytes(), b"")
            other = root / "linked-input"
            os.link(path, other)
            with self.assertRaisesRegex(ValueError, windows.WRITE_REFUSAL):
                windows.write_empty_private_file(path, PUBLIC)
            other.unlink()
            for value in ["", "\0", "x" * (windows.MAX_BYTES + 1), "\ud800", b"bytes"]:
                with self.subTest(value_type=type(value).__name__), self.assertRaisesRegex(
                        ValueError, windows.WRITE_REFUSAL):
                    windows.write_empty_private_file(path, value)
                self.assertEqual(path.read_bytes(), b"")

    def test_private_ntfs_read_through_shared_owner(self):
        with private_fixture() as (_, path):
            # The real handle reader binds GetFileInformationByHandle's NTFS
            # volume/file index to Python's actual st_dev/st_ino on this host.
            self.assertEqual(private_file(path), PUBLIC)
            self.assertEqual(windows.read_private_file(path), PUBLIC)

    def test_effective_public_read_ace_refuses_and_does_not_rewrite_acl(self):
        with private_fixture() as (_, path):
            quoted = str(path).replace("'", "''")
            powershell("$p='"+quoted+"';$a=Get-Acl -LiteralPath $p;"
                       "$s=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545');"
                       "$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new("
                       "$s,'Read','Allow'));[IO.File]::SetAccessControl($p,$a)")
            with self.assertRaisesRegex(ValueError, windows.REFUSAL):
                private_file(path)
            # Read-only failure leaves the synthetic input untouched.
            self.assertEqual(path.read_text(encoding="utf-8"), PUBLIC)
            with self.assertRaisesRegex(ValueError, windows.REFUSAL):
                private_file(path)

    def test_existing_writer_and_hardlink_are_refused(self):
        with private_fixture() as (root, path):
            with path.open("r+b"):
                with self.assertRaisesRegex(ValueError, windows.REFUSAL):
                    private_file(path)
            self.assertEqual(private_file(path), PUBLIC)
            other = root / "hardlink.token"
            os.link(path, other)
            with self.assertRaisesRegex(ValueError, windows.REFUSAL):
                private_file(path)
            other.unlink()
            self.assertEqual(private_file(path), PUBLIC)

    def test_bounds_directory_ads_and_utf8_errors_are_fixed_refusals(self):
        with private_fixture() as (root, path):
            for value in [b"x" * (windows.MAX_BYTES + 1), b"\xff"]:
                path.write_bytes(value)
                with self.assertRaisesRegex(ValueError, windows.REFUSAL):
                    private_file(path)
            for invalid in [root, Path(str(path) + ":stream"), Path("relative.token")]:
                with self.assertRaisesRegex(ValueError, windows.REFUSAL):
                    private_file(invalid)

    def test_junction_ancestor_refuses(self):
        with private_fixture() as (root, path):
            target = root / "target"
            target.mkdir()
            (target / "operator.token").write_text(PUBLIC, encoding="utf-8")
            alias = root / "alias"
            powershell("New-Item -ItemType Junction -Path '"+str(alias).replace("'", "''")+
                       "' -Target '"+str(target).replace("'", "''")+"' | Out-Null")
            try:
                with self.assertRaisesRegex(ValueError, windows.REFUSAL):
                    private_file(alias / path.name)
            finally:
                # Remove only this known synthetic junction, never its target.
                alias.rmdir()


if __name__ == "__main__":
    unittest.main()
