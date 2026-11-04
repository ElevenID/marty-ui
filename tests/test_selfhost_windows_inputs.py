"""Synthetic-only private input controls, including actual Windows handles/ACLs."""
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

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
