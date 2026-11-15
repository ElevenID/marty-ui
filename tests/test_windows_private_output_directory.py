"""Mutable output membership does not relax held NTFS identity or privacy."""
import os
from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_selfhost_windows_inputs import private_fixture, powershell, windows

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='NTFS private directory lease')


def test_output_directory_allows_owned_membership_change():
    with private_fixture() as (root, _):
        directory = root/'output'
        directory.mkdir()
        with windows._held_private_input(directory, directory=True, mutable_directory=True):
            (directory/'public').write_bytes(b'PUBLIC')
        assert (directory/'public').read_bytes() == b'PUBLIC'


def test_output_directory_still_rejects_late_acl_change():
    with private_fixture() as (root, _):
        directory = root/'output'
        directory.mkdir()
        quoted = str(directory).replace("'", "''")
        with pytest.raises(ValueError):
            with windows._held_private_input(directory, directory=True, mutable_directory=True):
                powershell("$p='"+quoted+"';$a=Get-Acl -LiteralPath $p;"
                    "$s=[Security.Principal.SecurityIdentifier]::new('S-1-1-0');"
                    "$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($s,'Read','Allow'));"
                    "Set-Acl -LiteralPath $p -AclObject $a")


def test_output_mode_never_allows_mutable_file_input():
    with private_fixture() as (_, path):
        with pytest.raises(ValueError):
            with windows._held_private_input(path, mutable_directory=True):
                pytest.fail('Mutable file mode admitted')
