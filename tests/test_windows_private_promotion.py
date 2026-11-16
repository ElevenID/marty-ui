"""Promotion binds one checked NTFS file handle and never overwrites a target."""
import os
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_selfhost_windows_inputs import private_fixture, windows

pytestmark=pytest.mark.skipif(os.name!='nt',reason='Actual NTFS promotion')

@pytest.mark.parametrize('fault',[None,'body','destination'])
def test_checked_handle_promotion_is_exclusive_and_preserves_identity(fault):
    with private_fixture() as (root,source):
        target=root/'published'
        before=source.stat()
        if fault=='destination':target.write_bytes(b'PUBLIC_EXISTING')
        def promote():
            with windows._held_private_input(source,_rename_to=target) as raw:
                assert raw
                if fault=='body':raise ValueError('PUBLIC_BODY_FAILURE')
        if fault:
            with pytest.raises(ValueError):promote()
            assert source.exists()
            if fault=='body':assert not target.exists()
            else:assert target.read_bytes()==b'PUBLIC_EXISTING'
        else:
            promote()
            assert not source.exists() and target.stat().st_ino==before.st_ino
