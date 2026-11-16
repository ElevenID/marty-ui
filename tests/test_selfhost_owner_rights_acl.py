"""OWNER_RIGHTS is the proven current object owner; no permission changes or I/O."""
import sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from selfhost_windows_inputs import checked_acl,FULL_CONTROL
USER="S-1-5-21-1-2-3-1001"
OWNER_RIGHTS=("S-1-3-4",0,0x10,FULL_CONTROL)

def test_owner_rights_is_an_alternate_proven_current_owner():
    checked_acl(USER,USER,[OWNER_RIGHTS])
    checked_acl(USER,USER,[("S-1-5-18",0,0x10,FULL_CONTROL),("S-1-5-32-544",0,0x10,FULL_CONTROL),OWNER_RIGHTS])
    checked_acl(USER,USER,[(USER,0,0x10,FULL_CONTROL)])

@pytest.mark.parametrize("owner,entries",[
    ("S-1-5-21-1-2-3-2002",[OWNER_RIGHTS]),
    (USER,[OWNER_RIGHTS,(USER,0,0,FULL_CONTROL)]),
    (USER,[OWNER_RIGHTS,OWNER_RIGHTS]),
    (USER,[OWNER_RIGHTS,("S-1-1-0",0,0,FULL_CONTROL)]),
    (USER,[("S-1-3-4",0,0x18,FULL_CONTROL)]),
    (USER,[("S-1-3-4",1,0,FULL_CONTROL)]),
    (USER,[("S-1-3-4",0,0,0x120089)]),
])
def test_owner_rights_cannot_widen_or_duplicate_admission(owner,entries):
    with pytest.raises(ValueError):checked_acl(owner,USER,entries)
