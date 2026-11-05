"""Opt-in actual Linux export worker; synthetic tmpfs, network disabled."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from selfhost_windows_renewal_native import EXPORT_WORKER

HARNESS=r'''
import base64,contextlib,hashlib,io,json,os,pathlib,sys
worker=json.load(sys.stdin)['worker']
os.umask(0o077)
parent=pathlib.Path('/control/next-r4');parent.mkdir(mode=0o700)
root=parent/'application-mail-generation';root.mkdir(mode=0o700)
values={'empty':b'','leaf_cert':'SYNTHETIC_UTF8_\u00e9'.encode(),'a_token':b'SYNTHETIC_PRIVATE_SENTINEL'+b'x'*24000}
for name,value in values.items():
 (root/name).write_bytes(value);(root/name).chmod(0o600)
base={'mirror':str(root),'names':sorted(values),'part':None,'sha256':None}
def run(request,*,fail=False):
 out=io.StringIO();err=io.StringIO();original=sys.stdin;failed=False
 try:
  sys.stdin=io.StringIO(json.dumps(request))
  with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
   try:exec(compile(worker,'generation-export-worker','exec'),{})
   except BaseException:failed=True
 finally:sys.stdin=original
 assert failed==fail
 if fail:assert out.getvalue()=='';return
 assert len(out.getvalue().encode())<=29000
 return json.loads(out.getvalue())
manifest=run(base);parts=[]
for i in range(manifest['parts']):
 part=run(dict(base,part=i,sha256=manifest['sha256']))
 assert part['part']==i and part['sha256']==manifest['sha256'];parts.append(part['chunk'])
raw=''.join(parts).encode()
assert len(raw)==manifest['length'] and hashlib.sha256(raw).hexdigest()==manifest['sha256']
assert {k:base64.b64decode(v,validate=True) for k,v in json.loads(raw).items()}==values
assert manifest['parts']>=3
# Known snapshot changed between requests: reject before publishing any chunk.
(root/'empty').write_bytes(b'changed')
run(dict(base,part=0,sha256=manifest['sha256']),fail=True)
(root/'empty').write_bytes(b'')
for case in ['mode','hardlink','symlink','extra','private-key','binary','oversized','parent-symlink']:
 target=root/'empty'
 if case=='mode':target.chmod(0o644)
 elif case=='hardlink':os.link(target,'/control/alias')
 elif case=='symlink':target.unlink();target.symlink_to('/etc/passwd')
 elif case=='extra':(root/'foreign').write_bytes(b'PUBLIC')
 elif case=='private-key':target.write_bytes(b'PRIVATE KEY')
 elif case=='binary':target.write_bytes(b'\0')
 elif case=='oversized':target.write_bytes(b'x'*65537)
 else:
  pathlib.Path('/control/link').symlink_to(parent,target_is_directory=True)
  run(dict(base,mirror='/control/link/application-mail-generation'),fail=True)
  pathlib.Path('/control/link').unlink();continue
 run(base,fail=True)
 if case=='hardlink':pathlib.Path('/control/alias').unlink()
 if case=='extra':(root/'foreign').unlink()
 if target.is_symlink():target.unlink();target.touch()
 target.write_bytes(b'');target.chmod(0o600)
# Replace an ancestor after it has been opened. Relative held-directory reads
# must stay on original file identities and final binding must refuse the alias.
foreign=pathlib.Path('/control/foreign');foreign.mkdir(mode=0o700)
other=foreign/root.name;other.mkdir(mode=0o700)
for name in values:(other/name).write_bytes(b'SYNTHETIC_FOREIGN');(other/name).chmod(0o600)
original_open=os.open;original_inodes={name:(root/name).stat().st_ino for name in values}
swapped=[False]
def swap_parent(name,flags,*args,**kwargs):
 handle=original_open(name,flags,*args,**kwargs)
 if name==root.name and kwargs.get('dir_fd') is not None and not swapped[0]:
  parent.rename('/control/moved');parent.symlink_to(foreign,target_is_directory=True);swapped[0]=True
 if name in original_inodes:assert os.fstat(handle).st_ino==original_inodes[name]
 return handle
try:
 os.open=swap_parent;run(base,fail=True)
finally:
 os.open=original_open
 if swapped[0]:parent.unlink();pathlib.Path('/control/moved').rename(parent)
# Modify the first file while the final file is read: the whole-batch final
# checks must detect it, rather than just checking each file immediately.
original_fdopen=os.fdopen;last_inode=(root/'leaf_cert').stat().st_ino
class MutatingReader:
 def __init__(self,f):self.f=f
 def __enter__(self):return self
 def __exit__(self,*args):return self.f.__exit__(*args)
 def fileno(self):return self.f.fileno()
 def read(self,*args):
  result=self.f.read(*args);(root/'a_token').write_bytes(b'SYNTHETIC_CHANGED_LATE');return result
def fdopen(handle,*args,**kwargs):
 f=original_fdopen(handle,*args,**kwargs)
 return MutatingReader(f) if os.fstat(handle).st_ino==last_inode else f
try:
 os.fdopen=fdopen;run(base,fail=True)
finally:
 os.fdopen=original_fdopen;(root/'a_token').write_bytes(values['a_token'])
print(json.dumps({'exact_multichunk_bytes':True,'refusal_cases':11,'host_or_named_volume_mounts':False}))
'''


def test_actual_linux_export_worker_inventory_permissions_and_chunk_coherence():
    image=os.environ.get('MARTY_WINDOWS_AUTHORITY_TEST_IMAGE')
    if not image:pytest.skip('explicit cached immutable Linux Python image required')
    assert re.fullmatch(r'[a-z0-9./_-]+@sha256:[0-9a-f]{64}',image)
    args=['docker','--host',os.environ['MARTY_WINDOWS_AUTHORITY_TEST_DOCKER_HOST'],
        'run','--rm','--pull','never','-i','--network','none','--read-only','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--memory','128m','--cpus','1',
        '--tmpfs','/control:rw,noexec,nosuid,nodev,size=2m,mode=0700',
        '--entrypoint','python',image,'-c',HARNESS]
    result=subprocess.run(args,input=json.dumps({'worker':EXPORT_WORKER}).encode(),capture_output=True,timeout=120)
    assert result.returncode==0,result.stderr.decode(errors='replace')
    assert json.loads(result.stdout)=={'exact_multichunk_bytes':True,'refusal_cases':11,'host_or_named_volume_mounts':False}
