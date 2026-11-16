"""Opt-in Linux worker execution with synthetic authority and tmpfs only."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from selfhost_windows_renewal_native import AUTHORITY_WORKER

# No network, host files, credentials, named volumes or deployment state.
# The caller supplies an already-cached immutable Linux Python image explicitly.
HARNESS = r"""
import contextlib,hashlib,io,json,os,pathlib,stat,sys
worker=json.load(sys.stdin)['worker']
binary=pathlib.Path('/operator/tool')
binary.write_text('''#!/usr/local/bin/python
import json,os,pathlib,sys
args=sys.argv[1:]
with open('/control/invocations','a') as f:f.write(' '.join(args)+'\\n')
if args==['--build-identity']:print('1'*40+':v1.2.3');raise SystemExit(0)
body=json.load(sys.stdin)
if args[1]=='approle-login':
 assert body=={}
 reply={'role_id':'synthetic-role','secret_id':'synthetic-secret',
   'names':['policy-'+str(n) for n in range(20 if os.environ.get('SYNTHETIC_CASE')=='wrong-policies' else 21)],
   'token':'SYNTHETIC_PRIVATE_TOKEN_123456789'}
 if os.environ.get('SYNTHETIC_CASE')=='extra-metadata':reply['unexpected']='synthetic'
 print(json.dumps(reply))
elif args[1]=='authority-check':
 assert body=={'token':'SYNTHETIC_PRIVATE_TOKEN_123456789','rotation':False}
 if os.environ.get('SYNTHETIC_FAIL_SCOPE')=='1':raise SystemExit(7)
 print('{"value":null}')
else:raise SystemExit(8)
''')
binary.chmod(0o700)
base={'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
 'source_sha':'1'*40,'release_tag':'v1.2.3','bao_addr':'https://not-contacted.invalid'}
log=pathlib.Path('/control/invocations')
for index,case in enumerate(['success','scope-failure','existing-folder','file-reservation-failure','bad-identity','wrong-policies','extra-metadata']):
 session=pathlib.Path('/control/recovery-session-'+str(index)*32)
 request=dict(base,session_dir=str(session))
 if log.exists():log.unlink()
 if case=='existing-folder':session.mkdir()
 if case=='bad-identity':request['source_sha']='2'*40
 os.environ['SYNTHETIC_CASE']=case
 os.environ['SYNTHETIC_FAIL_SCOPE']='1' if case=='scope-failure' else '0'
 previous_stdin=sys.stdin;out=io.StringIO();err=io.StringIO();failed=False
 actual_open=os.open
 def bounded_open(path,flags,*args,**kwargs):
  if case=='file-reservation-failure' and str(path)==str(session/'token'):
   raise OSError('synthetic file creation failure')
  return actual_open(path,flags,*args,**kwargs)
 try:
  sys.stdin=io.StringIO(json.dumps(request));os.open=bounded_open
  with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
   try:exec(compile(worker,'authority-worker','exec'),{})
   except BaseException:failed=True
 finally:sys.stdin=previous_stdin;os.open=actual_open
 assert 'SYNTHETIC_PRIVATE_TOKEN' not in out.getvalue()+err.getvalue()
 calls=log.read_text() if log.exists() else ''
 if case in ['success','scope-failure','wrong-policies','extra-metadata']:
  assert (session/'token').read_text()=='SYNTHETIC_PRIVATE_TOKEN_123456789'
  assert stat.S_IMODE(session.stat().st_mode)==0o700
  assert stat.S_IMODE((session/'token').stat().st_mode)==0o600
  assert 'approle-login' in calls
  assert ('authority-check' in calls)==(case in ['success','scope-failure'])
 else:assert 'approle-login' not in calls
 if case=='success':
  assert not failed
  assert json.loads(out.getvalue())=={'authority':True,'policy_count':21,'token_file':str(session/'token')}
 else:assert failed and out.getvalue()==''
print(json.dumps({'synthetic_worker_cases':7,'credentials_disclosed':False}))
"""


def test_actual_linux_worker_custody_and_failure_boundaries():
    image = os.environ.get('MARTY_WINDOWS_AUTHORITY_TEST_IMAGE')
    if not image:
        pytest.skip('explicit cached immutable Linux Python image required')
    import re
    assert re.fullmatch(r'[a-z0-9./_-]+@sha256:[0-9a-f]{64}', image)
    args = ['docker', '--host', os.environ['MARTY_WINDOWS_AUTHORITY_TEST_DOCKER_HOST'],
            'run', '--rm', '--pull', 'never', '-i', '--network', 'none',
            '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--memory', '128m', '--cpus', '1',
            '--tmpfs', '/operator:rw,exec,nosuid,nodev,size=1m,mode=0700',
            '--tmpfs', '/control:rw,noexec,nosuid,nodev,size=1m,mode=0700',
            '--entrypoint', 'python', image, '-c', HARNESS]
    result = subprocess.run(args, input=json.dumps({'worker': AUTHORITY_WORKER}).encode(),
                            capture_output=True, timeout=120)
    # Only synthetic data exists in this fixture. Surface diagnostics on failure.
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    assert json.loads(result.stdout) == {'synthetic_worker_cases': 7, 'credentials_disclosed': False}
