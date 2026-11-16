"""Opt-in Linux worker filesystem/escrow controls; synthetic tmpfs only."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from selfhost_windows_renewal_native import PRODUCER_ASSEMBLE, PRODUCER_PREPARE

HARNESS=r'''
import base64,contextlib,hashlib,io,json,os,pathlib,subprocess,sys
workers=json.load(sys.stdin);os.umask(0o077)
binary=pathlib.Path('/operator/tool');binary.write_bytes(b'PUBLIC_SYNTHETIC_BINARY')
authority=pathlib.Path('/control/token');authority.write_text('SYNTHETIC_PRIVATE_AUTHORITY')
outputs={'keycloak_signing_kms_token':'SYNTHETIC_PRIVATE_SIGNING',
 'keycloak_master_rs256_cert':'PUBLIC_CERT_MASTER','keycloak_11id_rs256_cert':'PUBLIC_CERT_11ID',
 **{f'keycloak_{realm}_{purpose}_token':f'SYNTHETIC_PRIVATE_{realm}_{purpose}'
 for realm in ['master','11id'] for purpose in ['cookie','ciba']}}
cases=['success','timeout','nonzero','oversized','malformed','duplicate-token']
for index,case in enumerate(cases):
 root=pathlib.Path('/control/windows-renewal-'+f'{index:032x}')
 current={f'field_{i}':base64.b64encode(b'SYNTHETIC_PRIVATE_CURRENT').decode() for i in range(40)}
 def execute(worker,request,fail=False):
  original=sys.stdin;out=io.StringIO();err=io.StringIO();failed=False
  try:
   sys.stdin=io.StringIO(json.dumps(request))
   with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
    try:exec(compile(worker,'synthetic-producer-worker','exec'),{})
    except BaseException:failed=True
  finally:sys.stdin=original
  assert failed==fail
  if fail:assert out.getvalue()==''
  else:return json.loads(out.getvalue())
 assert execute(workers['prepare'],{'root':str(root),'current':current})=={'prepared':True}
 assert (root/'source/field_0').read_bytes()==b'SYNTHETIC_PRIVATE_CURRENT'
 for p in root.rglob('*'):
  assert p.stat().st_mode&0o777==(0o700 if p.is_dir() else 0o600)
 # Exclusive creation refuses replay without replacing the source snapshot.
 execute(workers['prepare'],{'root':str(root),'current':current},fail=True)
 captured=json.dumps(outputs).encode()
 if case=='timeout':captured=b'SYNTHETIC_PRIVATE_PARTIAL'
 elif case=='oversized':captured=b'x'*(128*1024+1)
 elif case=='malformed':captured=b'SYNTHETIC_PRIVATE_INVALID_JSON'
 elif case=='duplicate-token':
  altered=dict(outputs,keycloak_signing_kms_token=outputs['keycloak_master_cookie_token'])
  captured=json.dumps(altered).encode()
 calls=[];original_run=subprocess.run
 def run(args,**kwargs):
  if args[1:]==['--build-identity']:
   return subprocess.CompletedProcess(args,0,b'PUBLIC_SOURCE:PUBLIC_TAG',b'')
  if args[1:3]==['operator','keycloak-provision']:
   escrow=root/'keycloak-response.private.json'
   assert escrow.is_file() and escrow.stat().st_size==0 and escrow.stat().st_mode&0o777==0o600
   assert json.loads(kwargs['input'])['token']=='SYNTHETIC_PRIVATE_AUTHORITY'
   if case=='timeout':raise subprocess.TimeoutExpired(args,90,output=captured)
   return subprocess.CompletedProcess(args,7 if case=='nonzero' else 0,captured,b'')
  assert case=='success'
  body=json.loads(kwargs['input']);op=args[2];calls.append(op)
  if op=='generation':value=40 if body['operation']=='stage' else [40,39]
  else:
   assert op in ['activation-tokens','activation-certificates']
   assert body['minimum_ttl']==3600 and body['require_orphan_new'] is True
   value=None
  return subprocess.CompletedProcess(args,0,json.dumps({'value':value}).encode(),b'')
 request={'root':str(root),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
  'source_sha':'PUBLIC_SOURCE','release_tag':'PUBLIC_TAG','authority':str(authority),
  'bao_addr':'https://synthetic.invalid:8200','files':40,'minimum_ttl':3600}
 try:
  subprocess.run=run
  result=execute(workers['assemble'],request,fail=case!='success')
 finally:subprocess.run=original_run
 escrow=root/'keycloak-response.private.json'
 assert escrow.read_bytes()==captured and escrow.stat().st_mode&0o777==0o600
 if case=='success':
  assert result=={'files':40,'changed_files':39,'native_verified':True}
  assert calls==['generation','generation','activation-tokens','activation-certificates']
  assert {p.name:p.read_text() for p in (root/'keycloak').iterdir()}==outputs
 else:assert calls==[] and not list((root/'keycloak').iterdir())
print(json.dumps({'cases':len(cases),'escrow_persisted_before_refusal':True,'production_access':False}))
'''


def test_actual_linux_producer_worker_escrow_and_exclusive_snapshot():
    image=os.environ.get('MARTY_WINDOWS_AUTHORITY_TEST_IMAGE')
    if not image:pytest.skip('explicit cached immutable Linux Python image required')
    assert re.fullmatch(r'[a-z0-9./_-]+@sha256:[0-9a-f]{64}',image)
    args=['docker','--host',os.environ['MARTY_WINDOWS_AUTHORITY_TEST_DOCKER_HOST'],
        'run','--rm','--pull','never','-i','--network','none','--read-only','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--memory','128m','--cpus','1','--log-driver','none',
        '--tmpfs','/control:rw,noexec,nosuid,nodev,size=4m,mode=0700',
        '--tmpfs','/operator:rw,noexec,nosuid,nodev,size=1m,mode=0700',
        '--entrypoint','python',image,'-c',HARNESS]
    result=subprocess.run(args,input=json.dumps({'prepare':PRODUCER_PREPARE,'assemble':PRODUCER_ASSEMBLE}).encode(),
        capture_output=True,timeout=120)
    assert result.returncode==0,result.stderr.decode(errors='replace')
    assert json.loads(result.stdout)=={'cases':6,'escrow_persisted_before_refusal':True,'production_access':False}
