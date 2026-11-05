"""Read-only signed Linux operator transport for held Windows renewal inputs.

The caller selects an already release-verified operator; digest and embedded
source/tag identity are rechecked while the NTFS asset remains held. This does
not replace signature/provenance verification or admit a release for production.
"""
from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

from selfhost_windows_inputs import hold_private_input


WORKER = r'''
import base64,hashlib,json,pathlib,subprocess,sys
d=json.load(sys.stdin)
binary='/operator/tool'
assert hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()==d['binary_sha256']
p=subprocess.run([binary,'--build-identity'],capture_output=True,timeout=20)
assert p.returncode==0 and p.stdout.decode().strip()==d['source_sha']+':'+d['release_tag']
roots={'old':d['current'],'new':d['renewed']}
for role,root in roots.items():
 assert sorted(p.name for p in pathlib.Path(root).iterdir())==sorted(d['bytes'][role])
 for name,value in d['bytes'][role].items():
  expected=base64.b64decode(value,validate=True)
  assert len(expected)<=65536
  assert pathlib.Path(root,name).read_bytes()==expected
token=pathlib.Path(d['token_file']).read_text().strip()
def native(op,body,network=False):
 args=[binary,'operator',op]
 if network:args += [d['bao_addr'],'/input/ca.crt']
 p=subprocess.run(args,input=json.dumps(body).encode(),capture_output=True,timeout=90)
 assert p.returncode==0
 r=json.loads(p.stdout);assert isinstance(r,dict) and set(r)=={'value'}
 return r['value']
assert native('authority-check',{'token':token,'rotation':False},True) is None
assert native('generation',{'operation':'verify','current':roots['old'],'candidate':roots['new'],
                           'ca_overlap':False,'ca_retire':False})==[d['count'],d['changed']]
body={'token':token,'old':roots['old'],'new':roots['new'],'minimum_ttl':d['minimum_ttl'],
      'require_orphan_new':True,'require_orphan_old':False,'replacement':None,'retiring':False}
for op in ['activation-tokens','activation-certificates']:assert native(op,body,True) is None
print(json.dumps({'authority':True,'generation':True,'tokens':True,'certificates':True}))
'''


def preflight(config, project, old, new, docker_prefix):
    def require(value):
        if not value:
            raise ValueError('Windows native renewal preflight refused')
    require(set(old) == set(new) and 0 < len(old) <= 512)
    require(all(re.fullmatch(r'[a-z][a-z0-9_]{0,127}', name) for name in old))
    changed = sum(old[name] != new[name] for name in old)
    require(changed > 0)
    require(re.fullmatch(r'[0-9a-f]{64}', config['binary_sha256']))
    require(re.fullmatch(r'[0-9a-f]{40}', config['source_sha']))
    require(re.fullmatch(r'v\d+\.\d+\.\d+(?:-nightly\.20\d{6}\.[1-9]\d*)?', config['release_tag']))
    require(re.fullmatch(r'[a-z0-9./_-]+@sha256:[0-9a-f]{64}', config['helper_image']))
    require(config['control_volume'] == project + '-renewal-control')
    require(config['network'] == project + '_default')
    require(config['bao_addr'] == 'https://openbao:8200')
    require(type(config['minimum_ttl']) is int and 60 <= config['minimum_ttl'] <= 28800)
    for key in ['current', 'renewed', 'token_file']:
        p = PurePosixPath(config[key])
        require(p.is_relative_to('/control') and len(p.parts) >= 3
                and '..' not in p.parts and str(p) == config[key])
    require(config['current'] != config['renewed'])
    with hold_private_input(Path(config['binary']), max_bytes=256 * 1024 * 1024) as binary:
        require(hashlib.sha256(binary).hexdigest() == config['binary_sha256'])
        with hold_private_input(Path(config['ca_file'])):
            request = {key: config[key] for key in ['binary_sha256', 'source_sha', 'release_tag',
                                                  'bao_addr', 'current', 'renewed', 'token_file', 'minimum_ttl']}
            request.update(count=len(old), changed=changed, bytes={
                role: {name: base64.b64encode(raw).decode('ascii') for name, raw in values.items()}
                for role, values in [('old', old), ('new', new)]})
            args = [*docker_prefix, 'run', '--rm', '--pull', 'never', '-i', '--read-only',
                    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                    '--network', config['network'], '--mount',
                    f'type=volume,src={config["control_volume"]},dst=/control,readonly', '--mount',
                    f'type=bind,src={config["binary"]},dst=/operator/tool,readonly', '--mount',
                    f'type=bind,src={config["ca_file"]},dst=/input/ca.crt,readonly',
                    '--entrypoint', 'python', config['helper_image'], '-c', WORKER]
            p = subprocess.run(args, input=json.dumps(request).encode(), capture_output=True, timeout=420)
            require(p.returncode == 0)
            require(json.loads(p.stdout) == {'authority': True, 'generation': True,
                                            'tokens': True, 'certificates': True})
