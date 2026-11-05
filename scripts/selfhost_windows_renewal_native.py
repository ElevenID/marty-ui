"""Signed Linux operator transport for held Windows renewal inputs.

The caller selects an already release-verified operator; digest and embedded
source/tag identity are rechecked while the NTFS asset remains held. This does
not replace signature/provenance verification or admit a release for production.
Preflights are read-only; scoped reauthentication writes only a fresh session.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path, PurePosixPath

from selfhost_windows_inputs import hold_private_input

EXPORT_CHUNK_BYTES = 12000
EXPORT_LIMIT_BYTES = 8 * 1024 * 1024
EXPORT_WORKER = r'''
import base64,contextlib,hashlib,json,os,pathlib,stat,sys
d=json.load(sys.stdin);root=pathlib.Path(d['mirror'])
def identity(m):
 return (m.st_dev,m.st_ino,m.st_mode,m.st_uid,m.st_gid,m.st_nlink,m.st_size,m.st_mtime_ns,m.st_ctime_ns)
with contextlib.ExitStack() as held:
 directory_flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
 fd=os.open('/control',directory_flags);held.callback(os.close,fd)
 origin=os.fstat(fd);assert stat.S_ISDIR(origin.st_mode) and origin.st_uid==origin.st_gid==0
 directories=[]
 for name in root.parts[2:]:
  parent=fd;fd=os.open(name,directory_flags,dir_fd=parent);held.callback(os.close,fd)
  original=os.fstat(fd);assert stat.S_ISDIR(original.st_mode) and original.st_uid==original.st_gid==0
  directories.append((parent,name,fd,original))
 assert stat.S_IMODE(original.st_mode)==0o700
 assert sorted(os.listdir(fd))==d['names']
 files=[];values={}
 for name in d['names']:
  original=os.stat(name,dir_fd=fd,follow_symlinks=False)
  assert stat.S_ISREG(original.st_mode) and stat.S_IMODE(original.st_mode)==0o600
  assert original.st_uid==original.st_gid==0 and original.st_nlink==1 and original.st_size<=65536
  handle=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
  f=held.enter_context(os.fdopen(handle,'rb'))
  assert identity(os.fstat(f.fileno()))==identity(original)
  files.append((name,f,original))
 for name,f,original in files:
  raw=f.read(65537)
  assert len(raw)<=65536 and b'\0' not in raw and b'PRIVATE KEY' not in raw
  raw.decode('utf-8');values[name]=base64.b64encode(raw).decode('ascii')
 for name,f,original in files:
  assert identity(os.fstat(f.fileno()))==identity(original)
  assert identity(os.stat(name,dir_fd=fd,follow_symlinks=False))==identity(original)
 assert sorted(os.listdir(fd))==d['names']
 for parent,name,handle,original in reversed(directories):
  assert identity(os.fstat(handle))==identity(original)
  assert identity(os.stat(name,dir_fd=parent,follow_symlinks=False))==identity(original)
 assert identity(os.stat('/control',follow_symlinks=False))==identity(origin)
payload=json.dumps(values,sort_keys=True,separators=(',',':')).encode()
assert 0<len(payload)<=8388608
digest=hashlib.sha256(payload).hexdigest();parts=(len(payload)+11999)//12000
if d['part'] is None:result={'length':len(payload),'sha256':digest,'parts':parts}
else:
 assert digest==d['sha256'] and type(d['part']) is int and 0<=d['part']<parts
 result={'sha256':digest,'part':d['part'],'chunk':payload[d['part']*12000:(d['part']+1)*12000].decode('ascii')}
encoded=json.dumps(result);assert len(encoded.encode())<=29000
print(encoded)
'''


def export_generation(config, mirror):
    """Return private leaf bytes through bounded read-only chunks, never stdout.

    The generation owner must hold its project lease and run native admission
    over the resulting held Windows files. Export alone admits no credentials,
    writes no host files and cannot select, mint or activate a generation.
    """
    from selfhost_windows_renewal import UncertainComposeMutation
    uncertain=False;owned_processes_zero=False
    try:
        return _export_generation(config,mirror)
    except UncertainComposeMutation as error:
        uncertain=True
        owned_processes_zero=getattr(error,'owned_processes_zero',False) is True
    except Exception:
        pass
    # Raise outside the except suite: parser/UTF8 exceptions retain private
    # data, and uncertain exceptions retain private chunks in their traceback
    # or prior exception chain even after their direct tails are cleared.
    if uncertain:
        clean=UncertainComposeMutation('Windows generation export requires transport inspection')
        clean.stdout=clean.stderr=b'';clean.owned_processes_zero=owned_processes_zero
        raise clean
    raise ValueError('Windows generation export refused')


def _export_generation(config, mirror):
    from selfhost_windows_renewal import Docker, run_owned_mutation
    from selfhost_windows_selection import decode

    def require(value):
        if not value:raise ValueError('Windows generation export refused')
    config=json.loads(json.dumps(config));project=config['project'];native=config['native']
    require(re.fullmatch(r'marty-(?:selfhost|production)-[a-z0-9][a-z0-9-]{0,59}',project))
    require(native['control_volume']==project+'-renewal-control')
    require(re.fullmatch(r'[a-z0-9./_-]+@sha256:[0-9a-f]{64}',native['helper_image']))
    require(isinstance(mirror,str))
    path=PurePosixPath(mirror)
    require(str(path)==mirror and path.is_relative_to('/control') and len(path.parts)>=4
            and '..' not in path.parts and path.name in {'generation','application-generation','application-mail-generation'})
    require(all(re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,127}',name) for name in path.parts[2:]))
    deadline=time.monotonic()+600
    with hold_private_input(Path(config['compose_file']),max_bytes=2*1024*1024) as raw:
        require(hashlib.sha256(raw).hexdigest()==config['compose_sha256'])
        model=decode(raw)
        require(isinstance(model,dict) and isinstance(model.get('secrets'),dict))
        names=sorted(model['secrets'])
        require(0<len(names)<=512 and all(re.fullmatch(r'[a-z][a-z0-9_]{0,127}',name) for name in names))
        docker=Docker(config['docker_host'],config['engine_id'])
        volumes=docker.json(['volume','inspect',native['control_volume']])
        require(isinstance(volumes,list) and len(volumes)==1 and volumes[0]['Name']==native['control_volume']
                and volumes[0]['Driver']=='local' and volumes[0].get('Options') in (None,{}))
        def fetch(part=None,digest=None):
            remaining=deadline-time.monotonic();require(remaining>0)
            request={'mirror':mirror,'names':names,'part':part,'sha256':digest}
            args=[*docker.prefix,'run','--rm','--pull','never','-i','--log-driver','none','--network','none','--read-only',
                '--cap-drop','ALL','--security-opt','no-new-privileges','--memory','128m','--cpus','1',
                '--mount',f'type=volume,src={native["control_volume"]},dst=/control,readonly,volume-nocopy',
                '--entrypoint','python',native['helper_image'],'-c',EXPORT_WORKER]
            p=run_owned_mutation(args,stdin_bytes=json.dumps(request).encode(),timeout=min(60,remaining))
            require(p.returncode==0 and 0<len(p.stdout)<=29000)
            require(time.monotonic()<deadline)
            return decode(p.stdout)
        manifest=fetch()
        require(isinstance(manifest,dict) and set(manifest)=={'length','sha256','parts'})
        length=manifest['length'];digest=manifest['sha256'];parts=manifest['parts']
        require(type(length) is int and 0<length<=EXPORT_LIMIT_BYTES
                and isinstance(digest,str) and re.fullmatch(r'[0-9a-f]{64}',digest)
                and type(parts) is int and parts==(length+EXPORT_CHUNK_BYTES-1)//EXPORT_CHUNK_BYTES)
        chunks=[]
        for index in range(parts):
            part=fetch(index,digest)
            require(isinstance(part,dict) and set(part)=={'sha256','part','chunk'}
                    and part['sha256']==digest and type(part['part']) is int and part['part']==index
                    and isinstance(part['chunk'],str) and part['chunk'].isascii())
            chunk=part['chunk'].encode('ascii')
            require(len(chunk)==min(EXPORT_CHUNK_BYTES,length-index*EXPORT_CHUNK_BYTES))
            chunks.append(chunk)
        payload=b''.join(chunks)
        require(len(payload)==length and hashlib.sha256(payload).hexdigest()==digest)
        encoded=decode(payload)
        require(isinstance(encoded,dict) and sorted(encoded)==names
                and json.dumps(encoded,sort_keys=True,separators=(',',':')).encode()==payload)
        values={}
        for name in names:
            require(isinstance(encoded[name],str) and len(encoded[name])<=87384)
            value=base64.b64decode(encoded[name],validate=True)
            require(len(value)<=65536 and base64.b64encode(value).decode('ascii')==encoded[name]
                    and b'\0' not in value and b'PRIVATE KEY' not in value)
            value.decode('utf-8');values[name]=value
    require(time.monotonic()<deadline)
    return values

AUTHORITY_WORKER = r'''
import hashlib,json,os,pathlib,subprocess,sys
d=json.load(sys.stdin)
binary='/operator/tool'
assert hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()==d['binary_sha256']
p=subprocess.run([binary,'--build-identity'],capture_output=True,timeout=20)
assert p.returncode==0 and p.stdout.decode().strip()==d['source_sha']+':'+d['release_tag']
os.umask(0o077)
folder=pathlib.Path(d['session_dir']);folder.mkdir(mode=0o700)
fd=os.open(folder/'token',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
p=subprocess.run([binary,'operator','approle-login','renewal',d['bao_addr'],'/input/ca.crt','/control/identity'],
                 input=b'{}',capture_output=True,timeout=90)
assert p.returncode==0
login=json.loads(p.stdout)
assert isinstance(login,dict) and isinstance(login.get('token'),str) and 20<=len(login['token'])<=8192
with os.fdopen(fd,'w') as f:
 f.write(login['token']);f.flush();os.fsync(f.fileno())
for directory in [folder,folder.parent]:
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
assert set(login)=={'role_id','secret_id','names','token'}
assert isinstance(login['names'],list) and len(login['names'])==len(set(login['names']))==21
assert all(isinstance(name,str) for name in login['names'])
p=subprocess.run([binary,'operator','authority-check',d['bao_addr'],'/input/ca.crt'],
                 input=json.dumps({'token':login['token'],'rotation':False}).encode(),capture_output=True,timeout=90)
assert p.returncode==0 and json.loads(p.stdout)=={'value':None}
print(json.dumps({'authority':True,'policy_count':21,'token_file':str(folder/'token')}))
'''


def reauthenticate(config, project, docker_prefix, session_dir):
    """Refresh existing scoped enrollment; print/store no credentials on host."""
    def require(value):
        if not value:raise ValueError('Windows scoped authority refresh refused')
    require(re.fullmatch(r'marty-(?:selfhost|production)-[a-z0-9][a-z0-9-]{0,59}',project))
    require(config['control_volume']==project+'-renewal-control' and config['network']==project+'_default')
    require(config['bao_addr']=='https://openbao:8200')
    require(re.fullmatch(r'/control/recovery-session-[0-9a-f]{32}',session_dir))
    require(re.fullmatch(r'[0-9a-f]{64}',config['binary_sha256']))
    require(re.fullmatch(r'[0-9a-f]{40}',config['source_sha']))
    require(re.fullmatch(r'v\d+\.\d+\.\d+(?:-nightly\.20\d{6}\.[1-9]\d*)?',config['release_tag']))
    require(re.fullmatch(r'[a-z0-9./_-]+@sha256:[0-9a-f]{64}',config['helper_image']))
    # Docker must not silently create an empty control volume during recovery.
    p=subprocess.run([*docker_prefix,'volume','inspect',config['control_volume']],capture_output=True,timeout=30)
    require(p.returncode==0 and len(p.stdout)<=65536)
    volumes=json.loads(p.stdout)
    require(isinstance(volumes,list) and len(volumes)==1 and volumes[0]['Name']==config['control_volume']
            and volumes[0]['Driver']=='local' and volumes[0].get('Options') in (None,{}))
    with hold_private_input(Path(config['binary']),max_bytes=256*1024*1024) as binary:
        require(hashlib.sha256(binary).hexdigest()==config['binary_sha256'])
        with hold_private_input(Path(config['ca_file'])):
            request={k:config[k] for k in ['binary_sha256','source_sha','release_tag','bao_addr']}
            request['session_dir']=session_dir
            args=[*docker_prefix,'run','--rm','--pull','never','-i','--read-only','--cap-drop','ALL',
                '--security-opt','no-new-privileges','--network',config['network'],'--memory','256m','--cpus','1',
                '--mount',f'type=volume,src={config["control_volume"]},dst=/control',
                '--mount',f'type=bind,src={config["binary"]},dst=/operator/tool,readonly',
                '--mount',f'type=bind,src={config["ca_file"]},dst=/input/ca.crt,readonly',
                '--entrypoint','python',config['helper_image'],'-c',AUTHORITY_WORKER]
            from selfhost_windows_renewal import run_owned_mutation
            p=run_owned_mutation(args,stdin_bytes=json.dumps(request).encode(),timeout=240)
            require(p.returncode==0)
            expected={'authority':True,'policy_count':21,'token_file':session_dir+'/token'}
            require(json.loads(p.stdout)==expected)
    return expected['token_file']

WORKER = r'''
import base64,hashlib,json,os,pathlib,subprocess,sys
d=json.load(sys.stdin)
binary='/operator/tool'
assert hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()==d['binary_sha256']
p=subprocess.run([binary,'--build-identity'],capture_output=True,timeout=20)
assert p.returncode==0 and p.stdout.decode().strip()==d['source_sha']+':'+d['release_tag']
mirrors={'old':d['current'],'new':d['renewed']}
roots={}
os.umask(0o077)
for role,root in mirrors.items():
 assert sorted(p.name for p in pathlib.Path(root).iterdir())==sorted(d['bytes'][role])
 snapshot=pathlib.Path('/proof',role);snapshot.mkdir(mode=0o700)
 roots[role]=str(snapshot)
 for name,value in d['bytes'][role].items():
  expected=base64.b64decode(value,validate=True)
  assert len(expected)<=65536
  assert pathlib.Path(root,name).read_bytes()==expected
  fd=os.open(snapshot/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as f:
   assert f.write(expected)==len(expected);f.flush();os.fsync(f.fileno())
token=pathlib.Path(d['token_file']).read_text().strip()
def native(op,body,network=False):
 args=[binary,'operator',op]
 if network:args += [d['bao_addr'],'/input/ca.crt']
 p=subprocess.run(args,input=json.dumps(body).encode(),capture_output=True,timeout=90)
 assert p.returncode==0
 r=json.loads(p.stdout);assert isinstance(r,dict) and set(r)=={'value'}
 return r['value']
assert native('authority-check',{'token':token,'rotation':False},True) is None
if d['transition']:
 assert native('generation',{'operation':'verify','current':roots['old'],'candidate':roots['new'],
                            'ca_overlap':False,'ca_retire':False})==[d['count'],d['changed']]
else:
 assert d['changed']==0 and mirrors['old']==mirrors['new'] and d['bytes']['old']==d['bytes']['new']
body={'token':token,'old':roots['old'],'new':roots['new'],'minimum_ttl':d['minimum_ttl'],
      'require_orphan_new':True,'require_orphan_old':False,'replacement':None,'retiring':False}
for op in ['activation-tokens','activation-certificates']:assert native(op,body,True) is None
print(json.dumps({'authority':True,'generation':d['transition'],'tokens':True,'certificates':True}))
'''


def preflight(config, project, old, new, docker_prefix):
    """Verify a changing generation; all transition checks remain mandatory."""
    return _preflight(config, project, old, new, docker_prefix, transition=True)


def preflight_current(config, project, current, docker_prefix):
    """Read-only current custody/lifetime proof, never a transition admission."""
    config = dict(config)
    config['renewed'] = config['current']
    return _preflight(config, project, current, current, docker_prefix, transition=False)


def _preflight(config, project, old, new, docker_prefix, *, transition):
    def require(value):
        if not value:
            raise ValueError('Windows native renewal preflight refused')
    require(set(old) == set(new) and 0 < len(old) <= 512)
    require(all(re.fullmatch(r'[a-z][a-z0-9_]{0,127}', name) for name in old))
    changed = sum(old[name] != new[name] for name in old)
    require(changed > 0 if transition else changed == 0)
    require(re.fullmatch(r'[0-9a-f]{64}', config['binary_sha256']))
    require(re.fullmatch(r'[0-9a-f]{40}', config['source_sha']))
    require(re.fullmatch(r'v\d+\.\d+\.\d+(?:-nightly\.20\d{6}\.[1-9]\d*)?', config['release_tag']))
    require(re.fullmatch(r'[a-z0-9./_-]+@sha256:[0-9a-f]{64}', config['helper_image']))
    require(config['control_volume'] == project + '-renewal-control')
    require(config['network'] == project + '_default')
    require(config['bao_addr'] == 'https://openbao:8200')
    require(type(config['minimum_ttl']) is int and 60 <= config['minimum_ttl'] <= 28800)
    require(transition or config['minimum_ttl'] >= 3600)
    for key in ['current', 'renewed', 'token_file']:
        p = PurePosixPath(config[key])
        require(p.is_relative_to('/control') and len(p.parts) >= 3
                and '..' not in p.parts and str(p) == config[key])
    require(config['current'] != config['renewed'] if transition else config['current'] == config['renewed'])
    with hold_private_input(Path(config['binary']), max_bytes=256 * 1024 * 1024) as binary:
        require(hashlib.sha256(binary).hexdigest() == config['binary_sha256'])
        with hold_private_input(Path(config['ca_file'])):
            request = {key: config[key] for key in ['binary_sha256', 'source_sha', 'release_tag',
                                                  'bao_addr', 'current', 'renewed', 'token_file', 'minimum_ttl']}
            request.update(count=len(old), changed=changed, transition=transition, bytes={
                role: {name: base64.b64encode(raw).decode('ascii') for name, raw in values.items()}
                for role, values in [('old', old), ('new', new)]})
            args = [*docker_prefix, 'run', '--rm', '--pull', 'never', '-i', '--read-only',
                    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                    '--network', config['network'], '--tmpfs',
                    '/proof:rw,noexec,nosuid,nodev,size=128m,mode=0700', '--mount',
                    f'type=volume,src={config["control_volume"]},dst=/control,readonly', '--mount',
                    f'type=bind,src={config["binary"]},dst=/operator/tool,readonly', '--mount',
                    f'type=bind,src={config["ca_file"]},dst=/input/ca.crt,readonly',
                    '--entrypoint', 'python', config['helper_image'], '-c', WORKER]
            # Lazy import keeps the shared transport in its existing owner and
            # avoids a module-import cycle. Payload travels over the gated pipe,
            # never through command-line arguments or diagnostic output.
            from selfhost_windows_renewal import run_owned_mutation
            p = run_owned_mutation(args, stdin_bytes=json.dumps(request).encode(), timeout=240)
            require(p.returncode == 0)
            require(json.loads(p.stdout) == {'authority': True, 'generation': transition,
                                            'tokens': True, 'certificates': True})
