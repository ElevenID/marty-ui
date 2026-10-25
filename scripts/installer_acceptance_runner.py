"""Fixed controller-side installed probes; incomplete checkpoints are NOT acceptance.

No source checkout, SSH credential or controller ledger is copied into the guest.
The reviewed standalone read-only host probe is sent as Python stdin-equivalent
code (probe runtime, not a checkout). Native candidate dispatch remains the only
runtime mutator. Missing journey/lifecycle probes keep all release gates closed.
"""
from __future__ import annotations
import argparse
import base64
import os
from pathlib import Path
import re
import shlex
import stat
import tempfile
import time
import installer_release as r
import installer_candidate_dispatch as dispatch
from installer_candidate_authorize import read_record, write_exclusive
from installer_host_probe import command, DEVTOOLS
import verify_installer_provenance as provenance

SCHEMA = 'elevenid.installer-acceptance-checkpoint/v1'
NAME = 'installer-acceptance-checkpoint.json'


def validate(record, *, context, target, authorization, receipt, inventory):
    r.exact(record, {'schema','repository','source_sha','release_tag','harness_source_sha','workflow',
        'run_id','run_attempt','phase','nonce','target','authorization_sha256','receipt_sha256',
        'inventory_sha256','cases','host_observation_sha256','host_preflight','dispatch',
        'acceptance','installation_ready','observed_at'}, 'incomplete installed checkpoint')
    r.require(record['schema']==SCHEMA and record['repository']==r.REPOSITORY
        and record['workflow']==r.acceptance.WORKFLOW and record['acceptance'] is False
        and record['installation_ready'] is False, 'checkpoint scope differs')
    for key in ('source_sha','release_tag','harness_source_sha','run_id','run_attempt','phase','nonce'):
        r.require(record[key]==context[key], 'checkpoint invocation differs')
    r.require(record['target']==target and record['authorization_sha256']==r.digest(authorization)
        and record['receipt_sha256']==r.digest(receipt) and record['inventory_sha256']==r.digest(inventory),
        'checkpoint custody differs')
    r.positive(record['observed_at'])
    r.exact(record['cases'],set(r.acceptance.CASES),'checkpoint cases')
    # Only cryptographic artifact admission is implemented as a completed case.
    # No transport caller can turn unimplemented probes into acceptance booleans.
    r.require(record['cases']['artifact-verification']=='passed'
        and all(record['cases'][name]=='blocked' for name in r.acceptance.CASES if name!='artifact-verification'),
        'unimplemented installed case claimed')
    r.require(record['host_preflight'] in ('passed','failed')
        and record['dispatch'] in ('not_attempted','failed_or_incomplete','returned_zero_unqualified'),
        'checkpoint observation differs')
    digest=record['host_observation_sha256']
    if digest is not None: r.sha(digest,64)
    r.require(record['host_preflight']!='passed' or digest is not None, 'missing host observation')
    r.require(record['host_preflight']=='passed' or record['dispatch']=='not_attempted','dispatch before host admission')


def host_admission(raw,engine):
    value=r.decode(raw)
    r.require(value.get('schema')=='elevenid.installer-host-observation/v1'
        and value.get('acceptance') is False and value.get('engine_id')==engine, 'host identity differs')
    for key in ('docker_memory_bytes','guest_memory_bytes'):
        r.require(type(value.get(key)) is int and value[key]>=r.acceptance.MIN_MEMORY_BYTES,'qualification RAM unavailable')
    disk=value.get('docker_data_filesystem',{})
    r.require(type(disk.get('free_bytes')) is int and disk['free_bytes']>=r.acceptance.MIN_DISK_FREE_BYTES,'qualification disk unavailable')
    r.require(value.get('predicates')==dict(capacity=True,initial_docker_clean=True),'guest pre-pull state differs')
    r.require(value.get('resource_counts')==dict(containers=0,images=0,volumes=0,networks=3),'guest resources present')
    r.exact(value.get('credential_file_presence'),{'docker_config','containers_auth','runtime_containers_auth'},'credential observation')
    r.exact(value.get('development_tool_presence'),set(DEVTOOLS),'development-tool observation')
    r.require(value.get('credential_environment_names')==[] and isinstance(value.get('credential_file_presence'),dict)
        and all(v is False for v in value['credential_file_presence'].values())
        and isinstance(value.get('development_tool_presence'),dict)
        and all(v is False for v in value['development_tool_presence'].values()),'observed credential/development tool present')
    # These are narrow observations, never proof of exhaustive source/credential absence.
    return value


def probe_source():
    path=Path(__file__).absolute().with_name('installer_host_probe.py')
    r.require(path.resolve()==path,'host probe source path differs')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        r.require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=65536,'host probe source type/size differs')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(65537)
        after=os.fstat(fd)
        r.require(len(raw)==before.st_size and (before.st_dev,before.st_ino,before.st_mtime_ns,before.st_size)==
            (after.st_dev,after.st_ino,after.st_mtime_ns,after.st_size),'host probe source changed')
        return raw
    finally:os.close(fd)


def run(*, output, assets, grants, context_file, target_file, ledger, gh, cosign,
        ssh, scp, key, known_hosts, host, port, user, home,
        clock=time.time, verifier=provenance.command, execute=command,
        candidate_dispatch=dispatch.dispatch):
    r.require(os.name=='posix','Linux controller required')
    dispatch.executable(ssh);dispatch.executable(scp)
    r.require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}',host) is not None
        and type(port) is int and 1<=port<=65535,'SSH target invalid')
    for path in (key,known_hosts,ledger,context_file,target_file):dispatch.private_file(path,65536)
    originals={path:read_record(path) for path in (context_file,target_file,ledger)}
    custody={path:dispatch.private_file(path,65536) for path in (key,known_hosts)}
    context=r.decode(originals[context_file]);target=r.decode(originals[target_file])
    authorization,receipt,inventory,files=dispatch.verify(assets=assets,grants=grants,context=context,target=target,
        ledger=ledger,gh=gh,cosign=cosign,now=int(clock()),runner=verifier)
    def unchanged():
        for path,raw in originals.items():
            dispatch.private_file(path,65536)
            r.require(read_record(path)==raw,'controller identity changed')
        r.require(originals[ledger]==receipt,'consumed ledger differs')
        for path,expected in custody.items():
            r.require(dispatch.private_file(path,65536)==expected,'SSH custody changed')
        for path,expected in files.items():
            r.require(dispatch.private_file(path,expected[1],executable=path in (gh,cosign))==expected,
                'authenticated candidate custody changed')
    unchanged()
    dispatch.remote_plan(home,user,context,target) # Validate fixed guest account/path contract.
    r.require(context['phase']=='staged','published public acquisition is not implemented')
    identity={key:context[key] for key in ('source_sha','release_tag','harness_source_sha','run_id','run_attempt','phase','nonce')}
    checkpoint=dict(schema=SCHEMA,repository=r.REPOSITORY,workflow=r.acceptance.WORKFLOW,**identity,
        target=target,authorization_sha256=r.digest(authorization),receipt_sha256=r.digest(receipt),
        inventory_sha256=r.digest(inventory),cases={name:('passed' if name=='artifact-verification' else 'blocked') for name in r.acceptance.CASES},
        host_observation_sha256=None,host_preflight='failed',dispatch='not_attempted',acceptance=False,
        installation_ready=False,observed_at=int(clock()))
    write_exclusive(output/'runner-intent.json',r.encode(dict(schema='elevenid.installer-acceptance-runner-intent/v1',
        context_sha256=r.candidate_context_sha256(context),receipt_sha256=r.digest(receipt),target=target)))
    probe=probe_source()
    code="import base64;exec(compile(base64.b64decode("+repr(base64.b64encode(probe).decode())+"),'installer-host-probe','exec'))"
    remote='exec env -i HOME='+shlex.quote(home)+' PATH=/usr/bin:/bin /usr/bin/python3 -c '+shlex.quote(code)
    try:
        unchanged()
        r.bind_controller_consumption(receipt,authorization,inventory,expected=context,expected_engine=target['engine_id'],now=int(clock()))
        with tempfile.TemporaryDirectory(prefix='installer-acceptance-controller-') as private:
            raw=execute([str(ssh),*dispatch.ssh_options(key,known_hosts,port),'-T',user+'@'+host,remote],
                env=dict(HOME=private,PATH='/usr/bin:/bin',LANG='C',LC_ALL='C'),timeout=120)
        r.require(isinstance(raw,bytes) and len(raw)<=65536,'host observation exceeds record bound')
        write_exclusive(output/'host-observation.json',raw)
        checkpoint['host_observation_sha256']=r.digest(raw)
        host_admission(raw,target['engine_id'])
        checkpoint['host_preflight']='passed'
    except (ValueError,OSError):
        unchanged()
        validate(checkpoint,context=context,target=target,authorization=authorization,receipt=receipt,inventory=inventory)
        write_exclusive(output/NAME,r.encode(checkpoint));return checkpoint
    # Bind this preflight to the very same independently authenticated dispatch.
    # Repeat around every remote operation as well as before/after the dispatcher.
    unchanged()
    def guarded_execute(*args,**kwargs):
        unchanged()
        return execute(*args,**kwargs)
    checkpoint['dispatch']='failed_or_incomplete'
    try:
        candidate_dispatch(assets=assets,grants=grants,context_file=context_file,target_file=target_file,
            ledger=ledger,gh=gh,cosign=cosign,ssh=ssh,scp=scp,key=key,known_hosts=known_hosts,
            host=host,port=port,user=user,home=home,clock=clock,verifier=verifier,run=guarded_execute)
        checkpoint['dispatch']='returned_zero_unqualified'
    except (ValueError,OSError):
        pass # No error bodies, tokens, automatic cleanup or replay.
    unchanged()
    checkpoint['observed_at']=int(clock())
    validate(checkpoint,context=context,target=target,authorization=authorization,receipt=receipt,inventory=inventory)
    write_exclusive(output/NAME,r.encode(checkpoint));return checkpoint


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('output','assets','grants','context-file','target-file','ledger','gh','cosign','ssh','scp','key','known-hosts'):
        parser.add_argument('--'+name,type=Path,required=True)
    for name in ('host','user','home'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--port',type=int,required=True)
    try:run(**vars(parser.parse_args(argv)))
    except (ValueError,OSError,KeyError,TypeError):parser.exit(1,'Installed probe refused or uncertain; preserve all controller and guest state.\n')
    parser.exit(2,'Installed checkpoint retained; real installed acceptance remains incomplete.\n')


if __name__=='__main__':main()
