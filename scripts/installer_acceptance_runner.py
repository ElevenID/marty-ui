"""Fixed controller-side installed probes; incomplete checkpoints are NOT acceptance.

No source checkout, SSH credential or controller ledger is copied into the guest.
The reviewed standalone read-only host probe is sent as Python stdin-equivalent
code (probe runtime, not a checkout). Native candidate dispatch remains the only
runtime mutator. Missing journey/lifecycle probes keep all release gates closed.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
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

SCHEMA = 'elevenid.installer-acceptance-checkpoint/v2'
NAME = 'installer-acceptance-checkpoint.json'
TRUST_NAME = 'installer-trust-info-observation.json'
STATUS_NAME = 'installer-status-observation.json'
TRUST_EVIDENCE = {'installer-ingress.json','application-plan.json','application-created-resources.json',
    'application-start-result.json','application-generation-selection.json'}


def trust_observation(raw, target, observed_at):
    """Validate the native public export; this is never browser trust or Ready."""
    r.require(isinstance(raw, bytes) and 0 < len(raw) <= 65536, 'trust observation exceeds bound')
    value = r.decode(raw)
    r.exact(value, {'schema','installation_id','origin','ca_certificate_pem','ca_der_sha256',
        'ca_expires_at','certificate_expires_at','recorded_token_expires_at','evidence_sha256',
        'recorded_startup_containers','runtime_observed','host_trust_observed',
        'host_trust_modified','installation_ready','pending'}, 'trust observation')
    r.require(value['schema']=='elevenid.installer-trust-info/v1'
        and value['installation_id']==target['installation_id'], 'trust installation differs')
    origin=value['origin']
    r.require(isinstance(origin,str) and re.fullmatch(r'https://localhost:[1-9][0-9]{3,4}',origin)
        and 1024 <= int(origin.rsplit(':',1)[1]) <= 65535, 'trust origin differs')
    pem=value['ca_certificate_pem']
    r.require(isinstance(pem,str) and len(pem)<=16384
        and re.fullmatch(r'-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/=]{1,64}\n)+-----END CERTIFICATE-----\n',pem),
        'public CA encoding differs')
    encoded=''.join(pem.splitlines()[1:-1])
    try:der=base64.b64decode(encoded,validate=True)
    except (ValueError,base64.binascii.Error):raise ValueError('public CA encoding differs') from None
    r.require(0<len(der)<=12288 and base64.b64encode(der).decode()==encoded,
        'public CA encoding differs')
    r.sha(value['ca_der_sha256'],64)
    r.require(hashlib.sha256(der).hexdigest()==value['ca_der_sha256'], 'public CA hash differs')
    r.exact(value['evidence_sha256'],TRUST_EVIDENCE,'trust evidence')
    for digest in value['evidence_sha256'].values():r.sha(digest,64)
    for key in ('ca_expires_at','certificate_expires_at','recorded_token_expires_at'):
        r.require(type(value[key]) is int and value[key]>observed_at,'trust expiry differs')
    r.require(type(value['recorded_startup_containers']) is int
        and value['recorded_startup_containers']>0
        and all(value[key] is False for key in ('runtime_observed','host_trust_observed',
            'host_trust_modified','installation_ready'))
        and isinstance(value['pending'],list) and len(value['pending'])==3
        and all(isinstance(item,str) and 0<len(item)<=128 for item in value['pending']),
        'trust observation claimed readiness')
    return value


def status_observation(raw, context, target, authorization, inventory):
    r.require(isinstance(raw,bytes) and 0<len(raw)<=65536,'status observation exceeds bound')
    value=r.decode(raw)
    r.exact(value,{'scope','runtime_observed','journal','cleanup'},'status observation')
    r.require(value['scope']=='installation-journal' and value['runtime_observed'] is False,
        'status falsely observed runtime')
    journal=r.exact(value['journal'],{'schema','installation_id','identity','phase','revision',
        'runtime','scope'},'candidate journal')
    r.require(journal['schema']=='elevenid.installer-state/v1'
        and journal['installation_id']==target['installation_id']
        and journal['phase'] in ('provisioning','provisioned')
        and journal['revision'] in (2,3), 'candidate journal differs')
    r.require((journal['phase'],journal['revision']) in (('provisioning',2),('provisioned',3)),
        'candidate journal revision differs')
    r.require(journal['identity']==dict(source_sha=context['source_sha'],
        release_tag=context['release_tag'],inventory_sha256='sha256:'+r.digest(inventory)),
        'candidate identity differs')
    runtime=r.exact(journal['runtime'],{'docker_host','engine_id','openbao_port'},'candidate runtime')
    r.require(runtime['engine_id']==target['engine_id']
        and runtime['docker_host']=='unix:///var/run/docker.sock'
        and type(runtime['openbao_port']) is int and runtime['openbao_port']>=1024,
        'candidate runtime differs')
    scope=r.exact(journal['scope'],{'kind','authorization_sha256','context_sha256',
        'consumption_id'},'candidate scope')
    r.require(scope['kind']=='acceptance-only'
        and scope['authorization_sha256']==r.digest(authorization)
        and scope['context_sha256']==r.candidate_context_sha256(context),
        'candidate scope differs')
    claim=dict(nonce=context['nonce'],authorization_sha256=r.digest(authorization),
        context_sha256=r.candidate_context_sha256(context),installation_id=target['installation_id'],
        engine_id=target['engine_id'])
    # Match serde_json's preserve_order serialization in installer_candidate_nonce::consume.
    consumed=json.dumps(dict(schema='elevenid.installer-candidate-consumption/v1',scope='guest-local',
        claim=claim),separators=(',',':'),ensure_ascii=True).encode('ascii')
    r.require(scope['consumption_id']==r.digest(consumed),'candidate nonce consumption differs')
    cleanup=r.exact(value['cleanup'],{'state','runtime_observed'},'candidate cleanup')
    r.require(cleanup==dict(state='not_started',runtime_observed=False),'candidate cleanup started')
    return value


def validate(record, *, context, target, authorization, receipt, inventory):
    r.exact(record, {'schema','repository','source_sha','release_tag','harness_source_sha','workflow',
        'run_id','run_attempt','phase','nonce','target','authorization_sha256','receipt_sha256',
        'inventory_sha256','cases','host_observation_sha256','host_preflight','dispatch',
        'trust_info_sha256','trust_inspection','status_observation_sha256',
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
    r.require(record['trust_inspection'] in ('not_attempted','unavailable','verified_public_record'),
        'trust inspection differs')
    if record['trust_inspection']=='verified_public_record':
        r.sha(record['trust_info_sha256'],64)
        r.sha(record['status_observation_sha256'],64)
        r.require(record['host_preflight']=='passed' and record['dispatch']!='not_attempted',
            'trust record before dispatch')
    else:r.require(record['trust_info_sha256'] is None and record['status_observation_sha256'] is None,
        'unverified trust record claimed')
    r.require(record['dispatch']!='not_attempted' or record['trust_inspection']=='not_attempted',
        'trust inspection before dispatch')


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
    bootstrap_source=(dispatch.verified_bootstrap(context['harness_source_sha'])
        if context['phase']=='published' else None)
    dispatch.remote_plan(home,user,context,target,authorization=authorization,
        bootstrap_source=bootstrap_source) # Validate fixed guest account/path contract.
    identity={key:context[key] for key in ('source_sha','release_tag','harness_source_sha','run_id','run_attempt','phase','nonce')}
    checkpoint=dict(schema=SCHEMA,repository=r.REPOSITORY,workflow=r.acceptance.WORKFLOW,**identity,
        target=target,authorization_sha256=r.digest(authorization),receipt_sha256=r.digest(receipt),
        inventory_sha256=r.digest(inventory),cases={name:('passed' if name=='artifact-verification' else 'blocked') for name in r.acceptance.CASES},
        host_observation_sha256=None,host_preflight='failed',dispatch='not_attempted',
        trust_info_sha256=None,status_observation_sha256=None,trust_inspection='not_attempted',acceptance=False,
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
    # Native startup deliberately exits incomplete. Query its locked public
    # trust record through the same pinned SSH route; absence remains explicit.
    # This does not modify a trust store, contact the app, or qualify login.
    base, _, _ = dispatch.remote_plan(home,user,context,target,authorization=authorization,
        bootstrap_source=bootstrap_source)
    operator=(base+'/bootstrap/marty-deploy-linux-amd64' if context['phase']=='published'
        else base+'/marty-deploy')
    installation=home+'/marty-install-'+target['installation_id']
    quoted_operator=shlex.quote(operator)
    remote_prefix=('set -eu; PATH=/usr/bin:/bin; export PATH; '
        'test "$(id -un)" = '+shlex.quote(user)+'; '
        'printf "%s  %s\\n" '+shlex.quote(context['operator_sha256'])+' '+quoted_operator+
        ' | /usr/bin/sha256sum --check --status --strict; '
        'exec env -i HOME='+shlex.quote(home)+' PATH=/usr/bin:/bin '+quoted_operator)
    checkpoint['trust_inspection']='unavailable'
    try:
        with tempfile.TemporaryDirectory(prefix='installer-trust-controller-') as private:
            args=[str(ssh),*dispatch.ssh_options(key,known_hosts,port),'-T',user+'@'+host]
            status_command=remote_prefix+' status --install-dir '+shlex.quote(installation)
            status_raw=guarded_execute([*args,status_command],
                env=dict(HOME=private,PATH='/usr/bin:/bin',LANG='C',LC_ALL='C'),timeout=120,limit=65536)
            status_observation(status_raw,context,target,authorization,inventory)
            raw=guarded_execute([*args,remote_prefix+' trust-info --install-dir '+shlex.quote(installation)],
                env=dict(HOME=private,PATH='/usr/bin:/bin',LANG='C',LC_ALL='C'),timeout=120,limit=65536)
            status_again=guarded_execute([*args,status_command],
                env=dict(HOME=private,PATH='/usr/bin:/bin',LANG='C',LC_ALL='C'),timeout=120,limit=65536)
            r.require(status_again==status_raw,'candidate status changed across trust export')
        trust_observation(raw,target,int(clock()))
        unchanged()
        write_exclusive(output/STATUS_NAME,status_raw)
        write_exclusive(output/TRUST_NAME,raw)
        checkpoint['status_observation_sha256']=r.digest(status_raw)
        checkpoint['trust_info_sha256']=r.digest(raw)
        checkpoint['trust_inspection']='verified_public_record'
    except (ValueError,OSError):
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
