"""Fixed controller-side installed probes; incomplete checkpoints are NOT acceptance.

No source checkout, SSH credential or controller ledger is copied into the guest.
The reviewed standalone read-only host probe is sent as Python stdin-equivalent
code (probe runtime, not a checkout). Native candidate dispatch remains the only
runtime mutator. Missing journey/lifecycle probes keep all release gates closed.
"""
from __future__ import annotations
import argparse
import base64
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
from installer_host_admission import host_admission, resource_profile, STARTUP_PROFILE, LEGACY_PROFILE, RESOURCE_PROFILES
import installer_live_tls_probe as live_tls
import verify_installer_provenance as provenance

SCHEMA = 'elevenid.installer-acceptance-checkpoint/v4'
NAME = 'installer-acceptance-checkpoint.json'
TRUST_NAME = 'installer-trust-info-observation.json'
STATUS_NAME = 'installer-status-observation.json'
TLS_NAME = 'installer-live-tls-observation.json'
TRUST_EVIDENCE = {'installer-ingress.json','compose-session.json',
    'application-generation-selection.json','generation-observation.json'}
HOSTING_EVIDENCE = {'hosting-selection.json','hosting-input.json'}


def trust_observation(raw, target, observed_at, *, journal):
    """Validate the native public export; this is never browser trust or Ready."""
    r.require(isinstance(raw, bytes) and 0 < len(raw) <= 65536, 'trust observation exceeds bound')
    r.require(isinstance(journal,dict) and journal.get('installation_id')==target['installation_id'],
        'trust journal installation differs')
    value = r.decode(raw)
    r.require(isinstance(value,dict), 'trust observation shape differs')
    version=value.get('schema')
    modern=version=='elevenid.installer-trust-info/v5'
    public=modern and value.get('trust_source')=='mozilla-public-roots'
    fields = {'schema','installation_id','origin','local_probe_address','certificate_scope',
        'public_endpoint_observed',
        'certificate_der_sha256',
        'certificate_expires_at','recorded_token_expires_at','evidence_sha256',
        'recorded_startup_containers','runtime_observed','host_trust_observed',
        'host_trust_modified','installation_ready','pending'}
    if modern:fields.add('trust_source')
    if modern and 'selected_generation' in value:fields.add('selected_generation')
    if public:fields.add('public_certificate_admission')
    else:
        fields.update(('ca_certificate_pem','ca_der_sha256','ca_expires_at'))
        if 'ca_der_sha256s' in value:fields.add('ca_der_sha256s')
    r.exact(value, fields, 'trust observation')
    r.require(version in ('elevenid.installer-trust-info/v4','elevenid.installer-trust-info/v5')
        and value['installation_id']==target['installation_id'], 'trust installation differs')
    r.require(not modern or value['trust_source'] in ('configured-ca','mozilla-public-roots'),
        'trust source differs')
    if 'selected_generation' in value:
        selected_generation_evidence(value['selected_generation'])
    live_tls.public_origin(value['origin'])
    live_tls.local_address(value['local_probe_address'])
    r.require(value['certificate_scope'] in ('public-ingress','backend')
        and value['public_endpoint_observed'] is False, 'trust transport scope differs')
    r.sha(value['certificate_der_sha256'],64)
    imported='ca_der_sha256s' in value
    if public:
        admission=value['public_certificate_admission']
        public_certificate_admission(admission,value,target,observed_at)
        evidence=set(TRUST_EVIDENCE)-{'installer-ingress.json'}
        r.require(value['certificate_scope']=='public-ingress'
            and type(value['recorded_token_expires_at']) is int
            and value['recorded_token_expires_at']>observed_at, 'public trust token expiry differs')
    else:
        hashes=live_tls.certificate_hashes(value['ca_certificate_pem'])
        r.sha(value['ca_der_sha256'],64)
        r.require(hashes[0]==value['ca_der_sha256'], 'public CA hash differs')
    if imported:
        r.require(value['ca_der_sha256s']==hashes
            and value['recorded_token_expires_at'] is None, 'imported trust roots differ')
        evidence={'foundation-selection.json','compose-session.json','application-generation-selection.json'}
    elif not public:
        r.require(len(hashes)==1 and type(value['recorded_token_expires_at']) is int
            and value['recorded_token_expires_at']>observed_at, 'trust token expiry differs')
        evidence=set(TRUST_EVIDENCE)
    if 'hosting_selection_sha256' in journal:
        evidence.update(HOSTING_EVIDENCE)
    r.exact(value['evidence_sha256'],evidence,'trust evidence')
    for digest in value['evidence_sha256'].values():r.sha(digest,64)
    if 'hosting_selection_sha256' in journal:
        r.require(value['evidence_sha256']['hosting-selection.json']==journal['hosting_selection_sha256'],
            'trust hosting selection differs')
    for key in (('certificate_expires_at',) if public else ('ca_expires_at','certificate_expires_at')):
        r.require(type(value[key]) is int and value[key]>observed_at,'trust expiry differs')
    r.require(type(value['recorded_startup_containers']) is int
        and value['recorded_startup_containers']>0
        and all(value[key] is False for key in ('runtime_observed','host_trust_observed',
            'host_trust_modified','installation_ready'))
        and isinstance(value['pending'],list) and len(value['pending'])==3
        and all(isinstance(item,str) and 0<len(item)<=128 for item in value['pending']),
        'trust observation claimed readiness')
    return value


def selected_generation_evidence(value):
    r.require(isinstance(value,dict) and len(value)==10,'selected generation evidence differs')
    kinds={'intent','public-ingress-plan','helper','candidate','binding','activation-intent',
           'activation','session','selection'}
    r.require('application-generation-current.json' in value,'generation selector missing')
    sequences=set()
    observed=set()
    for name,digest in value.items():
        r.sha(digest,64)
        if name=='application-generation-current.json':continue
        match=re.fullmatch(r'generation-([0-9]{20})-([a-z-]+)\.json',name)
        r.require(match is not None and int(match[1])>0 and match[2] in kinds,
            'selected generation record differs')
        sequences.add(match[1]);observed.add(match[2])
    r.require(len(sequences)==1 and observed==kinds,'selected generation lineage differs')


def public_certificate_admission(admission, trust, target, observed_at):
    """A production native admission is distinct from a live TLS observation."""
    fields={'schema','installation_id','transit_key_name','transit_key_version','public_spki_sha256',
        'dns_names','ip_addresses','private_key_exported','activation_performed','installation_ready',
        'trust_class','trust_store','trust_store_sha256','trust_anchor_spki_value_sha256',
        'public_chain_validated','observed_at','not_before','not_after','minimum_remaining_seconds',
        'maximum_validity_seconds','leaf_der_sha256','fullchain_pem_sha256','intermediate_count',
        'revocation_status','browser_acceptance'}
    r.exact(admission,fields,'public certificate admission')
    origin=live_tls.public_origin(trust['origin'])
    r.require(admission['schema']=='elevenid.installer-external-certificate/v1'
        and admission['installation_id']==target['installation_id']
        and admission['transit_key_name']=='installer-ingress-'+target['installation_id'].replace('-','')
        and admission['transit_key_version']==1
        and admission['dns_names']==[origin.hostname]
        and admission['trust_class']=='production_public'
        and admission['trust_store']=='mozilla_webpki_roots'
        and admission['public_chain_validated'] is True
        and all(admission[key] is False for key in ('private_key_exported','activation_performed','installation_ready'))
        and admission['leaf_der_sha256']==trust['certificate_der_sha256']
        and admission['not_after']==trust['certificate_expires_at']
        and admission['revocation_status']=='not_checked'
        and admission['browser_acceptance']=='not_assessed', 'public certificate provenance differs')
    for key in ('public_spki_sha256','trust_store_sha256','trust_anchor_spki_value_sha256',
                'leaf_der_sha256','fullchain_pem_sha256'):r.sha(admission[key],64)
    for key in ('observed_at','not_before','not_after','minimum_remaining_seconds',
                'maximum_validity_seconds','intermediate_count'):
        r.require(type(admission[key]) is int and admission[key]>=0,'public certificate bound differs')
    r.require(admission['not_before']<=admission['observed_at']<=observed_at<admission['not_after']
        and 0<=admission['intermediate_count']<=7
        and admission['not_after']-admission['not_before']<=admission['maximum_validity_seconds']<=100*86400
        and isinstance(admission['ip_addresses'],list) and len(admission['ip_addresses'])<=1,
        'public certificate validity differs')
    for address in admission['ip_addresses']:
        parsed=live_tls.ipaddress.ip_address(address)
        r.require(str(parsed)==address and parsed.is_global,'public certificate IP differs')


def status_observation(raw, context, target, authorization, inventory):
    r.require(isinstance(raw,bytes) and 0<len(raw)<=65536,'status observation exceeds bound')
    value=r.decode(raw)
    r.exact(value,{'scope','runtime_observed','journal','cleanup'},'status observation')
    r.require(value['scope']=='installation-journal' and value['runtime_observed'] is False,
        'status falsely observed runtime')
    journal=value['journal']
    r.require(isinstance(journal,dict), 'candidate journal shape differs')
    fields={'schema','installation_id','identity','phase','revision','runtime','scope'}
    for optional in ('hosting_selection_sha256','hosting_addon_sha256'):
        if optional in journal:
            fields.add(optional);r.sha(journal[optional],64)
    r.exact(journal,fields,'candidate journal')
    r.require('hosting_addon_sha256' not in journal or 'hosting_selection_sha256' in journal,
        'hosting add-on lacks selection')
    r.require(journal['schema']=='elevenid.installer-state/v1'
        and journal['installation_id']==target['installation_id']
        and journal['phase'] in ('provisioning','provisioned')
        and journal['revision'] in (2,3), 'candidate journal differs')
    r.require((journal['phase'],journal['revision']) in (('provisioning',2),('provisioned',3)),
        'candidate journal revision differs')
    r.require(journal['identity']==dict(source_sha=context['source_sha'],
        release_tag=context['release_tag'],inventory_sha256='sha256:'+r.digest(inventory)),
        'candidate identity differs')
    runtime=journal['runtime']
    r.require(isinstance(runtime,dict), 'candidate runtime shape differs')
    runtime_fields={'docker_host','engine_id','openbao_port'}
    if 'profile' in runtime:runtime_fields.add('profile')
    r.exact(runtime,runtime_fields,'candidate runtime')
    profile=runtime.get('profile','rootful')
    socket=runtime['docker_host']
    r.require((profile=='rootful' and socket=='unix:///var/run/docker.sock')
        or (profile=='rootless' and isinstance(socket,str)
            and re.fullmatch(r'unix:///run/user/[1-9][0-9]{0,9}/docker.sock',socket)),
        'candidate runtime profile differs')
    r.require(runtime['engine_id']==target['engine_id']
        and type(runtime['openbao_port']) is int and 1024<=runtime['openbao_port']<=65535,
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
    cleanup_fields={'operations','next_operations','historical_evidence_only',
        'automatic_retry','host_data_credentials_images_and_named_volumes_retained'}
    if 'pending_operations' in value['cleanup']:cleanup_fields.add('pending_operations')
    cleanup=r.exact(value['cleanup'],cleanup_fields,'candidate cleanup')
    expected_cleanup=dict(operations=dict.fromkeys(('start','stop','down'),'not_started'),
        next_operations={action:action+'-0001' for action in ('start','stop','down')},
        historical_evidence_only=True,automatic_retry=False,
        host_data_credentials_images_and_named_volumes_retained=True)
    if 'pending_operations' in cleanup:expected_cleanup['pending_operations']={}
    r.require(cleanup==expected_cleanup,'candidate cleanup started')
    return value


def tls_observation(raw, trust, target, observed_at):
    r.require(isinstance(raw,bytes) and 0<len(raw)<=65536,'TLS observation exceeds bound')
    value=r.decode(raw)
    public=trust.get('trust_source')=='mozilla-public-roots'
    fields={'schema','installation_id','engine_id','origin','local_probe_address',
        'certificate_scope','public_endpoint_observed',
        'peer_der_sha256','tls_version','root_status','discovery_status','discovery_sha256',
        'issuer','observed_at','browser_login_observed','host_trust_modified'}
    fields.update(('probe_trust_source','probe_trust_bundle_sha256') if public else ('ca_der_sha256',))
    r.exact(value,fields,'live TLS observation')
    if public:
        r.require(value['probe_trust_source']=='ubuntu-system-ca-bundle','public probe trust source differs')
        r.sha(value['probe_trust_bundle_sha256'],64)
    else:r.require(value['ca_der_sha256']==trust['ca_der_sha256'],'TLS CA differs')
    r.require(value['schema']==('elevenid.installer-live-tls-observation/v3' if public else 'elevenid.installer-live-tls-observation/v2')
        and value['installation_id']==target['installation_id']
        and value['engine_id']==target['engine_id']
        and value['origin']==trust['origin']
        and value['local_probe_address']==trust['local_probe_address']
        and value['certificate_scope']==trust['certificate_scope']
        and value['public_endpoint_observed'] is False
        and value['peer_der_sha256']==trust['certificate_der_sha256']
        and value['issuer']==trust['origin']+'/realms/11id'
        and value['tls_version'] in ('TLSv1.2','TLSv1.3')
        and value['root_status']==value['discovery_status']==200
        and value['browser_login_observed'] is False
        and value['host_trust_modified'] is False
        and type(value['observed_at']) is int
        and 0<=observed_at-value['observed_at']<=120,'live TLS identity differs')
    r.sha(value['peer_der_sha256'],64)
    r.sha(value['discovery_sha256'],64)
    return value


def validate(record, *, context, target, authorization, receipt, inventory):
    r.exact(record, {'schema','repository','source_sha','release_tag','harness_source_sha','workflow',
        'run_id','run_attempt','phase','nonce','target','authorization_sha256','receipt_sha256',
        'inventory_sha256','cases','host_observation_sha256','host_preflight','dispatch',
        'trust_info_sha256','trust_inspection','status_observation_sha256',
        'tls_observation_sha256','tls_inspection',
        'resource_profile','functional_recovery_qualified','load_characterized',
        'acceptance','installation_ready','observed_at'}, 'incomplete installed checkpoint')
    resource_profile(record['resource_profile'])
    r.require(record['schema']==SCHEMA and record['repository']==r.REPOSITORY
        and record['workflow']==r.acceptance.WORKFLOW and record['acceptance'] is False
        and record['installation_ready'] is False
        and record['functional_recovery_qualified'] is False
        and record['load_characterized'] is False, 'checkpoint scope differs')
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
    r.require(record['tls_inspection'] in ('not_attempted','unavailable','verified_local_https'),
        'TLS inspection differs')
    if record['tls_inspection']=='verified_local_https':
        r.sha(record['tls_observation_sha256'],64)
        r.require(record['trust_inspection']=='verified_public_record',
            'TLS observation before trust binding')
    else:r.require(record['tls_observation_sha256'] is None,'unverified TLS claimed')
    r.require(record['trust_inspection']=='verified_public_record' or record['tls_inspection']=='not_attempted',
        'TLS probe before trust export')


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


def incomplete_checkpoint(*, context, target, authorization, receipt, inventory,
                          host_observation_sha256=None,
                          host_preflight='failed', dispatch_status='not_attempted',
                          observed_at, resource_profile=LEGACY_PROFILE):
    """Create the shared false-authority checkpoint for one candidate attempt."""
    identity={key:context[key] for key in ('source_sha','release_tag','harness_source_sha',
                                          'run_id','run_attempt','phase','nonce')}
    checkpoint=dict(schema=SCHEMA,repository=r.REPOSITORY,
        workflow=r.acceptance.WORKFLOW,**identity,target=target,
        authorization_sha256=r.digest(authorization),receipt_sha256=r.digest(receipt),
        inventory_sha256=r.digest(inventory),
        cases={name:('passed' if name=='artifact-verification' else 'blocked')
               for name in r.acceptance.CASES},
        host_observation_sha256=host_observation_sha256,
        host_preflight=host_preflight,dispatch=dispatch_status,
        trust_info_sha256=None,status_observation_sha256=None,
        trust_inspection='not_attempted',acceptance=False,
        tls_observation_sha256=None,tls_inspection='not_attempted',
        resource_profile=resource_profile,functional_recovery_qualified=False,load_characterized=False,
        installation_ready=False,observed_at=observed_at)
    validate(checkpoint,context=context,target=target,authorization=authorization,
             receipt=receipt,inventory=inventory)
    return checkpoint


def observe_after_dispatch(*, checkpoint, output, context, target, authorization, receipt,
        inventory, ssh, key, known_hosts, port, host, user, home, bootstrap_source,
        tls_source, unchanged, guarded_execute, clock=time.time, writer=None):
    """Collect bound read-only status, trust and TLS after one dispatch attempt.

    This function never starts the installer or qualifies an installed journey.
    The caller supplies custody and live-target guards for every SSH operation.
    """
    validate(checkpoint, context=context, target=target, authorization=authorization,
             receipt=receipt, inventory=inventory)
    r.require(checkpoint['host_preflight']=='passed'
              and checkpoint['dispatch']!='not_attempted',
              'post-dispatch observation requires admitted invocation')
    if writer is None:
        writer=lambda name, raw: write_exclusive(output/name, raw)
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
            status_value=status_observation(status_raw,context,target,authorization,inventory)
            raw=guarded_execute([*args,remote_prefix+' trust-info --install-dir '+shlex.quote(installation)],
                env=dict(HOME=private,PATH='/usr/bin:/bin',LANG='C',LC_ALL='C'),timeout=120,limit=65536)
            status_again=guarded_execute([*args,status_command],
                env=dict(HOME=private,PATH='/usr/bin:/bin',LANG='C',LC_ALL='C'),timeout=120,limit=65536)
            r.require(status_again==status_raw,'candidate status changed across trust export')
        trust_value=trust_observation(raw,target,int(clock()),journal=status_value['journal'])
        unchanged()
        writer(STATUS_NAME,status_raw)
        writer(TRUST_NAME,raw)
        checkpoint['status_observation_sha256']=r.digest(status_raw)
        checkpoint['trust_info_sha256']=r.digest(raw)
        checkpoint['trust_inspection']='verified_public_record'
    except (ValueError,OSError):
        unchanged()
    if checkpoint['trust_inspection']=='verified_public_record':
        checkpoint['tls_inspection']='unavailable'
        try:
            code=("import base64;exec(compile(base64.b64decode("+
                repr(base64.b64encode(tls_source.encode('utf-8')).decode())+
                "),'installer-live-tls-probe','exec'))")
            public=trust_value.get('trust_source')=='mozilla-public-roots'
            ca_encoded=base64.b64encode(trust_value.get('ca_certificate_pem','').encode('ascii')).decode('ascii')
            probe_args=[code,trust_value['origin'],trust_value['local_probe_address'],
                trust_value['certificate_scope'],ca_encoded,target['installation_id'],target['engine_id']]
            if public:probe_args.extend(('--public-roots',trust_value['certificate_der_sha256']))
            tls_remote=('set -eu; test "$(id -un)" = '+shlex.quote(user)+'; exec env -i HOME='+
                shlex.quote(home)+' PATH=/usr/bin:/bin /usr/bin/python3 -I -c '+
                shlex.join(probe_args))
            with tempfile.TemporaryDirectory(prefix='installer-tls-controller-') as private:
                args=[str(ssh),*dispatch.ssh_options(key,known_hosts,port),'-T',user+'@'+host]
                tls_raw=guarded_execute([*args,tls_remote],
                    env=dict(HOME=private,PATH='/usr/bin:/bin',LANG='C',LC_ALL='C'),timeout=120,limit=65536)
                tls_observation(tls_raw,trust_value,target,int(clock()))
                status_after=guarded_execute([*args,status_command],
                    env=dict(HOME=private,PATH='/usr/bin:/bin',LANG='C',LC_ALL='C'),timeout=120,limit=65536)
                trust_after=guarded_execute([*args,remote_prefix+' trust-info --install-dir '+shlex.quote(installation)],
                    env=dict(HOME=private,PATH='/usr/bin:/bin',LANG='C',LC_ALL='C'),timeout=120,limit=65536)
            r.require(status_after==status_raw and trust_after==raw,'candidate changed across live TLS probe')
            unchanged()
            writer(TLS_NAME,tls_raw)
            checkpoint['tls_observation_sha256']=r.digest(tls_raw)
            checkpoint['tls_inspection']='verified_local_https'
        except (ValueError,OSError):
            unchanged()
    checkpoint['observed_at']=int(clock())
    validate(checkpoint,context=context,target=target,authorization=authorization,receipt=receipt,inventory=inventory)
    unchanged()
    writer(NAME,r.encode(checkpoint))
    unchanged()
    return checkpoint


def run(*, output, assets, grants, context_file, target_file, ledger, gh, cosign,
        ssh, scp, key, known_hosts, host, port, user, home,
        clock=time.time, verifier=provenance.command, execute=command,
        candidate_dispatch=dispatch.dispatch, resource_profile=STARTUP_PROFILE):
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
    checkpoint=incomplete_checkpoint(context=context,target=target,
        authorization=authorization,receipt=receipt,inventory=inventory,
        observed_at=int(clock()),resource_profile=resource_profile)
    write_exclusive(output/'runner-intent.json',r.encode(dict(schema='elevenid.installer-acceptance-runner-intent/v1',
        context_sha256=r.candidate_context_sha256(context),receipt_sha256=r.digest(receipt),
        target=target,resource_profile=resource_profile)))
    probe=probe_source()
    r.require(probe.decode('utf-8')==dispatch.verified_harness_script(
        context['harness_source_sha'],'installer_host_probe.py'),
        'host probe differs from signed harness source')
    tls_source=dispatch.verified_harness_script(context['harness_source_sha'],'installer_live_tls_probe.py')
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
        host_admission(raw,target['engine_id'],profile=resource_profile)
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
    return observe_after_dispatch(
        checkpoint=checkpoint, output=output, context=context, target=target,
        authorization=authorization, receipt=receipt, inventory=inventory,
        ssh=ssh, key=key, known_hosts=known_hosts, port=port, host=host, user=user,
        home=home, bootstrap_source=bootstrap_source, tls_source=tls_source,
        unchanged=unchanged, guarded_execute=guarded_execute, clock=clock)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('output','assets','grants','context-file','target-file','ledger','gh','cosign','ssh','scp','key','known-hosts'):
        parser.add_argument('--'+name,type=Path,required=True)
    for name in ('host','user','home'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--port',type=int,required=True)
    parser.add_argument('--resource-profile',choices=RESOURCE_PROFILES,default=STARTUP_PROFILE)
    try:run(**vars(parser.parse_args(argv)))
    except (ValueError,OSError,KeyError,TypeError):parser.exit(1,'Installed probe refused or uncertain; preserve all controller and guest state.\n')
    parser.exit(2,'Installed checkpoint retained; real installed acceptance remains incomplete.\n')


if __name__=='__main__':main()
