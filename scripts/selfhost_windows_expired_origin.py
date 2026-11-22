"""Prepare-only selected-expired origin for the existing Windows recovery owner.

Offline dates are evidence, not credential admission. A separately completed
signed certificate-lifetime refusal can make this typed origin inspectable only
after every selected-input/custody exit succeeds. No producer or activation is
called here, and an uncertain attempt is never replayed.
"""
from contextlib import ExitStack
from pathlib import Path
import re
import ssl
import time

import selfhost_windows_selection as selection
from selfhost_windows_renewal_native import certificate_inspection_result
from stage_selfhost_renewed_secrets import CA_FILE, RENEWED_CERT_FILES

SCHEMA = 'marty.windows-selected-expired-origin/v1'
PROOF_SCHEMA = 'marty.windows-selected-expired-certificate-proof/v1'
EVIDENCE_SCHEMA = 'marty.windows-offline-certificate-dates/v1'
REFUSAL_SCHEMA = 'marty.windows-selected-expired-certificate-refusal/v1'
STARTED = 'current-certificates.started.json'
COMPLETED = 'current-certificates.completed.json'
PENDING = 'current-certificates.refused.pending.json'
REFUSED = 'current-certificates.refused.json'
require = selection.require
renewal = selection.renewal


def _public_dates(root, current):
    """Re-derive dates from held public bytes, including during receipt replay."""
    require(RENEWED_CERT_FILES<=set(current))
    certificates={}
    for name in sorted(RENEWED_CERT_FILES):
        raw=current[name]
        require(type(raw) is bytes and 0<len(raw)<=65536
                and Path(root,name).read_bytes()==raw)
        parsed=ssl._ssl._test_decode_cert(str(Path(root,name)))
        before=ssl.cert_time_to_seconds(parsed['notBefore'])
        after=ssl.cert_time_to_seconds(parsed['notAfter'])
        require(before==int(before) and after==int(after))
        certificates[name]={'sha256':selection.digest(raw),
                            'not_before':int(before),'not_after':int(after)}
    return certificates


def validate_certificate_evidence(evidence, current, minimum_ttl, root):
    require(type(evidence) is dict and set(evidence)=={
        'schema','observed_at','minimum_ttl','certificates'})
    require(evidence['schema']==EVIDENCE_SCHEMA and type(evidence['observed_at']) is int
            and 0<evidence['observed_at']<253402300800
            and evidence['observed_at']<=int(time.time())
            and type(minimum_ttl) is int and 3600<=minimum_ttl<=28800
            and type(evidence['minimum_ttl']) is int and evidence['minimum_ttl']==minimum_ttl)
    certificates=evidence['certificates'];now=evidence['observed_at'];expired=[]
    require(type(certificates) is dict and set(certificates)==RENEWED_CERT_FILES)
    require(selection.packed(certificates)==selection.packed(_public_dates(root,current)))
    for name, item in certificates.items():
        require(type(item) is dict and set(item)=={'sha256','not_before','not_after'})
        require(type(current[name]) is bytes and item['sha256']==selection.digest(current[name])
                and type(item['not_before']) is int and type(item['not_after']) is int
                and 0<=item['not_before']<item['not_after']<253402300800
                and item['not_before']<=now)
        if name==CA_FILE:require(item['not_after']>=now+minimum_ttl)
        elif item['not_after']<=now:expired.append(name)
    require(expired)
    return evidence


def observe_certificate_dates(root, current, minimum_ttl):
    """Parse only the retained public certificate allowlist under held inputs."""
    now=int(time.time());certificates=_public_dates(root,current)
    evidence={'schema':EVIDENCE_SCHEMA,'observed_at':now,'minimum_ttl':minimum_ttl,
              'certificates':certificates}
    return validate_certificate_evidence(evidence,current,minimum_ttl,root)


def names(stage, *, pending=False):
    """The typed namespace cannot be mistaken for ordinary staging history."""
    require(type(pending) is bool)
    if stage['schema']==selection.STAGE_SCHEMA:
        require(not pending)
        return selection._stage_names()
    require(stage['schema']==SCHEMA)
    return [*selection._stage_names(),STARTED,COMPLETED,PENDING if pending else REFUSED]


def validate_intent(stage, expected, config, current=None):
    """Reconstruct every origin field from the selected owner and held inputs."""
    if stage['schema']==selection.STAGE_SCHEMA:
        require(stage==expected)
        return
    require(stage['schema']==SCHEMA and current is not None)
    evidence=stage['certificate_evidence']
    validate_certificate_evidence(evidence,current,config['native']['minimum_ttl'],config['current_secrets'])
    require(selection.packed(stage)==selection.packed(dict(expected,schema=SCHEMA,certificate_evidence=evidence)))


def refusal_receipt(stage, config):
    require(stage['schema']==SCHEMA)
    native=config['native']
    return {'schema':REFUSAL_SCHEMA,'origin_sha256':selection.digest(selection.packed(stage)),
        'selected_sha256':stage['selected_sha256'],'config_sha256':stage['config_sha256'],
        'certificate_evidence_sha256':selection.digest(selection.packed(stage['certificate_evidence'])),
        'operator':{key:native[key] for key in ('binary_sha256','source_sha','release_tag')},
        'inspection':certificate_inspection_result('lifetime-refused')}


def receipt_hashes(stage, config, raws, *, pending_sha256=None):
    """Admit only an actual, narrowly typed certificate refusal for this origin."""
    from selfhost_windows_staging_recovery import failed_current_receipts
    if stage['schema']==selection.STAGE_SCHEMA:
        require(pending_sha256 is None)
        return failed_current_receipts(raws)
    pending=pending_sha256 is not None
    require(type(raws) is dict and set(raws)==set(names(stage,pending=pending))-{'intent.json'})
    expected_refusal=selection.packed(refusal_receipt(stage,config))
    if pending:
        require(type(pending_sha256) is str
                and selection.digest(expected_refusal)==pending_sha256)
    completed={'authority.started.json','authority.completed.json',STARTED}
    marker=PENDING if pending else REFUSED
    for name,raw in raws.items():
        require(type(raw) is bytes)
        if name==marker:require(raw==expected_refusal)
        elif name in completed:
            phase,event,_=name.split('.')
            require(raw==selection.packed({'phase':phase,'event':event,'metadata':{}}))
        else:require(raw==b'')
    # Pending validation is internal publication work. The externally replayed
    # proof always refers to the final, no-overwrite promoted receipt name.
    return {REFUSED if name==PENDING else name:selection.digest(raw)
            for name,raw in sorted(raws.items())}


def proof(stage, record, hashes):
    typed=stage['schema']==SCHEMA
    require(typed or stage['schema']==selection.STAGE_SCHEMA)
    result={'schema':PROOF_SCHEMA if typed else 'marty.windows-failed-current-proof/v1',
            'project':stage['project'],'sequence':record['sequence'],
            'guard_sha256':selection.digest(selection.packed(stage)),
            'receipt_sha256':hashes,'data_sha256':record['data_sha256'],
            'guard_retained':True,'credential_admission':False}
    if typed:result.update(operation='activation-certificates',tokens_examined=False,whole_current_proof=False)
    return result


def start(config, choice, values, record, output_dir, logical_project, stack):
    """Run once under the selected lease; return only provisional metadata."""
    import selfhost_windows_renewal_native as native
    require(type(record['sequence']) is int and 1<=record['sequence']<selection.MAX_SELECTIONS)
    require(not selection._initial_current_record(record))
    selection.require_logical_tls_project(logical_project)
    root=Path(output_dir);parent=Path(config['current_secrets']).parent
    require(root.is_absolute() and root.parent==parent
            and re.fullmatch(r'windows-renewal-[0-9a-f]{32}',root.name))
    require(not renewal.recovery_pending(config))
    stack.enter_context(renewal.hold_storage_namespace(root))
    with selection._held_private_input(root,directory=True):pass
    require(not list(root.iterdir()))
    deadline=time.monotonic()+600
    observed=selection._inspect(config,choice,values,stack,
        expected_data=record['data_sha256'],require_ready=False)
    # Strict ForeignContext is unchanged: a changing restart count/PID/state
    # refuses preparation. This path grants no stop or quiescence privilege.
    observed['context'].check(before_intent=True)
    evidence=observe_certificate_dates(record['selected']['secrets_dir'],values[choice],
                                       config['native']['minimum_ttl'])
    cycle=root.name.removeprefix('windows-renewal-')
    secrets=parent/('candidate-secrets-renewal-'+cycle)
    require(not renewal.namespace_entry_exists(secrets));secrets.mkdir()
    stack.enter_context(renewal.hold_storage_namespace(secrets))
    stack.enter_context(selection._held_private_input(secrets,directory=True))
    activation=root/'activation';activation.mkdir()
    layers=renewal.dependency_layers(observed['model'],observed['services'],
        renewal.owned_roles(observed['model'],observed['services']))
    next_config=selection._stage_configuration(config,choice,record,root,layers)
    paths=[Path(next_config[name]) for name in ('intent','result','new_log','rollback_log')]
    paths += [Path(path) for step in next_config['step_receipts'] for path in step.values()]
    for path in paths:selection._new_private(path,b'')
    env=renewal.read_private_bytes(Path(next_config['current_env']));lines=env.splitlines(keepends=True)
    indices=[i for i,line in enumerate(lines) if line.startswith(b'SELFHOST_SECRET_DIR=')]
    require(len(indices)==1)
    index=indices[0];ending=b'\r\n' if lines[index].endswith(b'\r\n') else b'\n'
    lines[index]=b'SELFHOST_SECRET_DIR='+secrets.as_posix().encode()+ending
    renewed_env=b''.join(lines)
    require(renewal.env_body(env,Path(next_config['current_secrets']))==renewal.env_body(renewed_env,secrets))
    selection._new_private(root/'renewed.env',renewed_env)
    next_raw=selection.packed(next_config)
    selection._new_private(activation/'config.private.json',next_raw)
    authority='/control/recovery-session-'+cycle+'/token'
    stage={'schema':SCHEMA,'project':config['project'],'engine_id':config['engine_id'],
        'sequence':record['sequence']+1,'selected_sha256':selection.digest(selection.packed(record['selected'])),
        'data_sha256':record['data_sha256'],'root':str(root),'config_path':str(activation/'config.private.json'),
        'config_sha256':selection.digest(next_raw),'authority_file':authority,'logical_project':logical_project,
        'services_image':observed['model']['services']['signing-keys']['image'],'candidate_only':True,
        'certificate_evidence':evidence}
    stage_names=names(stage,pending=True)
    for name in [*stage_names,'result.json','publication.pending.json']:selection._new_private(root/name,b'')
    guard=renewal.renewal_staging_guard(config)
    selection._new_private(guard,selection.packed(stage))
    renewal.write_empty_private_file(root/'intent.json',selection.packed(stage).decode())
    stack.enter_context(renewal.hold_private_input(guard))
    stack.enter_context(renewal.hold_private_input(root/'intent.json'))
    # All empty producer/activation outputs and directory membership are held
    # through this attempt. Only the three named inspection phase files change.
    def membership(path, expected):require({p.name for p in path.iterdir()}==expected)
    for path,expected in [(root,set(stage_names)|{'result.json','publication.pending.json','renewed.env','activation'}),
            (activation,{'config.private.json',*(p.name for p in paths)}),(secrets,set())]:
        membership(path,expected);stack.callback(membership,path,expected)
    stack.enter_context(selection._held_private_input(root,directory=True))
    stack.enter_context(selection._held_private_input(activation,directory=True))
    mutable={'authority.started.json','authority.completed.json',STARTED,COMPLETED,PENDING}
    for path in [*paths,root/'result.json',root/'publication.pending.json',
                 *(root/name for name in stage_names if name not in mutable|{'intent.json'})]:
        require(stack.enter_context(renewal.hold_private_input(path))==b'')
    require(stack.enter_context(renewal.hold_private_input(activation/'config.private.json'))==next_raw)
    require(stack.enter_context(renewal.hold_private_input(root/'renewed.env'))==renewed_env)
    def checkpoint(name, metadata=None):
        phase,event,_=name.split('.')
        body={'phase':phase,'event':event,'metadata':{} if metadata is None else metadata}
        renewal.write_empty_private_file(root/name,selection.packed(body).decode())
        stack.enter_context(renewal.hold_private_input(root/name))
    require(time.monotonic()<deadline)
    checkpoint('authority.started.json')
    require(native.reauthenticate(config['native'],config['project'],observed['docker'].prefix,
                                  authority.rsplit('/',1)[0])==authority)
    checkpoint('authority.completed.json')
    observed['context'].check(before_intent=True)
    require(time.monotonic()<deadline)
    checkpoint(STARTED)
    inspected=dict(next_config['native'],renewed=next_config['native']['current'])
    result=native.inspect_current_certificates(inspected,config['project'],values[choice],observed['docker'].prefix)
    if result==certificate_inspection_result('completed'):
        checkpoint(COMPLETED,result)
        # Truthful certificate success is not a failed whole-current proof.
        # Preserve the typed guard and refuse this expired-origin preparation.
        raise ValueError('Selected expired certificate inspection unexpectedly completed; preserve its guard')
    require(result==certificate_inspection_result('lifetime-refused'))
    observed['context'].check(before_intent=True)
    require(time.monotonic()<deadline)
    receipt=selection.packed(refusal_receipt(stage,next_config))
    renewal.write_empty_private_file(root/PENDING,receipt.decode())
    stack.enter_context(renewal.hold_private_input(root/PENDING))
    require(stack.enter_context(renewal.hold_private_input(root/COMPLETED))==b'')
    hashes=receipt_hashes(stage,next_config,
        {name:renewal.read_private_bytes(root/name) for name in stage_names if name!='intent.json'},
        pending_sha256=selection.digest(receipt))
    return {'root':str(root),'receipt_sha256':selection.digest(receipt),
            'guard_sha256':selection.digest(selection.packed(stage)),'result':proof(stage,record,hashes)}


def finish(config_path, pending):
    """Promote only after the initial selected lease and fresh reproof exit.

    Failed pre-promotion proof exits leave the pending receipt unusable. A rename
    followed by failed postchecks is uncertain publication and requires fresh
    reproof. There is no public retry/promote command or automatic phase replay.
    """
    from selfhost_windows_staging_recovery import _failed_current_inputs
    root=Path(pending['root'])
    with ExitStack() as coordination:
        with _failed_current_inputs(config_path,_coordination=coordination,
                _expired_pending_sha256=pending['receipt_sha256']) as lease:
            result=lease['proof']
            require(lease['failed_root']==root and result['schema']==PROOF_SCHEMA
                    and result['guard_sha256']==pending['guard_sha256'] and result==pending['result'])
        # All selection, generation, configuration, namespace and ForeignContext
        # checks have closed. Exclusive coordination remains held for promotion.
        with renewal.hold_storage_namespace(root):
            with selection._held_private_input(root/PENDING,_rename_to=root/REFUSED) as raw:
                require(selection.digest(raw)==pending['receipt_sha256'])
    return result


def prepare_selected(config_path, output_dir, logical_project):
    """Explicit prepare-only entry, never ordinary renewal or scheduled retry."""
    selection.require_logical_tls_project(logical_project)
    with selection.selected_inputs(config_path) as lease:
        result=lease.prepare_expired_current(output_dir,logical_project)
    # selected_inputs publishes only after its entire selected lease exits.
    return result
