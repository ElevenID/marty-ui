"""Typed recovery successors; contracts alone never select a generation."""
from copy import deepcopy
from pathlib import Path
import re

import selfhost_windows_selection as selection

SCHEMA = 'marty.windows-recovery-successor/v1'
INTENT = 'recovery.intent.json'
DECISION = 'recovery.selection.json'
FILES = {INTENT, DECISION}
OPERATOR_FIELDS = {'binary','binary_sha256','source_sha','release_tag'}


def checked_successor_binding(previous, successor, admission):
    """Preserve the admitted operator or bind one freshly admitted successor.

    The finishing owner must provide the admission obtained under its held
    signature/API/capability context. A serialized dict is never that authority.
    """
    require=selection.require
    require(type(previous) is dict and type(successor) is dict)
    if admission is None:
        require(previous==successor)
        return deepcopy(successor)
    expected=deepcopy(previous)
    require(set(successor)==set(previous) and type(admission) is dict)
    require(set(admission)=={'schema','source_sha','release_tag','run_id','run_attempt','binary_sha256',
                            'historical_operator_sha256','verifier_sha256'})
    require(admission['schema']=='marty.windows-recovery-operator-admission/v1')
    require(admission['historical_operator_sha256']==previous['native']['binary_sha256'])
    require(re.fullmatch(r'[0-9a-f]{40}',admission['source_sha'])
            and re.fullmatch(r'v\d+\.\d+\.\d+',admission['release_tag'])
            and re.fullmatch(r'[0-9a-f]{64}',admission['binary_sha256']))
    require(all(type(admission[key]) is int and admission[key]>0 for key in ('run_id','run_attempt')))
    verifiers=admission['verifier_sha256']
    require(type(verifiers) is dict and set(verifiers)=={'gh','cosign'}
            and all(type(value) is str and re.fullmatch(r'[0-9a-f]{64}',value) for value in verifiers.values()))
    require(set(successor['native'])==set(previous['native']))
    binary=Path(successor['native']['binary'])
    require(binary.is_absolute() and binary.name=='marty-deploy-linux-amd64'
            and successor['native']['binary']!=previous['native']['binary'])
    for field in OPERATOR_FIELDS:
        expected['native'][field]=successor['native'][field]
    require(expected==successor)
    require(all(successor['native'][field]==admission[field]
                for field in ('binary_sha256','source_sha','release_tag')))
    require(successor['native']['binary_sha256']!=previous['native']['binary_sha256'])
    return deepcopy(successor)


def successor_configuration(config, root):
    """Separate retained recovery receipts from future ordinary operations."""
    result=deepcopy(config)
    for key in ('intent','result','new_log','rollback_log'):
        result[key]=str(Path(root)/'selection'/('credential-'+key+'.json'))
    result['step_receipts']=[{key:str(Path(root)/'selection'/f'credential-{index:03}-{key}.json')
        for key in step} for index,step in enumerate(config['step_receipts'])]
    return result


def derive_seed(*, previous_binding, previous_intent, previous_record, config_path, config_raw,
                snapshots, admission, publication_raw, activation_intent_raw, activation_result_raw,
                source_dir, transition_sha256, generation_sequence):
    """Derive inert successor bytes from already held and authenticated evidence.

    The finishing owner must bind these inputs to the complete predecessor and
    actual runtime under its project lock. This function writes nothing and
    never authorizes guard removal or bypasses a native proof.
    """
    from selfhost_windows_continuation import CHECKPOINT
    from selfhost_windows_model import model_binding
    from selfhost_windows_staging_recovery import RECOVERY_RECEIPTS
    require=selection.require
    config=selection.decode(config_raw)
    require(config_raw==selection.packed(config) and Path(config_path).is_absolute()
            and Path(source_dir).is_absolute())
    owner=checked_successor_binding(previous_binding,selection.binding(config),admission)
    require(Path(source_dir).parent==Path(owner['root']) and Path(config_path).name=='config.private.json'
            and Path(config_path).is_relative_to(Path(owner['root'])))
    require(previous_intent['schema']==previous_record['schema']==selection.SCHEMA
            and previous_record['intent_sha256']==selection.digest(selection.packed(previous_intent))
            and previous_record['selected']==previous_intent['inputs'][previous_record['choice']])
    require(type(generation_sequence) is int and generation_sequence>0
            and type(transition_sha256) is str and re.fullmatch(r'[0-9a-f]{64}',transition_sha256))
    publication=selection.decode(publication_raw)
    intent=selection.decode(activation_intent_raw)
    result=selection.decode(activation_result_raw)
    require(all(raw==selection.packed(value) for raw,value in ((publication_raw,publication),
        (activation_intent_raw,intent),(activation_result_raw,result))))
    require(set(publication)=={'schema','guard_sha256','config_sha256','receipt_sha256',
                              'generation_sha256','sequence','data_sha256','credential_admission','guards_retained'})
    require(set(intent)=={'schema','project','publication_sha256','data_mounts_before','layers','rollback_to_expired'})
    require(type(publication['receipt_sha256']) is dict and set(publication['receipt_sha256'])==RECOVERY_RECEIPTS
            and all(type(value) is str and re.fullmatch(r'[0-9a-f]{64}',value)
                    for value in publication['receipt_sha256'].values()))
    require(publication['schema']=='marty.windows-recovery-candidate-publication/v1'
            and publication['sequence']==previous_record['sequence']
            and publication['config_sha256']==selection.digest(config_raw)
            and publication['credential_admission'] is False and publication['guards_retained'] is True)
    require(intent['schema']=='marty.windows-recovery-activation/v1' and intent['project']==owner['project']
            and intent['publication_sha256']==selection.digest(publication_raw)
            and intent['rollback_to_expired'] is False)
    require(set(result)=={'schema','result','project','secret_mounts','data_sha256',
                         'guards_retained','rollback_to_expired','credential_admission'})
    require(result['schema']==intent['schema'] and result['result']=='activated-unselected'
            and result['project']==owner['project'] and type(result['secret_mounts']) is int
            and result['secret_mounts']>0 and result['guards_retained'] is True
            and result['rollback_to_expired'] is False and result['credential_admission'] is False)
    data_sha=selection.digest(selection.packed(intent['data_mounts_before']))
    require(data_sha==previous_record['data_sha256']==publication['data_sha256']==result['data_sha256'])
    require(set(snapshots)=={'old','new'} and snapshots['old']==previous_record['selected']
            and snapshots['new']['secrets_sha256']==publication['generation_sha256'])
    for choice,prefix,mirror in (('old','current','current'),('new','renewed','renewed')):
        snapshot=snapshots[choice]
        require(set(snapshot)=={'env_file','env_sha256','secrets_dir','secrets_sha256','native_mirror'}
                and snapshot['env_file']==config[prefix+'_env']
                and snapshot['secrets_dir']==config[prefix+'_secrets']
                and snapshot['native_mirror']==config['native'][mirror]
                and all(type(snapshot[key]) is str and re.fullmatch(r'[0-9a-f]{64}',snapshot[key])
                        for key in ('env_sha256','secrets_sha256')))
    successor=successor_configuration(config,Path(config_path).parent)
    successor_raw=selection.packed(successor)
    first={'schema':selection.SCHEMA,'sequence':1,'parent':None,'operation':'recovery-successor',
           'config_path':str(Path(config_path).parent/'selection.config.private.json'),
           'config_file_sha256':selection.digest(successor_raw),
           'config_sha256':selection.config_digest(successor),'inputs':deepcopy(snapshots),
           'result_before_sha256':selection.digest(b'')}
    selected={'schema':selection.SCHEMA,'sequence':1,'parent':None,
              'intent_sha256':selection.digest(selection.packed(first)),'decision':'recovered-new',
              'choice':'new','selected':deepcopy(snapshots['new']),'data_sha256':data_sha,
              'result_sha256':selection.digest(b''),'transition_intent_sha256':selection.digest(b'')}
    carry={'schema':SCHEMA,'source_dir':str(source_dir),'intent_sha256':transition_sha256,
           'sequence_offset':generation_sequence,'generation_model':model_binding(config),
           'first_intent':first,'first_selection':selected}
    return {'owner.json':selection.packed({'schema':selection.SCHEMA,'binding':owner}),
            CHECKPOINT:selection.packed(carry),'000001.intent.json':selection.packed(first),
            '000001.selection.json':selection.packed(selected)}


def validate_marker(raw, expected, current_model, journal):
    """A recovery link seals the predecessor; missing decisions never fall back."""
    from selfhost_windows_continuation import INTENT as continuation, checkpoint
    from selfhost_windows_product_journal import INTENT as product
    require=selection.require
    marker=selection.decode(raw[INTENT])
    require(raw[INTENT]==selection.packed(marker) and continuation not in raw and product not in raw)
    require(set(marker)=={'schema','project','engine_id','source_dir','target_dir','source_sha256',
        'attempt_dir','config_sha256','generation_sequence','evidence_sha256','candidate_only'})
    require(marker['schema']==SCHEMA and marker['candidate_only'] is True
        and marker['project']==expected['project'] and marker['engine_id']==expected['engine_id']
        and marker['source_dir']==str(journal))
    require(marker['source_sha256']=={name:selection.digest(body) for name,body in raw.items() if name not in FILES})
    intents,records=selection._parse(raw,expected)
    require(len(intents)==len(records))
    carry=checkpoint(raw)
    require(type(marker['generation_sequence']) is int and marker['generation_sequence']==
        len(records)+(carry['sequence_offset'] if carry else 0))
    root,target=Path(marker['attempt_dir']),Path(marker['target_dir'])
    require(root.parent==target.parent==Path(expected['root'])
        and re.fullmatch(r'windows-renewal-[0-9a-f]{32}',root.name)
        and re.fullmatch(re.escape('.'+expected['project']+'.generation-recovery-')+r'[0-9a-f]{32}',target.name))
    require(type(marker['evidence_sha256']) is dict and marker['evidence_sha256']
        and all(type(name) is str and type(value) is str and re.fullmatch(r'[0-9a-f]{64}',value)
                for name,value in marker['evidence_sha256'].items()))
    require(type(marker['config_sha256']) is str and re.fullmatch(r'[0-9a-f]{64}',marker['config_sha256']))
    return marker


def seed(raw,expected,current_model,marker,stack):
    """Replay held immutable recovery execution evidence, never live admission."""
    from selfhost_windows_inputs import _held_private_input
    from selfhost_windows_model import effective_config, model_binding
    from selfhost_windows_staging_recovery import RECOVERY_RECEIPTS, recovery_phase_receipts, failed_current_receipts
    renewal=selection.renewal;require=selection.require
    require(validate_marker(raw,expected,current_model,Path(marker['source_dir']))==marker)
    intents,records=selection._parse(raw,expected)
    prior_intent,prior=intents[len(records)],records[len(records)]
    old_raw=stack.enter_context(renewal.hold_private_input(Path(prior_intent['config_path'])))
    require(selection.digest(old_raw)==prior_intent['config_file_sha256'])
    old=effective_config(selection.decode(old_raw),current_model)
    root=Path(marker['attempt_dir'])
    stack.enter_context(renewal.hold_storage_namespace(root))
    stack.enter_context(_held_private_input(root,directory=True))
    config_path=root/'config.private.json'
    config_raw=stack.enter_context(renewal.hold_private_input(config_path))
    config=selection.decode(config_raw)
    require(config_raw==selection.packed(config) and selection.digest(config_raw)==marker['config_sha256'])
    stage=selection.decode(stack.enter_context(renewal.hold_private_input(root/'intent.json')))
    require(set(stage)=={'schema','failed_proof','failed_root','root','logical_project','config_sha256',
                        'operator_admission','credential_admission','rollback_to_expired'}
        and stage['schema']=='marty.windows-expired-renewal-staging/v1' and stage['root']==str(root)
        and stage['config_sha256']==marker['config_sha256'] and stage['credential_admission'] is False
        and stage['rollback_to_expired'] is False)
    failure=stage['failed_proof'];failed=Path(stage['failed_root'])
    require(failed.parent==root.parent and failed!=root and re.fullmatch(r'windows-renewal-[0-9a-f]{32}',failed.name)
        and failure['schema']=='marty.windows-failed-current-proof/v1' and failure['sequence']==prior['sequence']
        and failure['project']==expected['project'] and failure['data_sha256']==prior['data_sha256']
        and failure['credential_admission'] is False and failure['guard_retained'] is True)
    stack.enter_context(renewal.hold_storage_namespace(failed))
    stack.enter_context(_held_private_input(failed,directory=True))
    failed_intent_raw=stack.enter_context(renewal.hold_private_input(failed/'intent.json'))
    require(selection.digest(failed_intent_raw)==failure['guard_sha256'])
    failed_receipts={name:stack.enter_context(renewal.hold_private_input(failed/name))
        for name in selection._stage_names() if name!='intent.json'}
    require(failed_current_receipts(failed_receipts)==failure['receipt_sha256'])
    # Reconstruct the only staged configuration, including admitted operator fields.
    model_raw=stack.enter_context(renewal.hold_private_input(Path(config['compose_file']),max_bytes=2*1024*1024))
    model=selection.decode(model_raw)
    require(selection.digest(model_raw)==config['compose_sha256'])
    execution=selection.decode(stack.enter_context(renewal.hold_private_input(Path(config['intent']))))
    services=set(execution['data_mounts_before'])
    require(services and services<=set(model['services']))
    layers=renewal.dependency_layers(model,services,renewal.owned_roles(model,services))
    require(execution['layers']==layers)
    failed_config=selection._stage_configuration(old,prior['choice'],prior,failed,layers)
    failed_config_raw=stack.enter_context(renewal.hold_private_input(failed/'activation/config.private.json'))
    require(failed_config_raw==selection.packed(failed_config))
    failed_intent=selection.decode(failed_intent_raw)
    failed_cycle=failed.name.removeprefix('windows-renewal-')
    require(failed_intent_raw==selection.packed(failed_intent) and failed_intent=={
        'schema':selection.STAGE_SCHEMA,'project':expected['project'],'engine_id':expected['engine_id'],
        'sequence':prior['sequence']+1,'selected_sha256':selection.digest(selection.packed(prior['selected'])),
        'data_sha256':prior['data_sha256'],'root':str(failed),
        'config_path':str(failed/'activation/config.private.json'),'config_sha256':selection.digest(failed_config_raw),
        'authority_file':'/control/recovery-session-'+failed_cycle+'/token',
        'logical_project':failed_intent['logical_project'],
        'services_image':model['services']['signing-keys']['image'],'candidate_only':True})
    require(re.fullmatch(r'marty-selfhost-[a-z0-9][a-z0-9-]{0,59}',failed_intent['logical_project']))
    require({p.name for p in failed.iterdir()}==set(selection._stage_names())|
            {'result.json','publication.pending.json','renewed.env','activation'})
    failed_paths=[Path(failed_config[name]) for name in ('intent','result','new_log','rollback_log')]
    failed_paths += [Path(path) for step in failed_config['step_receipts'] for path in step.values()]
    stack.enter_context(_held_private_input(failed/'activation',directory=True))
    require({p.name for p in (failed/'activation').iterdir()}=={'config.private.json',*(p.name for p in failed_paths)})
    for path in [*failed_paths,failed/'result.json',failed/'publication.pending.json']:
        require(stack.enter_context(renewal.hold_private_input(path))==b'')
    failed_env=stack.enter_context(renewal.hold_private_input(failed/'renewed.env'))
    old_env=stack.enter_context(renewal.hold_private_input(Path(failed_config['current_env'])))
    require(renewal.env_body(failed_env,Path(failed_config['renewed_secrets']))==
            renewal.env_body(old_env,Path(failed_config['current_secrets'])))
    failed_candidate=Path(failed_config['renewed_secrets'])
    stack.enter_context(renewal.hold_storage_namespace(failed_candidate))
    stack.enter_context(_held_private_input(failed_candidate,directory=True))
    require(not list(failed_candidate.iterdir()))
    stack.callback(lambda:require(not list(failed_candidate.iterdir())))
    reconstructed=selection._stage_configuration(old,prior['choice'],prior,root,layers)
    for field in OPERATOR_FIELDS:reconstructed['native'][field]=config['native'][field]
    require(reconstructed==config and model_binding(old)==model_binding(config))
    paths=[Path(config[key]) for key in ('intent','result','new_log','rollback_log')]
    paths += [Path(path) for step in config['step_receipts'] for path in step.values()]
    require(all(path.parent==root/'activation' for path in paths))
    successor=successor_configuration(config,root)
    successor_path=root/'selection.config.private.json'
    require(stack.enter_context(renewal.hold_private_input(successor_path))==selection.packed(successor))
    selection_paths=[Path(successor[key]) for key in ('intent','result','new_log','rollback_log')]
    selection_paths += [Path(path) for step in successor['step_receipts'] for path in step.values()]
    require(all(path.parent==root/'selection' for path in selection_paths))
    stack.enter_context(_held_private_input(root/'selection',directory=True))
    require({path.name for path in (root/'selection').iterdir()}=={path.name for path in selection_paths})
    require(all(stack.enter_context(renewal.hold_private_input(path))==b'' for path in selection_paths))
    expected_files={*RECOVERY_RECEIPTS,'intent.json','config.private.json','publication.json','renewed.env',
                    'selection.config.private.json',
                    *(str(path.relative_to(root)).replace('\\','/') for path in selection_paths),
                    *(str(path.relative_to(root)).replace('\\','/') for path in paths)}
    require(set(marker['evidence_sha256'])==expected_files)
    require({path.name for path in root.iterdir()}==set(RECOVERY_RECEIPTS)|
        {'intent.json','config.private.json','publication.json','renewed.env','activation','selection','selection.config.private.json'})
    stack.enter_context(_held_private_input(root/'activation',directory=True))
    require({path.name for path in (root/'activation').iterdir()}=={path.name for path in paths})
    bodies={name:stack.enter_context(renewal.hold_private_input(root/name,max_bytes=2*1024*1024)) for name in expected_files}
    require(all(selection.digest(body)==marker['evidence_sha256'][name] for name,body in bodies.items()))
    receipts={name:bodies[name] for name in RECOVERY_RECEIPTS}
    hashes,_=recovery_phase_receipts(receipts,expected['project'],root.name.removeprefix('windows-renewal-'),
        config['native']['helper_image'],model['services']['signing-keys']['image'])
    publication=selection.decode(bodies['publication.json'])
    require(publication['receipt_sha256']==hashes and publication['guard_sha256']==selection.digest(bodies['intent.json']))
    for index,layer in enumerate(layers):
        step=config['step_receipts'][index]
        for event in ('started','completed'):
            require(bodies[str(Path(step['new_'+event]).relative_to(root)).replace('\\','/')]==
                    selection.packed({'roles':layer,'event':event}))
            require(bodies[str(Path(step['rollback_'+event]).relative_to(root)).replace('\\','/')]==b'')
    require(bodies['activation/rollback_log']==b'')
    _values,snapshots=selection._inputs(config,stack)
    old_binding_config=deepcopy(old);old_binding_config.pop('_historical_compose_sha256',None)
    return derive_seed(previous_binding=selection.binding(old_binding_config),previous_intent=prior_intent,previous_record=prior,
        config_path=config_path,config_raw=config_raw,snapshots=snapshots,admission=stage['operator_admission'],
        publication_raw=bodies['publication.json'],activation_intent_raw=bodies['activation/intent'],
        activation_result_raw=bodies['activation/result'],source_dir=Path(marker['source_dir']),
        transition_sha256=selection.digest(selection.packed(marker)),generation_sequence=marker['generation_sequence'])


def decision(marker,initial):
    return {'schema':SCHEMA,'intent_sha256':selection.digest(selection.packed(marker)),
            'target_entries_sha256':{name:selection.digest(body) for name,body in initial.items()},'candidate_only':True}
