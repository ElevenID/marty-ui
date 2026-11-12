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
    """Exactly one freshly admitted operator, preserving all runtime bindings.

    The finishing owner must provide the admission obtained under its held
    signature/API/capability context. A serialized dict is never that authority.
    """
    require=selection.require
    require(type(previous) is dict and type(successor) is dict)
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
    first={'schema':selection.SCHEMA,'sequence':1,'parent':None,'operation':'recovery-successor',
           'config_path':str(config_path),'config_file_sha256':selection.digest(config_raw),
           'config_sha256':selection.config_digest(config),'inputs':deepcopy(snapshots),
           'result_before_sha256':selection.digest(b'')}
    selected={'schema':selection.SCHEMA,'sequence':1,'parent':None,
              'intent_sha256':selection.digest(selection.packed(first)),'decision':'recovered-new',
              'choice':'new','selected':deepcopy(snapshots['new']),'data_sha256':data_sha,
              'result_sha256':selection.digest(activation_result_raw),
              'transition_intent_sha256':selection.digest(activation_intent_raw)}
    carry={'schema':SCHEMA,'source_dir':str(source_dir),'intent_sha256':transition_sha256,
           'sequence_offset':generation_sequence,'generation_model':model_binding(config),
           'first_intent':first,'first_selection':selected}
    return {'owner.json':selection.packed({'schema':selection.SCHEMA,'binding':owner}),
            CHECKPOINT:selection.packed(carry),'000001.intent.json':selection.packed(first),
            '000001.selection.json':selection.packed(selected)}
