"""Recovery cannot smuggle a runtime/model/storage change into operator succession."""
from copy import deepcopy
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from selfhost_windows_recovery_journal import checked_successor_binding, derive_seed
import selfhost_windows_selection as selection
from selfhost_windows_staging_recovery import RECOVERY_RECEIPTS

def bindings(tmp_path):
    old={'project':'marty-production-synthetic','engine_id':'PUBLIC_ENGINE','docker_host':'PUBLIC_PIPE',
         'compose_file':str(tmp_path/'model.json'),'compose_sha256':'1'*64,'root':str(tmp_path),
         'native':{'binary':str(tmp_path/'old-operator'),'binary_sha256':'a'*64,'source_sha':'a'*40,
                   'release_tag':'v1.2.3','helper_image':'PUBLIC_HELPER','control_volume':'PUBLIC_CONTROL',
                   'network':'PUBLIC_NETWORK','bao_addr':'https://openbao:8200','ca_file':'PUBLIC_CA'}}
    new=deepcopy(old)
    new['native'].update(binary=str(tmp_path/'new'/'marty-deploy-linux-amd64'),
                         binary_sha256='b'*64,source_sha='b'*40,release_tag='v1.2.4')
    admission={'schema':'marty.windows-recovery-operator-admission/v1','source_sha':'b'*40,
        'release_tag':'v1.2.4','binary_sha256':'b'*64,'run_id':42,'run_attempt':1,
        'historical_operator_sha256':'a'*64,'verifier_sha256':{'gh':'c'*64,'cosign':'d'*64}}
    return old,new,admission

def test_exact_operator_successor_preserves_its_predecessor(tmp_path):
    old,new,admission=bindings(tmp_path)
    saved=deepcopy(old)
    result=checked_successor_binding(old,new,admission)
    assert result==new and old==saved
    result['native']['network']='PUBLIC_CHANGED'
    assert new['native']['network']=='PUBLIC_NETWORK'

@pytest.mark.parametrize('field',['project','engine_id','docker_host','compose_file','compose_sha256','root',
    'native.helper_image','native.control_volume','native.network','native.bao_addr','native.ca_file',
    'native.binary_sha256','native.source_sha','native.release_tag'])
def test_unadmitted_binding_changes_refuse(tmp_path,field):
    old,new,admission=bindings(tmp_path)
    if field.startswith('native.'):
        new['native'][field.split('.')[1]]='PUBLIC_CHANGED'
    else:new[field]='PUBLIC_CHANGED'
    with pytest.raises(ValueError):checked_successor_binding(old,new,admission)

@pytest.mark.parametrize('fault',['predecessor','verifier','run','extra'])
def test_admission_identity_must_match_both_generations(tmp_path,fault):
    old,new,admission=bindings(tmp_path)
    if fault=='predecessor':admission['historical_operator_sha256']='0'*64
    elif fault=='verifier':admission['verifier_sha256']['gh']='PUBLIC_UNPINNED'
    elif fault=='run':admission['run_attempt']=True
    else:admission['override']=True
    with pytest.raises(ValueError):checked_successor_binding(old,new,admission)


def seed_inputs(tmp_path):
    old,new,admission=bindings(tmp_path)
    cfg=deepcopy(new)
    cfg.update(schema=selection.renewal.SCHEMA,candidate_only=True,
        current_secrets=str(tmp_path/'selected'),renewed_secrets=str(tmp_path/'recovered'),
        current_env=str(tmp_path/'selected.env'),renewed_env=str(tmp_path/'recovered.env'))
    cfg['native'].update(minimum_ttl=3600,current='/control/selected/generation',renewed='/control/recovered/generation')
    snapshots={choice:{'env_file':cfg[prefix+'_env'],'env_sha256':'e'*64,
        'secrets_dir':cfg[prefix+'_secrets'],'secrets_sha256':('f' if choice=='new' else 'e')*64,
        'native_mirror':cfg['native'][prefix]} for choice,prefix in (('old','current'),('new','renewed'))}
    previous={'schema':selection.SCHEMA,'sequence':24,'parent':'1'*64,'config_path':'PUBLIC_PREVIOUS_CONFIG',
        'config_file_sha256':'2'*64,'config_sha256':'3'*64,'inputs':{'old':{},'new':snapshots['old']},
        'operation':'activation','result_before_sha256':selection.digest(b'')}
    data=selection.digest(selection.packed({}))
    record={'schema':selection.SCHEMA,'sequence':24,'parent':'1'*64,'intent_sha256':selection.digest(selection.packed(previous)),
        'decision':'activated','choice':'new','selected':snapshots['old'],'data_sha256':data,
        'result_sha256':'4'*64,'transition_intent_sha256':'5'*64}
    publication={'schema':'marty.windows-recovery-candidate-publication/v1','guard_sha256':'6'*64,
        'config_sha256':selection.digest(selection.packed(cfg)),
        'receipt_sha256':{name:'8'*64 for name in RECOVERY_RECEIPTS},'generation_sha256':'f'*64,
        'sequence':24,'data_sha256':data,'credential_admission':False,'guards_retained':True}
    intent={'schema':'marty.windows-recovery-activation/v1','project':old['project'],
        'publication_sha256':selection.digest(selection.packed(publication)),'data_mounts_before':{},
        'layers':[['gateway']],'rollback_to_expired':False}
    result={'schema':intent['schema'],'result':'activated-unselected','project':old['project'],
        'secret_mounts':1,'data_sha256':data,'guards_retained':True,'rollback_to_expired':False,'credential_admission':False}
    return dict(previous_binding=old,previous_intent=previous,previous_record=record,config_path=tmp_path/'config.private.json',
        config_raw=selection.packed(cfg),snapshots=snapshots,admission=admission,
        publication_raw=selection.packed(publication),activation_intent_raw=selection.packed(intent),
        activation_result_raw=selection.packed(result),source_dir=tmp_path/'journal',transition_sha256='7'*64,generation_sequence=24)


def test_recovery_seed_selects_new_generation_and_retains_execution_hashes(tmp_path):
    args=seed_inputs(tmp_path)
    seed=derive_seed(**args)
    selected=selection.decode(seed['000001.selection.json'])
    assert selected['selected']==args['snapshots']['new'] and selected['decision']=='recovered-new'
    assert selected['result_sha256']==selection.digest(args['activation_result_raw'])
    assert selection.decode(seed['checkpoint.json'])['sequence_offset']==24


@pytest.mark.parametrize('fault',['predecessor','selection','data','rollback','result','mirror','config','publication'])
def test_unbound_execution_cannot_seed_recovery(tmp_path,fault):
    args=seed_inputs(tmp_path)
    if fault=='predecessor':args['previous_record']['intent_sha256']='0'*64
    elif fault=='selection':args['previous_record']['selected']={}
    elif fault=='mirror':args['snapshots']['new']['native_mirror']='/control/foreign/generation'
    elif fault=='config':args['config_raw']+=b' '
    else:
        name='activation_result_raw' if fault in ('rollback','result','data') else 'publication_raw'
        record=selection.decode(args[name])
        if fault=='rollback':record['rollback_to_expired']=True
        elif fault=='result':record['result']='rolled-back'
        elif fault=='data':record['data_sha256']='0'*64
        else:record['sequence']=23
        args[name]=selection.packed(record)
    with pytest.raises(ValueError):derive_seed(**args)
