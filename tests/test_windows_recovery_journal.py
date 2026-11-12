"""Recovery cannot smuggle a runtime/model/storage change into operator succession."""
from copy import deepcopy
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from selfhost_windows_recovery_journal import checked_successor_binding

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
