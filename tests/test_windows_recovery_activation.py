"""Real NTFS activation intent/failure controls; Compose/native oracles mocked."""
from contextlib import contextmanager
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_windows_recovery_publication import prepared
import selfhost_windows_recovery_activation as activation
import selfhost_windows_staging_recovery as recovery
import selfhost_windows_selection as selection

@pytest.mark.parametrize('fault',[None,'uncertain','data','native','result-replaced'])
def test_activation_never_rolls_back_or_clears_guards(monkeypatch,fault):
    with prepared(monkeypatch) as (path,cfg,output,events):
        recovery.publish_recovery_candidate(path,output)
        original=activation._recovery_candidate_inputs
        state={}
        @contextmanager
        def inputs(*args,**kwargs):
            with original(*args,**kwargs) as lease:
                observed=lease['observed'];docker=observed['docker']
                # Existing fixture substitutes runtime hashes and model rendering.
                lease['proof']=dict(lease['proof'],data_sha256=selection.digest(selection.packed(
                    activation.renewal.data_mounts(observed['owned']))))
                monkeypatch.setattr(docker,'hashes',lambda command:{},raising=False)
                lease['config'].setdefault('tls_init_receipt',{})
                state.update(lease=lease)
                yield lease
            if fault=='result-replaced':
                result_path=Path(state['lease']['config']['result'])
                result_path.rename(result_path.with_name('result-original'))
                result_path.write_bytes(b'')
        monkeypatch.setattr(activation,'_recovery_candidate_inputs',inputs)
        monkeypatch.setattr(activation.renewal,'checked_models',lambda *args:None)
        monkeypatch.setattr(activation.renewal,'checked_live_configuration',lambda *args:None)
        monkeypatch.setattr(activation.renewal,'checked_secret_mounts',lambda *args,**kwargs:1)
        def recreate(docker,command,changing,services,model,log,progress):
            events.append('activate')
            lease=state['lease']
            assert Path(lease['config']['intent']).read_bytes()
            assert selection.renewal.recovery_guard(cfg).exists()
            assert log.name=='new_log' and changing=={'gateway'}
            if fault=='uncertain':raise selection.renewal.UncertainComposeMutation('PUBLIC_UNCERTAIN')
            for index,layer in enumerate(selection.renewal.dependency_layers(model,services,changing)):
                progress('started',index,layer);progress('completed',index,layer)
        monkeypatch.setattr(activation.renewal,'recreate',recreate)
        original_data=activation.renewal.data_mounts
        def data(items):
            result=original_data(items)
            if fault=='data' and 'activate' in events:result=dict(result,unexpected={'PUBLIC':'changed'})
            return result
        monkeypatch.setattr(activation.renewal,'data_mounts',data)
        def native(*args):
            events.append('fresh-current-proof')
            if fault=='native':raise ValueError('PUBLIC_NATIVE_FAILURE')
        monkeypatch.setattr(activation.native,'preflight_current',native)
        if fault:
            with pytest.raises((ValueError,selection.renewal.UncertainComposeMutation)):
                activation.activate_recovery_candidate(path,output)
            assert (output/'activation/result').read_bytes()==b''
        else:
            result=activation.activate_recovery_candidate(path,output)
            assert result['result']=='activated-unselected' and result['guards_retained']
            assert not result['rollback_to_expired'] and not result['credential_admission']
        assert events.count('activate')==1
        assert (output/'activation/rollback_log').read_bytes()==b''
        assert selection.renewal.recovery_guard(cfg).exists()
        assert selection.renewal.renewal_staging_guard(cfg).exists()


def test_owned_config_change_between_proof_and_baseline_refuses_before_recreate(monkeypatch):
    with prepared(monkeypatch) as (path,cfg,output,events):
        recovery.publish_recovery_candidate(path,output)
        original=activation._recovery_candidate_inputs
        @contextmanager
        def changed(*args,**kwargs):
            with original(*args,**kwargs) as lease:
                observed=lease['observed'];docker=observed['docker']
                previous=docker.containers
                def containers():
                    items=previous()
                    owned=next(item for item in items if activation.renewal._service(item)=='gateway')
                    owned['Config']['Cmd']=['PUBLIC_CHANGED_COMMAND']
                    return items
                monkeypatch.setattr(docker,'containers',containers)
                monkeypatch.setattr(docker,'hashes',lambda command:{},raising=False)
                yield lease
        monkeypatch.setattr(activation,'_recovery_candidate_inputs',changed)
        monkeypatch.setattr(activation.renewal,'checked_models',lambda *args:None)
        monkeypatch.setattr(activation.renewal,'recreate',lambda *args,**kwargs:pytest.fail('Changed baseline admitted'))
        with pytest.raises(ValueError):activation.activate_recovery_candidate(path,output)
        assert selection.renewal.recovery_guard(cfg).exists()
