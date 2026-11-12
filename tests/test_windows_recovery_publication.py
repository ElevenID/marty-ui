"""Publication requires fresh held proof and never releases either guard."""
from contextlib import contextmanager
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_windows_failed_current_inspection import failed_current
import selfhost_windows_renewal_native as native
import selfhost_windows_staging_recovery as recovery
import selfhost_windows_selection as selection

@contextmanager
def prepared(monkeypatch):
    with failed_current(monkeypatch) as (root,path,cfg,failed,events):
        output=root/('windows-renewal-'+'e'*32);output.mkdir()
        monkeypatch.setattr(native,'require_recovery_capability',lambda *args:None)
        monkeypatch.setattr(native,'preflight_recovery',lambda *args:None)
        def produce(config,current,logical,cycle,image,checkpoint):
            events.append('recovery-producer')
            for phase in ('prepare','tls','keycloak','export'):
                checkpoint(phase,'started',{})
                if phase!='export':
                    metadata={'id':{'prepare':'b','tls':'c','keycloak':'d'}[phase]*64,
                        'name':cfg['project']+'-renew-'+phase+'-'+cycle,
                        'image':image if phase=='tls' else config['native']['helper_image']}
                    if phase=='tls':checkpoint(phase,'created',metadata)
                    checkpoint(phase,'helper',metadata)
                checkpoint(phase,'completed',{})
            return {name:b'' if value==b'' else b'PUBLIC_RECOVERED_'+name.encode() for name,value in current.items()}
        monkeypatch.setattr(native,'produce_recovery_generation',produce)
        recovery.stage_recovery_generation(path,output,'marty-selfhost-synthetic')
        yield path,cfg,output,events


def test_publication_reproves_without_replaying_production_and_keeps_guards(monkeypatch):
    with prepared(monkeypatch) as (path,cfg,output,events):
        proof=recovery.publish_recovery_candidate(path,output)
        assert proof['guards_retained'] and not proof['credential_admission']
        assert (output/'publication.json').read_bytes()==selection.packed(proof)
        assert recovery.publish_recovery_candidate(path,output)==proof
        assert events.count('recovery-producer')==1
        assert selection.renewal.recovery_guard(cfg).exists()
        assert selection.renewal.renewal_staging_guard(cfg).exists()


def test_exit_failure_leaves_pending_receipt_and_requires_fresh_reproof(monkeypatch):
    with prepared(monkeypatch) as (path,cfg,output,events):
        original=recovery._recovery_candidate_inputs
        @contextmanager
        def fail_exit(*args):
            with original(*args) as lease:yield lease
            raise ValueError('PUBLIC_PROOF_EXIT_FAILURE')
        monkeypatch.setattr(recovery,'_recovery_candidate_inputs',fail_exit)
        with pytest.raises(ValueError):recovery.publish_recovery_candidate(path,output)
        assert (output/'publication.pending.json').exists() and not (output/'publication.json').exists()
        monkeypatch.setattr(recovery,'_recovery_candidate_inputs',original)
        recovery.publish_recovery_candidate(path,output)
        assert events.count('recovery-producer')==1


@pytest.mark.parametrize('fault',['phase','config','extra','publication'])
def test_changed_staging_evidence_cannot_be_published(monkeypatch,fault):
    with prepared(monkeypatch) as (path,cfg,output,events):
        if fault=='phase':(output/'candidate.completed.json').write_bytes(b'{}')
        elif fault=='config':(output/'config.private.json').write_bytes(b'{}')
        elif fault=='extra':(output/'extra').write_bytes(b'PUBLIC')
        else:(output/'publication.pending.json').write_bytes(b'{}')
        with pytest.raises((ValueError,KeyError)):
            recovery.publish_recovery_candidate(path,output)
        assert not (output/'publication.json').exists()
        assert selection.renewal.recovery_guard(cfg).exists()
