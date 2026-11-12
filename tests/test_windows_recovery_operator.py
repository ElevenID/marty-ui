"""Successor signatures/API state are reverified under real private NTFS holds."""
import hashlib
import json
import sys
from pathlib import Path

import pytest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_selfhost_windows_inputs import private_fixture
import selfhost_windows_recovery_operator as recovery


@pytest.mark.parametrize('fault',[None,'draft','failed-run','source','unsigned','capability','digest','published-digest'])
def test_operator_admission_preserves_history_and_requires_fresh_proofs(monkeypatch,fault):
    with private_fixture() as (root, _):
        binary=root/'marty-deploy-linux-amd64'
        binary.write_bytes(b'PUBLIC_SYNTHETIC_OPERATOR')
        for suffix in ('.provenance.jsonl','.sigstore.json'):
            (root/(binary.name+suffix)).write_bytes(b'PUBLIC_SYNTHETIC_PROOF')
        expected={'source_sha':'1'*40,'release_tag':'v1.2.3','run_id':42,'run_attempt':2,
                  'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
        if fault=='digest':expected['binary_sha256']='0'*64
        original={'binary':'historical-operator','binary_sha256':'a'*64,'source_sha':'a'*40,
                  'release_tag':'v1.2.2','network':'preserved-network'}
        calls=[]
        def runner(args):
            calls.append(args)
            if '/releases/' in args[-1]:
                return json.dumps({'tag_name':'v1.2.3','draft':fault=='draft','prerelease':False,
                    'published_at':'2026-01-01T00:00:00Z','assets':[{'name':binary.name,'size':binary.stat().st_size,
                    'digest':'sha256:'+('0'*64 if fault=='published-digest' else hashlib.sha256(binary.read_bytes()).hexdigest())}]})
            return json.dumps({'id':42,'run_attempt':2,'head_sha':'0'*40 if fault=='source' else '1'*40,
                'status':'completed','conclusion':'failure' if fault=='failed-run' else 'success',
                'path':'.github/workflows/cd.yml'})
        def verify(subject,bundle,**kwargs):
            assert subject==binary and kwargs['signature_bundle']==root/(binary.name+'.sigstore.json')
            assert kwargs['source_sha']=='1'*40 and kwargs['run_id']==42 and kwargs['run_attempt']==2
            calls.append('signature')
            if fault=='unsigned':raise ValueError('SYNTHETIC_SIGNATURE_REFUSAL')
        def capability(config,prefix):
            assert config['network']=='preserved-network' and config['binary']==str(binary)
            calls.append('capability')
            if fault=='capability':raise ValueError('SYNTHETIC_CAPABILITY_REFUSAL')
        monkeypatch.setattr(recovery.provenance,'verify_subject',verify)
        monkeypatch.setattr(recovery.native,'require_recovery_capability',capability)
        def admit():
            with recovery.admitted_operator(original,root,expected,gh=root/'gh',cosign=root/'cosign',
                                             docker_prefix=[],runner=runner) as (successor,proof):
                assert successor['release_tag']=='v1.2.3'
                assert proof['historical_operator_sha256']=='a'*64
        if fault:
            with pytest.raises(ValueError):admit()
        else:
            admit()
            assert calls[-2:]==['signature','capability']
        assert original['release_tag']=='v1.2.2' and original['binary']=='historical-operator'
