"""Closed renewal custody interfaces; only synthetic files/public fixture input."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import passport_remote_tls as admission
import selfhost_windows_renewal_native as export

PROJECT='marty-passport-acceptance-trust-00000000-0000-4000-8000-000000000001'


@pytest.mark.parametrize('profile',['passport-role-repair','passport-role-renew'])
def test_selective_admission_keeps_exact_three_files_and_native_issuer_checks(tmp_path,monkeypatch,profile):
    fixture=Path(__file__).resolve().parents[1]/'rust/crates/passport-keyless-edge/tests/fixtures/existing-key-public.pem'
    ca=fixture.read_bytes();source=tmp_path/'source';source.mkdir(mode=0o700);destination=tmp_path/'new';destination.mkdir(mode=0o700)
    old=tmp_path/'old';old.mkdir();(old/'retained.txt').write_bytes(b'unchanged')
    for name in ['workload_identity_ca_cert','trust_profile_workload_server_cert']:(source/name).write_bytes(ca)
    (source/'trust_profile_workload_server_kms_token').write_text('synthetic-scope-token-xxxxxxxxxxxxxxxxxxxx')
    calls=[]
    def native(root,*args,input=None):
        calls.append(args)
        assert args in [('operator','certificate-spki'),('operator','certificate-chain')]
        return b'public-spki' if args[-1]=='certificate-spki' else b'true'
    monkeypatch.setattr(admission,'operator_bytes',native)
    admission.accept_remote_tls(source,destination,'synthetic-authority-token-xxxxxxxxxxxxxxxxxxxx',profile=profile,
                                role='trust-profile-server',expected_workload_ca=fixture)
    assert sorted(p.name for p in destination.iterdir())==['trust_profile_workload_server_cert','trust_profile_workload_server_kms_token','workload_identity_ca_cert']
    assert len(calls)==3 and not list(source.iterdir()) and (old/'retained.txt').read_bytes()==b'unchanged'


def test_renewal_cannot_expand_the_selected_role_or_overwrite_old_generation(tmp_path):
    source=tmp_path/'source';source.mkdir();destination=tmp_path/'old';destination.mkdir()
    with pytest.raises(ValueError,match='contract is invalid'):
        admission.accept_remote_tls(source,destination,'unused',profile='passport-role-renew',role='flow-server',expected_workload_ca=tmp_path/'ca')


def test_export_uses_distinct_closed_cycle_namespace_and_keeps_original():
    base='/control/trust-role-00000000-0000-4000-8000-000000000001'
    assert export._role_generation_mirror(PROJECT,'passport-role-repair')==base+'/generation'
    assert export._role_generation_mirror(PROJECT,'passport-role-renew','a'*32)==base+'/renewal-'+('a'*32)+'/generation'


@pytest.mark.parametrize('cycle',[None,'a'*31,'../generation','A'*32])
def test_export_refuses_missing_or_ambiguous_cycle_before_transport(cycle):
    with pytest.raises(ValueError,match='export refused'):
        export._role_generation_mirror(PROJECT,'passport-role-renew',cycle)
    if cycle is not None:
        with pytest.raises(ValueError,match='export refused'):
            export._role_generation_mirror(PROJECT,'passport-role-repair',cycle)
