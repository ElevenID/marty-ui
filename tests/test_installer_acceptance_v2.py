"""Closed qualification gates: synthetic records never become installed proof."""
import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import installer_acceptance as legacy
import installer_acceptance_v2 as v2
import installer_release as release
from test_installer_host_admission import observed_rootless_host_with_neighbors


def typed_case(case='ip-entry-browser'):
    scope = dict(installation_id='22345678-1234-4234-8234-123456789abc',engine_id='test-engine-12345678',
                 operator_sha256='a'*64,context_sha256='b'*64,authorized_at=100000)
    proof = dict(schema=f'elevenid.installer-installed-{case}/v1',case=case,scope=scope,selection=None,
                 started_at=100001,completed_at=100002,status='passed',checks=dict.fromkeys(v2.CASE_CHECKS[case],True),
                 native_evidence={owner:dict(name=owner+'-12345678-1234-4234-8234-123456789abc.json',sha256='c'*64,
                     owner_schema=f'elevenid.installer-qualification-{owner}/v1',
                     **{key:scope[key] for key in ('installation_id','engine_id','operator_sha256','context_sha256')},
                     selection=None,started_at=100001,completed_at=100002) for owner in v2.CASE_OWNERS[case]})
    return proof,dict(case=case,scope=copy.deepcopy(scope),selection=None,observed_at=100003)


def test_new_profiles_preserve_all_old_cases_and_require_real_new_owners():
    assert set(legacy.CASES) <= set(v2.FUNCTIONAL_CASES)
    assert set(v2.STARTUP_CASES) < set(v2.FUNCTIONAL_CASES)
    assert set(v2.RECOVERY_CASES) <= set(v2.FUNCTIONAL_CASES)
    assert v2.MIN_MEMORY_BYTES==7*1024**3 and legacy.MIN_MEMORY_BYTES==32*1024**3
    assert set(v2.missing_writers(v2.FUNCTIONAL_PROFILE))==set(v2.FUNCTIONAL_CASES)-set(v2.STARTUP_CASES)
    assert v2.IMPLEMENTED_INSTALLED_WRITERS==frozenset(v2.STARTUP_CASES)
    assert v2.missing_writers(v2.STARTUP_PROFILE)==()


@pytest.mark.parametrize('case',v2.FUNCTIONAL_CASES)
def test_caller_passed_json_cannot_graduate_any_unimplemented_installed_owner(case):
    proof,kwargs=typed_case(case)
    with pytest.raises(ValueError,match='owner and native proof adapter unavailable'):
        v2.validate_case_proof(proof,**kwargs)


@pytest.mark.parametrize('mutation',['generic','case','check','operator','engine','installation','context','clock','selection','owner'])
def test_case_specific_scope_and_native_references_are_checked_before_owner_gate(mutation):
    proof,kwargs=typed_case()
    reference=next(iter(proof['native_evidence'].values()))
    if mutation=='generic':
        proof=dict(schema='elevenid.installer-installed-case/v1',case='ip-entry-browser',scope=proof['scope'],
            selection=None,observed_at=100002,status='passed',checks=dict.fromkeys(
                ('assertion_performed','exact_signed_artifacts','owned_installation_only','tls_verification_enabled',
                 'runtime_unmodified','source_checkout_not_used'),True))
    elif mutation=='case':proof['case']='browser-tls-login'
    elif mutation=='check':proof['checks']['no_ip_session_request_or_cookie']=False
    elif mutation=='operator':reference['operator_sha256']='d'*64
    elif mutation=='engine':reference['engine_id']='other-engine'
    elif mutation=='installation':reference['installation_id']='12345678-1234-4234-8234-123456789abc'
    elif mutation=='context':reference['context_sha256']='d'*64
    elif mutation=='clock':reference['completed_at']=100004
    elif mutation=='selection':reference['selection']={'current_binding_sha256':'d'*64}
    elif mutation=='owner':proof['native_evidence']['standalone-bao-fixture']=proof['native_evidence'].pop('installed-browser')
    with pytest.raises(ValueError) as error:v2.validate_case_proof(proof,**kwargs)
    assert 'adapter unavailable' not in str(error.value)


@pytest.mark.parametrize('profile',[v2.STARTUP_PROFILE,v2.FUNCTIONAL_PROFILE])
def test_report_emitter_stays_held_until_installed_writers_exist(profile):
    with pytest.raises(ValueError,match='installed qualification writers unavailable'):
        v2.produce(completed_case_bytes={name:release.encode(typed_case(name)[0]) for name in v2.cases_for(profile)},
            report={'profile':profile},inventory_bytes=b'{}',source_sha='a'*40,release_tag='v1.2.3',phase='staged',run={})


def test_startup_schema_cannot_enter_the_release_admission_contract():
    fixture=json.loads((Path(__file__).resolve().parents[1]/'rust/crates/deployment-catalog/tests/fixtures/installer-candidate-hosting-v2.json').read_text())[1]
    authorization=release.decode(fixture['authorization']) if isinstance(fixture['authorization'],bytes) else release.decode(fixture['authorization'].encode())
    report=dict(schema=v2.SCHEMA,repository=release.REPOSITORY,source_sha=authorization['source_sha'],source_ref='refs/heads/main',
        harness_source_sha=authorization['harness_source_sha'],release_tag=authorization['release_tag'],phase='published',
        platform='linux/amd64',inventory_sha256='sha256:'+release.digest(fixture['inventory'].encode()),
        workflow=legacy.WORKFLOW,run_id=authorization['run_id'],run_attempt=authorization['run_attempt'],
        profile=v2.STARTUP_PROFILE,authority={},host_observation='',scope={},selection=None,cases={},proofs={},
        neighbor_preservation={},cleanup={},observed_at=100003,load_characterized=False)
    run=dict(repository=dict(full_name=release.REPOSITORY),path=legacy.WORKFLOW,event='workflow_dispatch',
        head_branch='main',head_sha=authorization['harness_source_sha'],id=authorization['run_id'],
        run_attempt=authorization['run_attempt'],status='completed',conclusion='success')
    with pytest.raises(ValueError,match='startup evidence cannot promote'):
        legacy.validate(report,inventory_bytes=fixture['inventory'].encode(),source_sha=authorization['source_sha'],
                        release_tag=authorization['release_tag'],phase='published',run=run)
