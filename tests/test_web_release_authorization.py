"""Independent admission of a protected private one-job release authority."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import web_release_authorization as approval
import website_provenance as proof
from tests.test_website_provenance import verified


@pytest.fixture
def candidate():
    a = {'schema': 'elevenid.private-run-approval/v1', 'nonce': 'c'*64,
         'repository_id': approval.PRIVATE_ID, 'workflow': approval.WORKFLOW,
         'source': 'b'*40, 'ref': 'refs/heads/main',
         'inputs': {'mode': 'standalone-website', 'ui_source_sha': 'd'*40, 'website_source_sha': 'e'*40},
         'run': 123, 'attempt': 2, 'job': 456, 'runner_id': 789,
         'runner_name': 'elevenid-release-123-2', 'expires': 5000}
    raw = (json.dumps(a, sort_keys=True, separators=(',', ':'))+'\n').encode()
    digest = hashlib.sha256(raw).hexdigest()
    path = f'{approval.DIRECTORY}/{digest}.sha256'
    head, introduction = 'e'*40, 'f'*40
    api = {'': {'id': approval.PUBLIC_ID, 'full_name': approval.PUBLIC, 'private': False},
           '/branches/main': {'name': 'main', 'protected': True, 'commit': {'sha': head}},
           f'/contents/{path}?ref={head}': {'type': 'file', 'path': path, 'size': 65,
              'encoding': 'base64', 'content': base64.b64encode((digest+'\n').encode()).decode()},
           f'/commits?sha={head}&path={path}&per_page=1': [{'sha': introduction}],
           f'/commits/{introduction}/pulls': [{'merge_commit_sha': introduction,
               'base': {'ref': 'main', 'repo': {'id': approval.PUBLIC_ID}},
               'merged_at': '1970-01-01T00:01:00Z'}]}
    producer = {'repository': 'ElevenID/marty-subscriptions', 'workflow': approval.WORKFLOW,
                'source_sha': a['source'], 'ref': a['ref'], 'run_id': '123', 'run_attempt': '2'}
    definition = {'buildType': 'https://actions.github.io/buildtypes/workflow/v1',
        'externalParameters': {'elevenidReleaseAuthorization': raw.decode(),
            'workflow': {'ref': a['ref'], 'repository': 'https://github.com/ElevenID/marty-subscriptions',
                         'path': approval.WORKFLOW}},
        'internalParameters': {'github': {'runner_environment': 'self-hosted',
                                          'repository_id': str(approval.PRIVATE_ID)}}}
    result = {'verificationResult': {'statement': {'predicateType': 'https://slsa.dev/provenance/v1',
        'predicate': {'buildDefinition': definition}}, 'verifiedTimestamps': [
            {'type': 'TimestampAuthority', 'uri': 'timestamp.githubapp.com',
             'timestamp': '1970-01-01T00:02:00Z'}]}}
    job = {'id': 456, 'name': 'standalone-website', 'run_id': 123, 'head_sha': a['source'],
           'runner_id': 789, 'runner_name': a['runner_name'],
           'labels': ['self-hosted', 'linux', 'x64', a['runner_name']],
           'status': 'completed', 'conclusion': 'success',
           'started_at': '1970-01-01T00:01:30Z', 'completed_at': '1970-01-01T00:03:00Z'}
    return a, producer, result, api, job


def test_signed_approval_uses_verified_time_instead_of_current_expiration(candidate):
    a, producer, result, api, _ = candidate
    assert approval.verified_authorization(result, producer, 'website', read=api.__getitem__) == a
    # This approval expired decades ago. Its authenticated historical signing
    # time remains within its authorization, so normal runtime replay is valid.
    result['verificationResult']['verifiedTimestamps'][0]['timestamp'] = '1970-01-01T02:00:00Z'
    with pytest.raises(ValueError, match='expired'):
        approval.verified_authorization(result, producer, 'website', read=api.__getitem__)


def test_application_approval_requires_exact_verifiers_separate_from_the_build_source():
    inputs = {'mode': 'combined', 'ui_source_sha': 'a'*40,
              'stack_release_tag': 'v1.1.292', 'verification_source_sha': 'b'*40}
    assert approval.inputs_from(inputs) == inputs
    for value in ('main', '', 'c'*39, 'c'*41):
        with pytest.raises(ValueError):
            approval.inputs_from({**inputs, 'verification_source_sha': value})
    missing = inputs.copy(); missing.pop('verification_source_sha')
    with pytest.raises(ValueError): approval.inputs_from(missing)


def verified_local(candidate, monkeypatch):
    a, producer, result, api, _ = candidate
    output = verified(producer)
    output[0]['verificationResult'].update(result['verificationResult'])
    output[0]['verificationResult']['signature']['certificate']['runnerEnvironment'] = 'self-hosted'
    original = approval.verified_authorization
    monkeypatch.setattr(approval, 'verified_authorization',
                        lambda result, producer, role: original(result, producer, role, read=api.__getitem__))
    return a, producer, output


def test_self_hosted_certificate_needs_signed_approval_and_original_identity(candidate, monkeypatch):
    a, producer, output = verified_local(candidate, monkeypatch)
    assert proof.verified_certificate(json.dumps(output), producer, role='website') == a
    with pytest.raises(ValueError):
        proof.verified_certificate(json.dumps(output), producer)
    output[0]['verificationResult']['signature']['certificate']['sourceRepositoryDigest'] = 'a'*40
    with pytest.raises(ValueError, match='certificate differs'):
        proof.verified_certificate(json.dumps(output), producer, role='website')


def test_approved_private_subject_still_requires_cosign_and_unchanged_evidence(candidate, monkeypatch, tmp_path):
    a, producer, output = verified_local(candidate, monkeypatch)
    tmp_path.chmod(0o700)
    for name in ('gh', 'cosign', 'website-release.json', 'website-release.json.provenance.jsonl',
                 'website-release.json.sigstore.json'):
        (tmp_path/name).write_bytes(b'inert verifier fixture')
    calls = []
    def run(args):
        calls.append(args)
        if args[1] == 'attestation': return json.dumps(output)
        return 'original public Cosign proof verified'
    kwargs = dict(producer=producer, gh=tmp_path/'gh', cosign=tmp_path/'cosign', runner=run, role='website')
    assert proof.verify_subject(tmp_path/'website-release.json', **kwargs) == a
    assert [x[1] for x in calls] == ['attestation', 'verify-blob']
    assert '--deny-self-hosted-runners' not in calls[0]
    assert '--no-public-good' in calls[0] and '--no-public-good' not in calls[1]
    def bad_cosign(args):
        if args[1] == 'attestation': return json.dumps(output)
        raise ValueError('Cosign rejected original proof')
    with pytest.raises(ValueError, match='Cosign rejected'):
        proof.verify_subject(tmp_path/'website-release.json', **{**kwargs, 'runner': bad_cosign})
    output[0]['verificationResult']['statement']['predicate']['buildDefinition']['externalParameters'].pop(
        'elevenidReleaseAuthorization')
    calls.clear()
    with pytest.raises(ValueError):
        proof.verify_subject(tmp_path/'website-release.json', **kwargs)
    assert len(calls) == 1


def test_generic_private_and_all_public_admission_keep_hosted_only_cli_policy(candidate):
    producer = candidate[1]
    assert '--deny-self-hosted-runners' in proof.attestation_arguments(producer)
    public = {**producer, 'repository': 'ElevenID/marty-ui', 'workflow': '.github/workflows/production-web-release.yml'}
    assert '--deny-self-hosted-runners' in proof.attestation_arguments(public, role='website')


def test_public_transport_uses_fixed_system_trust_instead_of_environment(monkeypatch):
    calls = []
    class Context:
        def load_verify_locations(self, **kwargs): calls.append(kwargs)
        def cert_store_stats(self): return {'x509_ca': 1}
    monkeypatch.setattr(approval.sys, 'platform', 'linux')
    monkeypatch.setattr(approval.ssl, 'SSLContext', lambda protocol: Context())
    monkeypatch.setenv('SSL_CERT_FILE', '/untrusted/operator.pem')
    monkeypatch.setenv('SSL_CERT_DIR', '/untrusted/certs')
    assert isinstance(approval.public_context(), Context)
    assert calls == [{'cafile': '/etc/ssl/certs/ca-certificates.crt'}]


def test_windows_public_trust_comes_only_from_native_server_auth_stores(monkeypatch):
    calls, stores = [], []
    class Context:
        def load_verify_locations(self, **kwargs): calls.append(kwargs)
        def cert_store_stats(self): return {'x509_ca': 1}
    def certificates(store):
        stores.append(store)
        return [(b'accepted', 'x509_asn', True), (b'refused', 'x509_asn', {'another-purpose'})]
    monkeypatch.setattr(approval.sys, 'platform', 'win32')
    monkeypatch.setattr(approval.ssl, 'SSLContext', lambda protocol: Context())
    monkeypatch.setattr(approval.ssl, 'enum_certificates', certificates, raising=False)
    monkeypatch.setattr(approval.ssl, 'DER_cert_to_PEM_cert', lambda raw: raw.decode())
    approval.public_context()
    assert stores == ['CA', 'ROOT'] and calls == [{'cadata': 'accepted'}, {'cadata': 'accepted'}]


@pytest.mark.parametrize('field,value', [('source_sha', 'a'*40), ('run_id', '124'),
    ('run_attempt', '3'), ('workflow', '.github/workflows/other.yml'),
    ('ref', 'refs/heads/other'), ('repository', 'ElevenID/marty-ui')])
def test_signed_approval_cannot_substitute_original_producer(candidate, field, value):
    _, producer, result, api, _ = candidate
    producer[field] = value
    with pytest.raises(ValueError):
        approval.verified_authorization(result, producer, 'website', read=api.__getitem__)


@pytest.mark.parametrize('role', [None, 'application', 'composition', 'qualification'])
def test_an_approval_does_not_authorize_another_role(candidate, role):
    _, producer, result, api, _ = candidate
    with pytest.raises(ValueError):
        approval.verified_authorization(result, producer, role, read=api.__getitem__)


@pytest.mark.parametrize('fault', ['no-timestamp', 'two-timestamps', 'unverified-clock', 'wrong-tsa',
    'no-approval', 'noncanonical', 'wrong-predicate', 'wrong-build', 'wrong-runner', 'wrong-workflow'])
def test_incomplete_or_unbound_verified_claims_fail_closed(candidate, fault):
    _, producer, result, api, _ = candidate
    verified = result['verificationResult']
    definition = verified['statement']['predicate']['buildDefinition']
    if fault == 'no-timestamp': verified['verifiedTimestamps'] = []
    elif fault == 'two-timestamps': verified['verifiedTimestamps'] *= 2
    elif fault == 'unverified-clock': verified['verifiedTimestamps'][0]['type'] = 'untrusted'
    elif fault == 'wrong-tsa': verified['verifiedTimestamps'][0]['uri'] = 'elsewhere.invalid'
    elif fault == 'no-approval': definition['externalParameters'].pop('elevenidReleaseAuthorization')
    elif fault == 'noncanonical': definition['externalParameters']['elevenidReleaseAuthorization'] += ' '
    elif fault == 'wrong-predicate': verified['statement']['predicateType'] = 'other'
    elif fault == 'wrong-build': definition['buildType'] = 'other'
    elif fault == 'wrong-runner': definition['internalParameters']['github']['runner_environment'] = 'github-hosted'
    else: definition['externalParameters']['workflow']['path'] = 'other.yml'
    with pytest.raises(ValueError):
        approval.verified_authorization(result, producer, 'website', read=api.__getitem__)


@pytest.mark.parametrize('fault', ['unprotected', 'private-approval', 'wrong-digest', 'unmerged', 'late-approval'])
def test_public_approval_must_be_protected_and_precede_signed_time(candidate, fault):
    _, producer, result, api, _ = candidate
    pulls = next(v for k, v in api.items() if k.endswith('/pulls'))
    if fault == 'unprotected': api['/branches/main']['protected'] = False
    elif fault == 'private-approval': api['']['private'] = True
    elif fault == 'wrong-digest': next(v for k, v in api.items() if k.startswith('/contents/'))['content'] = base64.b64encode(b'0'*64+b'\n').decode()
    elif fault == 'unmerged': pulls[0]['merged_at'] = None
    else: pulls[0]['merged_at'] = '1970-01-01T00:02:01Z'
    with pytest.raises(ValueError):
        approval.verified_authorization(result, producer, 'website', read=api.__getitem__)


def test_running_producer_and_completed_intake_require_different_original_phases(candidate):
    a, _, _, api, job = candidate
    census = {'total_count': 1, 'jobs': [job]}
    assert approval.check_assignment(a, census, completed=True, read=api.__getitem__) == job
    with pytest.raises(ValueError):
        approval.check_assignment(a, census, completed=False, read=api.__getitem__)
    job.update(status='in_progress', conclusion=None)
    assert approval.check_assignment(a, census, completed=False, read=api.__getitem__) == job
    with pytest.raises(ValueError):
        approval.check_assignment(a, census, completed=True, read=api.__getitem__)


@pytest.mark.parametrize('fault', ['wrong-job', 'wrong-runner', 'wrong-source', 'wrong-labels',
    'extra-job', 'partial-census', 'duplicate-job', 'started-before-approval', 'completed-after-expiry'])
def test_assignment_requires_the_original_complete_one_job_inventory(candidate, fault):
    a, _, _, api, job = candidate
    census = {'total_count': 1, 'jobs': [job]}
    if fault == 'wrong-job': job['id'] += 1
    elif fault == 'wrong-runner': job['runner_id'] += 1
    elif fault == 'wrong-source': job['head_sha'] = 'a'*40
    elif fault == 'wrong-labels': job['labels'].append('other')
    elif fault == 'extra-job': census['jobs'].append({'status': 'completed', 'conclusion': 'success'})
    elif fault == 'partial-census': census['total_count'] = 2
    elif fault == 'duplicate-job': census['jobs'].append(copy.deepcopy(job))
    elif fault == 'started-before-approval': job['started_at'] = '1970-01-01T00:00:59Z'
    else: job['completed_at'] = '1970-01-01T02:00:00Z'
    if fault in {'extra-job', 'duplicate-job'}: census['total_count'] = len(census['jobs'])
    with pytest.raises(ValueError):
        approval.check_assignment(a, census, completed=True, read=api.__getitem__)
