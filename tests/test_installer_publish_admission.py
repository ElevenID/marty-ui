"""Mock GitHub publication, not genuine immutable-release qualification."""
import copy
import io
import os
from pathlib import Path
import sys
import pytest
import yaml
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_installer_promote import evidence

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import installer_publish_admission as pub
import installer_promote as promotion
import installer_release as r

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='Linux exclusive publication records')


class GitHub:
    def __init__(self):
        self.release = None
        self.files = {}
        self.calls = []
        self.policy = True
        self.immutable = True
        self.fail_upload = False
        self.wrong_download = False
        self.tag = None

    def request(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, kwargs))
        if path.endswith('/immutable-releases'):
            assert method == 'GET' and kwargs == {'policy': True}
            return {'enabled': self.policy}
        if '/git/ref/tags/' in path:
            return None if self.tag is None else {'object': {'type': 'commit', 'sha': self.tag, 'url': 'synthetic'}}
        if method == 'POST' and path.endswith('/releases'):
            assert self.release is None
            self.release = dict(body, id=77, immutable=False)
            return copy.deepcopy(self.release)
        if kwargs.get('upload'):
            assert method == 'POST' and '/releases/77/assets?name=' in path
            if self.fail_upload: raise ValueError('synthetic dropped upload response')
            name = path.split('?name=')[1]
            assert name not in self.files
            self.files[name] = body
            return {'id': len(self.files)}
        if path.endswith('/assets?per_page=100'):
            return [dict(id=index, name=name, state='uploaded', size=len(raw), digest='sha256:' + r.digest(raw))
                    for index, (name, raw) in enumerate(self.files.items(), 1)]
        if kwargs.get('binary'):
            raw = list(self.files.values())[int(path.rsplit('/', 1)[1]) - 1]
            return b'changed' if self.wrong_download else raw
        if method == 'PATCH':
            assert path.endswith('/releases/77') and body == {'draft': False, 'make_latest': 'false'}
            self.release.update(draft=False, immutable=self.immutable)
            self.tag = self.release['target_commitish']
            return copy.deepcopy(self.release)
        assert method == 'GET'
        return copy.deepcopy(self.release)


@pytest.fixture
def candidate(evidence):
    options, _ = evidence
    promotion.promote(**options)
    assets = options['output'].parent
    options['output'].rename(assets / 'installer-admission.json')
    for suffix in ('.sigstore.json', '.provenance.jsonl'):
        (assets / ('installer-admission.json' + suffix)).write_bytes(b'synthetic proof')
    api = r.decode(options['runs'].read_bytes())['promotion']
    api.update(status='completed', conclusion='success')
    options['runs'].write_bytes(r.encode(api))
    recovery = assets.parent / 'publication-evidence'
    recovery.mkdir(mode=0o700)
    return dict(assets=assets, run_record=options['runs'], gh=options['gh'], cosign=options['cosign'],
        evidence=recovery, source_sha=options['source_sha'], release_tag=options['release_tag'],
        promotion_source_sha=options['promotion_source_sha'], promotion_run_id=options['promotion_run_id'],
        promotion_run_attempt=options['promotion_run_attempt'], client=GitHub())


def test_publish_exact_triplet_then_existing_is_read_only(candidate):
    result = pub.publish(**candidate)
    client = candidate['client']
    assert result == dict(release_id=77, existing=False, immutable=True, channel_updated=False)
    assert client.release['tag_name'] == 'installer-admission-v1.2.3'
    assert set(client.files) == set(pub.NAMES)
    assert (candidate['evidence'] / 'admission-publication-pending.json').is_file()
    assert (candidate['evidence'] / 'admission-publication-publish-intent.json').is_file()
    before = len(client.calls)
    assert pub.publish(**candidate)['existing'] is True
    assert all(method == 'GET' for method, _, _ in client.calls[before:])
    existing = r.decode((candidate['evidence'] / 'admission-publication-existing.json').read_bytes())
    assert existing['release_id'] == 77 and existing['tag'] == 'installer-admission-v1.2.3'
    assert existing['commit'] == candidate['promotion_source_sha']
    assert existing['assets'] == {name: r.digest(raw) for name, raw in client.files.items()}
    assert not any(method == 'DELETE' or 'installer-channel' in path for method, path, _ in client.calls)


@pytest.mark.parametrize('fault', ['policy-disabled', 'wrong-source', 'wrong-attempt', 'incomplete-run', 'wrong-proof', 'extra-file'])
def test_refuses_before_any_write(candidate, monkeypatch, fault):
    if fault == 'policy-disabled': candidate['client'].policy = False
    elif fault == 'wrong-source': candidate['source_sha'] = 'f' * 40
    elif fault == 'wrong-attempt': candidate['promotion_run_attempt'] += 1
    elif fault == 'incomplete-run':
        run = r.decode(candidate['run_record'].read_bytes()); run.update(status='in_progress', conclusion=None)
        candidate['run_record'].write_bytes(r.encode(run))
    elif fault == 'wrong-proof':
        def failed(*a, **kw): raise ValueError('synthetic crypto failure')
        monkeypatch.setattr(pub.provenance, 'verify_subject', failed)
    else: (candidate['assets'] / 'unknown').write_bytes(b'extra')
    with pytest.raises(ValueError): pub.publish(**candidate)
    assert all(method == 'GET' for method, _, _ in candidate['client'].calls)


def test_uncertain_upload_retains_draft_and_refuses_adoption(candidate):
    candidate['client'].fail_upload = True
    with pytest.raises(ValueError): pub.publish(**candidate)
    assert candidate['client'].release['draft'] is True
    assert (candidate['evidence'] / 'admission-publication-created.json').is_file()
    before = len(candidate['client'].calls)
    with pytest.raises(ValueError): pub.publish(**candidate)
    assert all(method == 'GET' for method, _, _ in candidate['client'].calls[before:])


def test_readback_failure_prevents_publication(candidate):
    candidate['client'].wrong_download = True
    with pytest.raises(ValueError): pub.publish(**candidate)
    assert candidate['client'].release['draft'] is True
    assert not any(method == 'PATCH' for method, _, _ in candidate['client'].calls)


def test_missing_immutable_postcondition_is_not_success(candidate):
    candidate['client'].immutable = False
    with pytest.raises(ValueError): pub.publish(**candidate)
    assert not (candidate['evidence'] / 'admission-publication-result.json').exists()
    assert (candidate['evidence'] / 'admission-publication-publish-intent.json').is_file()


def test_policy_credential_cannot_be_used_for_mutation():
    client = pub.Client('synthetic-write', 'synthetic-read-only')
    with pytest.raises(ValueError):
        client.request('POST', pub.REPO + '/releases', {}, policy=True)


def test_network_json_lists_duplicates_and_policy_credential_scope():
    client = pub.Client('synthetic-write', 'synthetic-policy-read')
    requests = []
    class Opener:
        raw = b'[]'
        def open(self, request, timeout):
            requests.append(request)
            return io.BytesIO(self.raw)
    client.opener = Opener()
    assert client.request('GET', pub.REPO + '/releases/77/assets?per_page=100') == []
    assert requests[-1].get_header('Authorization') == 'Bearer synthetic-write'
    client.opener.raw = b'{"enabled":true}'
    assert client.request('GET', pub.REPO + '/immutable-releases', policy=True)['enabled'] is True
    assert requests[-1].get_header('Authorization') == 'Bearer synthetic-policy-read'
    client.opener.raw = b'{"enabled":true,"enabled":false}'
    with pytest.raises(ValueError):
        client.request('GET', pub.REPO + '/immutable-releases', policy=True)


def test_workflow_pins_main_and_retains_evidence_without_deletion():
    path = Path(__file__).resolve().parents[1] / '.github/workflows/installer-publish-admission.yml'
    job = yaml.safe_load(path.read_text())['jobs']['publish-admission']
    assert "github.ref == 'refs/heads/main'" in job['if'] and job['environment'] == 'stack-release'
    assert job['permissions']['contents'] == 'write'
    steps = job['steps']
    secret_steps = [s for s in steps if 'INSTALLER_REPOSITORY_POLICY_TOKEN' in s.get('env', {})]
    assert len(secret_steps) == 1 and 'installer_publish_admission.py' in secret_steps[0]['run']
    assert any(s.get('if') == 'always()' and 'upload-artifact@' in s.get('uses', '') for s in steps)
    assert not any('release delete' in s.get('run', '') or s.get('continue-on-error') for s in steps)
