"""Synthetic promotion contracts; mocked verifiers are not installed acceptance."""
import os
from pathlib import Path
import sys
import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import installer_promote as p
import installer_release as r


@pytest.fixture
def evidence(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    for name in ('assets', 'staged', 'published', 'tools', 'context', 'output'):
        (tmp_path / name).mkdir(mode=0o700)
    assets = tmp_path / 'assets'
    for name in r.ARTIFACTS:
        (assets / name).write_bytes(b'synthetic ' + name.encode())
    (assets / 'prepared-selfhost-images.json').write_bytes(r.encode(dict(
        schema='marty.selfhost-image-lock/v1', release='marty-ui@1.2.3',
        services={'gateway': 'ghcr.io/elevenid/service@sha256:' + 'a' * 64},
        openbao_didcomm_image='ghcr.io/elevenid/plugin@sha256:' + 'b' * 64)))
    inv = r.encode(r.inventory(assets, expected_services={'gateway'}, source_sha='a' * 40,
                              release_tag='v1.2.3', build_run_id=42, build_run_attempt=2))
    (assets / 'installer-inventory.json').write_bytes(inv)
    def run(number, workflow, source='c' * 40, active=False, attempt=1):
        return dict(repository=dict(full_name=r.REPOSITORY), id=number, run_attempt=attempt,
            path=workflow, head_sha=source, head_branch='main', event='workflow_dispatch',
            status='in_progress' if active else 'completed', conclusion=None if active else 'success')
    api = dict(build=run(42, '.github/workflows/cd.yml', 'a' * 40, attempt=2),
        staged=run(101, r.acceptance.WORKFLOW), published=run(102, r.acceptance.WORKFLOW),
        promotion=run(200, r.PROMOTION_WORKFLOW, 'd' * 40, active=True))
    for phase in ('staged', 'published'):
        report = dict(schema=r.acceptance.SCHEMA, repository=r.REPOSITORY, source_sha='a' * 40,
            harness_source_sha='c' * 40, source_ref='refs/heads/main', release_tag='v1.2.3',
            phase=phase, platform='linux/amd64', inventory_sha256='sha256:' + r.digest(inv),
            workflow=r.acceptance.WORKFLOW, run_id=api[phase]['id'], run_attempt=1,
            cases=dict.fromkeys(r.acceptance.CASES, 'passed'),
            host=dict(docker_version='29.1.3', compose_version='2.39.0', memory_bytes=32 * 1024**3,
                disk_free_bytes=20 * 1024**3, image_cache_empty=True, source_available=False,
                development_tools_available=False, credentials_available=False, tls_errors_ignored=False),
            cleanup=dict(owned_containers_remaining=0, owned_networks_remaining=0,
                owned_volumes_remaining=0, recovery_retention_verified=True))
        (tmp_path / phase / 'installer-acceptance.json').write_bytes(r.encode(report))
    for directory, names in [(assets, p.SUBJECTS), (tmp_path / 'staged', ['installer-acceptance.json']),
                              (tmp_path / 'published', ['installer-acceptance.json'])]:
        for name in names:
            for suffix in p.SUFFIXES[1:]:
                (directory / (name + suffix)).write_bytes(b'synthetic proof')
    tools = {}
    for name in ('gh', 'cosign'):
        raw = ('synthetic-' + name).encode()
        (tmp_path / 'tools' / name).write_bytes(raw)
        tools[name] = (r.digest(raw), len(raw))
    monkeypatch.setattr(p, 'TOOLS', tools)
    calls = []
    monkeypatch.setattr(p.provenance, 'verify_subject', lambda *a, **kw: calls.append((a, kw)))
    runs = tmp_path / 'context/runs.json'
    runs.write_bytes(r.encode(api))
    return dict(assets=assets, staged=tmp_path / 'staged', published=tmp_path / 'published', runs=runs,
        gh=tmp_path / 'tools/gh', cosign=tmp_path / 'tools/cosign', output=tmp_path / 'output/admission.json',
        source_sha='a' * 40, release_tag='v1.2.3', build_run_id=42, build_run_attempt=2,
        staged_run_id=101, staged_run_attempt=1, published_run_id=102, published_run_attempt=1,
        promotion_source_sha='d' * 40, promotion_run_id=200, promotion_run_attempt=1), calls


@pytest.mark.skipif(os.name != 'posix', reason='exclusive Linux output contract')
def test_only_complete_two_phase_evidence_produces_exclusive_admission(evidence):
    options, calls = evidence
    result = p.promote(**options)
    assert r.decode(options['output'].read_bytes()) == result
    assert result['status'] == 'accepted' and result['promotion_run_id'] == 200
    assert len(calls) == 9  # seven signature/proof pairs plus shared admission's two proof checks
    assert all(kw['run_id'] == 42 and kw['run_attempt'] == 2 for _, kw in calls[:5])
    assert all(kw['signature_bundle'].name.endswith('.sigstore.json') for _, kw in calls[:7])
    with pytest.raises(FileExistsError):
        p.promote(**options)


@pytest.mark.parametrize('fault', ['grant-only', 'missing-phase', 'failed-case', '4gib',
    'dirty-host', 'wrong-inventory', 'wrong-run', 'wrong-attempt', 'unsuccessful-run',
    'wrong-source', 'wrong-proof', 'tampered-asset'])
def test_rejects_unqualified_evidence_without_admission(evidence, monkeypatch, fault):
    options, _ = evidence
    path = options['published'] / 'installer-acceptance.json'
    report = r.decode(path.read_bytes())
    if fault == 'grant-only':
        path.unlink()
        (options['published'] / 'candidate-authorization.json').write_bytes(b'{}')
    elif fault == 'missing-phase':
        (options['staged'] / 'installer-acceptance.json.provenance.jsonl').unlink()
    elif fault in ('failed-case', '4gib', 'dirty-host', 'wrong-inventory', 'wrong-run'):
        if fault == 'failed-case': report['cases']['browser-tls-login'] = 'failed'
        if fault == '4gib': report['host']['memory_bytes'] = 4 * 1024**3
        if fault == 'dirty-host': report['host']['credentials_available'] = True
        if fault == 'wrong-inventory': report['inventory_sha256'] = 'sha256:' + 'f' * 64
        if fault == 'wrong-run': report['run_id'] = 103
        path.write_bytes(r.encode(report))
    elif fault in ('wrong-attempt', 'unsuccessful-run', 'wrong-source'):
        api = r.decode(options['runs'].read_bytes())
        if fault == 'wrong-attempt': api['published']['run_attempt'] = 2
        if fault == 'unsuccessful-run': api['published']['conclusion'] = 'failure'
        if fault == 'wrong-source': api['build']['head_sha'] = 'e' * 40
        options['runs'].write_bytes(r.encode(api))
    elif fault == 'wrong-proof':
        def refuse(*a, **kw): raise ValueError('synthetic cryptographic refusal')
        monkeypatch.setattr(p.provenance, 'verify_subject', refuse)
    else:
        (options['assets'] / 'install.sh').write_bytes(b'tampered')
    with pytest.raises((ValueError, OSError)):
        p.promote(**options)
    assert not options['output'].exists()


def test_workflow_is_main_only_archive_gate_with_no_channel_or_release_write():
    path = Path(__file__).resolve().parents[1] / '.github/workflows/installer-promote.yml'
    workflow = yaml.safe_load(path.read_text())
    job = workflow['jobs']['admit-installer']
    assert "github.ref == 'refs/heads/main'" in job['if']
    assert job['environment'] == 'stack-release' and job['permissions']['contents'] == 'read'
    steps = job['steps']
    assert not any(step.get('continue-on-error') for step in steps)
    commands = '\n'.join(step.get('run', '') for step in steps)
    assert 'python scripts/installer_promote.py' in commands
    assert '--staged-run-id' in commands and '--published-run-id' in commands
    assert 'release create' not in commands and 'release upload' not in commands
    assert 'installer-channel-' not in commands
    assert sum('attest-build-provenance@' in step.get('uses', '') for step in steps) == 1
