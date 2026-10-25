"""Controller orchestration with mocked crypto/SSH, never guest execution proof."""
import os
from pathlib import Path
import sys

import pytest

pytest.importorskip('fcntl', reason='Linux controller locking')

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import installer_candidate_dispatch as d
import installer_release as r

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='Linux controller filesystem contract')


@pytest.fixture
def staged(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    for name in ('assets', 'grants', 'tools', 'ledger', 'context'):
        (tmp_path / name).mkdir(mode=0o700)
    def put(path, raw, mode=0o600):
        path.write_bytes(raw)
        path.chmod(mode)
    assets = tmp_path / 'assets'
    for name in r.ARTIFACTS:
        put(assets / name, b'synthetic ' + name.encode())
    put(assets / 'prepared-selfhost-images.json', r.encode(dict(
        schema='marty.selfhost-image-lock/v1', release='marty-ui@1.2.3',
        services={'gateway': 'ghcr.io/elevenid/services@sha256:' + 'a' * 64},
        openbao_didcomm_image='ghcr.io/elevenid/plugin@sha256:' + 'b' * 64)))
    inventory = r.encode(r.inventory(assets, expected_services={'gateway'}, source_sha='a' * 40,
                                    release_tag='v1.2.3', build_run_id=42, build_run_attempt=2))
    put(assets / 'installer-inventory.json', inventory)
    run = dict(repository=dict(full_name=r.REPOSITORY), path=r.acceptance.WORKFLOW,
               head_sha='c' * 40, head_branch='main', event='workflow_dispatch', status='in_progress',
               conclusion=None, id=99, run_attempt=3)
    authorization = r.candidate_authorization(inventory, source_sha='a' * 40, release_tag='v1.2.3',
        build_run_id=42, build_run_attempt=2, acceptance_run=run, phase='staged', now=100000)
    auth = r.encode(authorization)
    context = {key: authorization[key] for key in r.CONTEXT_FIELDS}
    target = dict(guest_id='11111111-1111-4111-8111-111111111111', disk_id='d' * 64,
                  engine_id='engine-12345', installation_id='22222222-2222-4222-8222-222222222222')
    receipt = r.encode(r.controller_consumption(auth, inventory, expected=context, **target,
                                              consumed_at=100001, now=100001))
    grants = tmp_path / 'grants'
    put(grants / 'candidate-authorization.json', auth)
    put(grants / 'controller-consumption.json', receipt)
    for directory, names in [(assets, d.SUBJECTS),
                             (grants, ['candidate-authorization.json', 'controller-consumption.json'])]:
        for name in names:
            for suffix in d.SUFFIXES[1:]:
                put(directory / (name + suffix), b'synthetic proof')
    tools = {}
    for name in ('gh', 'cosign'):
        raw = ('synthetic-' + name).encode()
        path = tmp_path / 'tools' / name
        put(path, raw, 0o700)
        tools[name] = (r.digest(raw), len(raw))
    monkeypatch.setattr(d, 'TOOLS', tools)
    proofs = []
    monkeypatch.setattr(d.provenance, 'verify_subject', lambda *a, **k: proofs.append((a, k)))
    monkeypatch.setattr(d, 'executable', lambda path: None)
    ledger = tmp_path / 'ledger' / (context['nonce'] + '.json')
    put(ledger, receipt)
    for name, raw in [('context.json', r.encode(context)), ('target.json', r.encode(target)),
                      ('key', b'private test key'), ('known_hosts', b'host test-key')]:
        put(tmp_path / 'context' / name, raw)
    calls = []
    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return b''
    options = dict(assets=assets, grants=grants, context_file=tmp_path / 'context/context.json',
        target_file=tmp_path / 'context/target.json', ledger=ledger,
        gh=tmp_path / 'tools/gh', cosign=tmp_path / 'tools/cosign',
        ssh=Path('/usr/bin/ssh'), scp=Path('/usr/bin/scp'), key=tmp_path / 'context/key',
        known_hosts=tmp_path / 'context/known_hosts', host='127.0.0.1', port=2222,
        user='installer', home='/home/installer', clock=lambda: 100002, run=runner)
    return options, calls, proofs


def test_full_dispatch_verifies_seven_and_transfers_only_exact_inputs(staged):
    options, calls, proofs = staged
    result = d.dispatch(**options)
    assert len(proofs) == 7
    assert [k['workflow'] for _, k in proofs[:2]] == [r.acceptance.WORKFLOW] * 2
    assert all(k['run_id'] == 42 and k['run_attempt'] == 2 for _, k in proofs[2:])
    assert len(calls) == 6  # setup, exact15, grant6, two tools, native invocation
    assert len(calls[1][0][calls[1][0].index(str(options['assets'] / d.SUBJECTS[0])):-1]) == 15
    for argv, kwargs in calls:
        assert kwargs['env'].keys() == {'HOME', 'PATH', 'LANG', 'LC_ALL'}
        assert 'StrictHostKeyChecking=yes' in argv and 'IdentityAgent=none' in argv
        assert 'ProxyCommand=none' in argv and 'ControlPath=none' in argv
    assert str(options['key']) not in calls[1][0][calls[1][0].index(str(options['assets'] / d.SUBJECTS[0])):]
    invoke = calls[-1][0][-1]
    assert 'install-candidate' in invoke and '--docker-engine-id engine-12345' in invoke
    assert 'exec env -i HOME=/home/installer' in invoke
    context = r.decode(options['context_file'].read_bytes())
    assert context['operator_sha256'] in invoke
    assert invoke.count('/usr/bin/sha256sum --check --status --strict') == 3
    assert invoke.index('/usr/bin/sha256sum') < invoke.index('exec env -i')
    assert result['installation_ready'] is False and result['acceptance_report'] is False
    assert Path(str(options['ledger']) + '.dispatch.json').is_file()
    assert Path(str(options['ledger']) + '.invoke.json').is_file()
    with pytest.raises(FileExistsError):
        d.dispatch(**options)
    assert len(calls) == 6


@pytest.mark.parametrize('change', ['ledger', 'guest', 'engine', 'asset', 'proof', 'extra', 'tool'])
def test_refuses_before_any_ssh(staged, change):
    options, calls, _ = staged
    if change == 'ledger':
        options['ledger'].write_bytes(b'{}')
    elif change in ('guest', 'engine'):
        target = r.decode(options['target_file'].read_bytes())
        target['guest_id' if change == 'guest' else 'engine_id'] = (
            '33333333-3333-4333-8333-333333333333' if change == 'guest' else 'wrong-engine')
        options['target_file'].write_bytes(r.encode(target))
    elif change == 'asset':
        (options['assets'] / 'install.sh').write_bytes(b'tampered')
    elif change == 'proof':
        (options['grants'] / 'candidate-authorization.json.sigstore.json').unlink()
    elif change == 'extra':
        (options['assets'] / 'extra').write_bytes(b'unknown')
    else:
        options['gh'].write_bytes(b'tampered')
    with pytest.raises((ValueError, OSError)):
        d.dispatch(**options)
    assert not calls and not Path(str(options['ledger']) + '.dispatch.json').exists()


def test_uncertain_native_failure_retains_intent_and_forbids_retry(staged):
    options, calls, _ = staged
    original = options['run']
    def failed(argv, **kwargs):
        result = original(argv, **kwargs)
        if 'install-candidate' in argv[-1]:
            raise ValueError('synthetic SSH timeout')
        return result
    options['run'] = failed
    with pytest.raises(ValueError):
        d.dispatch(**options)
    assert Path(str(options['ledger']) + '.invoke.json').is_file()
    assert not Path(str(options['ledger']) + '.dispatch-result.json').exists()
    with pytest.raises(FileExistsError):
        d.dispatch(**options)
    assert len(calls) == 6


def test_expiry_after_transfer_prevents_native_invocation(staged):
    options, calls, _ = staged
    options['clock'] = lambda: 104000 if len(calls) >= 5 else 100002
    with pytest.raises(ValueError):
        d.dispatch(**options)
    assert len(calls) == 5
    assert not Path(str(options['ledger']) + '.invoke.json').exists()


def test_expiry_during_verification_prevents_first_guest_mutation(staged):
    options, calls, proofs = staged
    options['clock'] = lambda: 104000 if len(proofs) == 7 else 100002
    with pytest.raises(ValueError):
        d.dispatch(**options)
    assert not calls and not Path(str(options['ledger']) + '.dispatch.json').exists()


def test_replaced_controller_registry_blocks_next_guest_operation(staged):
    options, calls, _ = staged
    original = options['run']
    def replace(argv, **kwargs):
        result = original(argv, **kwargs)
        if len(calls) == 1:
            parent = options['ledger'].parent
            parent.rename(parent.with_name('retained-ledger'))
            parent.mkdir(mode=0o700)
        return result
    options['run'] = replace
    with pytest.raises(ValueError):
        d.dispatch(**options)
    assert len(calls) == 1


def test_interrupted_unlock_retries_and_closes_owned_descriptor(staged, monkeypatch):
    options, _, _ = staged
    original = d.fcntl.flock
    unlocks = []
    def interrupted(fd, operation):
        if operation == d.fcntl.LOCK_UN:
            unlocks.append(fd)
            if len(unlocks) == 1:
                raise InterruptedError('synthetic signal')
        return original(fd, operation)
    monkeypatch.setattr(d.fcntl, 'flock', interrupted)
    d.dispatch(**options)
    assert len(unlocks) == 2 and unlocks[0] == unlocks[1]
    with pytest.raises(OSError):
        os.fstat(unlocks[0])
    # A genuinely separate open-file description can acquire immediately.
    fd = os.open(options['ledger'].parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        original(fd, d.fcntl.LOCK_EX | d.fcntl.LOCK_NB)
    finally:
        os.close(fd)


@pytest.mark.parametrize('field,value', [('host', '-oProxyCommand=evil'), ('user', 'root'),
    ('user', 'installer;evil'), ('home', '/tmp/installer'), ('port', 0)])
def test_unsafe_ssh_target_refused_without_remote_operation(staged, field, value):
    options, calls, _ = staged
    options[field] = value
    with pytest.raises(ValueError):
        d.dispatch(**options)
    assert not calls
