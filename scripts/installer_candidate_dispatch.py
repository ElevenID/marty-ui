"""Dispatch one authenticated candidate to a controller-observed Linux guest.

Physical VM/disk identity and pre-install cleanliness remain controller assertions.
This transfers no SSH key, source checkout, controller ledger or ambient credential.
Any failed/uncertain attempt retains its durable intent and must not be retried.
Native installation currently returns incomplete until journey/trust work finishes;
that is a retained failure here, never an acceptance or readiness result.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import re
import shlex
import stat
import tempfile
import time

import installer_release as release
import verify_installer_provenance as provenance
from installer_candidate_authorize import read_record, write_exclusive
from installer_candidate_controller import _directory
from installer_host_probe import command

TOOLS = {
    'cosign': ('424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa', 145688404),
    'gh': ('cbfdc94f3a5c0713c0d6df3e0a1d88a59a76b0c52332aad7d21d112f9da2cc0e', 41070752),
}
SUBJECTS = ['installer-inventory.json', *sorted(release.ARTIFACTS)]
SUFFIXES = ('', '.sigstore.json', '.provenance.jsonl')
TARGET_FIELDS = {'guest_id', 'disk_id', 'engine_id', 'installation_id'}


def private_file(path: Path, maximum: int, executable=False):
    provenance.local_file(path, private=True, maximum=maximum)
    parent = _directory(path.parent)
    os.close(parent)
    info = path.lstat()
    release.require(info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == (0o700 if executable else 0o600),
                    'private file mode or links differ')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        total = 0
        for chunk in iter(lambda: stream.read(65536), b''):
            total += len(chunk)
            release.require(total <= maximum, 'input exceeds bound')
            digest.update(chunk)
    release.require(total == info.st_size, 'input changed')
    return digest.hexdigest(), total


def executable(path):
    release.require(path.is_absolute() and path.resolve() == path, 'client executable path invalid')
    for entry in (path, *path.parents):
        info = entry.lstat()
        release.require(info.st_uid == 0 and not info.st_mode & 0o022, 'untrusted client executable')
    release.require(path.is_file() and os.access(path, os.X_OK), 'client unavailable')


def ssh_options(key, known_hosts, port):
    return ['-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + str(known_hosts), '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'IdentityAgent=none', '-o', 'IdentitiesOnly=yes', '-o', 'ProxyCommand=none',
            '-o', 'ProxyJump=none', '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
            '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'PermitLocalCommand=no',
            '-o', 'ConnectTimeout=20', '-o', 'ConnectionAttempts=1',
            '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2',
            '-o', 'Port=' + str(port), '-i', str(key)]


def verify(*, assets, grants, context, target, ledger, gh, cosign, now, runner=provenance.command):
    release.exact(context, release.CONTEXT_FIELDS, 'independent candidate context')
    release.exact(target, TARGET_FIELDS, 'controller-observed target')
    release.require(context['phase'] in ('staged', 'published'), 'unsupported candidate phase')
    expected_names = {name + suffix for name in SUBJECTS for suffix in SUFFIXES}
    release.require({p.name for p in assets.iterdir()} == expected_names, 'candidate input closure differs')
    paths = {}
    for name in SUBJECTS:
        for suffix in SUFFIXES:
            maximum = 1048576 if suffix else (65536 if name == 'installer-inventory.json'
                                             else release.ARTIFACT_MAX_BYTES[name])
            path = assets / (name + suffix)
            paths[path] = private_file(path, maximum)
    for name in ('candidate-authorization.json', 'controller-consumption.json'):
        for suffix in SUFFIXES:
            path = grants / (name + suffix)
            paths[path] = private_file(path, 1048576 if suffix else 65536)
    for name, path in [('gh', gh), ('cosign', cosign)]:
        actual = private_file(path, TOOLS[name][1], executable=True)
        release.require(actual == TOOLS[name], 'verifier trust anchor differs')
        paths[path] = actual
    authorization = read_record(grants / 'candidate-authorization.json')
    receipt = read_record(grants / 'controller-consumption.json')
    inventory = read_record(assets / 'installer-inventory.json')
    for name in ('candidate-authorization.json', 'controller-consumption.json'):
        provenance.verify_subject(grants / name, grants / (name + '.provenance.jsonl'),
            gh=gh, cosign=cosign, signature_bundle=grants / (name + '.sigstore.json'),
            workflow=release.acceptance.WORKFLOW, source_sha=context['harness_source_sha'],
            run_id=context['run_id'], run_attempt=context['run_attempt'], runner=runner)
    bound = release.bind_controller_consumption(receipt, authorization, inventory,
        expected=context, expected_engine=target['engine_id'], now=now)
    release.require(all(bound[key] == target[key] for key in TARGET_FIELDS), 'observed guest differs')
    release.require(ledger.name == context['nonce'] + '.json' and read_record(ledger) == receipt,
                    'durable controller consumption differs')
    build = {key: bound[key] for key in ('source_sha', 'release_tag', 'build_run_id', 'build_run_attempt')}
    record = release.verify_inventory_assets(assets, **build)
    tier, _ = release.classify_release_tag(bound['release_tag'])
    workflow = '.github/workflows/nightly-release.yml' if tier == 'nightly' else '.github/workflows/cd.yml'
    for name in SUBJECTS:
        provenance.verify_subject(assets / name, assets / (name + '.provenance.jsonl'),
            gh=gh, cosign=cosign, signature_bundle=assets / (name + '.sigstore.json'),
            workflow=workflow, source_sha=bound['source_sha'], run_id=bound['build_run_id'],
            run_attempt=bound['build_run_attempt'], runner=runner)
    release.require(release.verify_inventory_assets(assets, **build) == record, 'candidate changed')
    for path, expected in paths.items():
        release.require(private_file(path, expected[1], executable=path in (gh, cosign)) == expected,
                        'verified input changed')
    return authorization, receipt, inventory, paths


def verified_bootstrap(harness_source_sha):
    release.sha(harness_source_sha)
    root = Path(__file__).resolve().parent.parent
    script = root / 'scripts/installer_candidate_public_bootstrap.py'
    release.require(script.is_file() and not script.is_symlink(), 'public guest bootstrap unavailable')
    with tempfile.TemporaryDirectory(prefix='marty-candidate-bootstrap-source-') as home:
        raw = command(['/usr/bin/git', '--no-replace-objects', '-C', str(root), 'show',
                       harness_source_sha + ':scripts/installer_candidate_public_bootstrap.py'],
                      env={'HOME': home, 'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                           'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_CONFIG_NOSYSTEM': '1',
                           'GIT_CONFIG_GLOBAL': '/dev/null'},
                      timeout=15, limit=65536)
    with script.open('rb') as stream:
        current = stream.read(65537)
    release.require(raw == current and 0 < len(raw) <= 65536 and len(current) <= 65536,
                    'public guest bootstrap differs from signed harness source')
    return raw.decode('utf-8')


def remote_plan(home, user, context, target, *, authorization=None, bootstrap_source=None):
    release.require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user) is not None and user != 'root', 'invalid guest user')
    release.require(home == '/home/' + user, 'guest home must match dedicated account')
    base = home + '/.marty-installer-dispatch-' + target['installation_id']
    installation = home + '/marty-install-' + target['installation_id']
    registry = home + '/.marty-installer-candidate-nonces'
    q = shlex.quote
    setup = ('set -eu; PATH=/usr/bin:/bin; export PATH; umask 077; test "$(id -u)" -ne 0; '
             f'test "$(id -un)" = {q(user)}; test "$HOME" = {q(home)}; '
             f'test "$(getent passwd "$(id -u)" | cut -d: -f6)" = {q(home)}; '
             f'test ! -L {q(home)}; test "$(stat -c %u:%a {q(home)})" = "$(id -u):700"; '
             f'if test -e {q(registry)} || test -L {q(registry)}; then '
             f'test -d {q(registry)}; test ! -L {q(registry)}; '
             f'test "$(stat -c %u:%a {q(registry)})" = "$(id -u):700"; '
             f'else mkdir -m 700 -- {q(registry)}; fi; '
             f'test ! -e {q(installation)}; test ! -L {q(installation)}; '
             f'mkdir -m 700 -- {q(base)}; mkdir -m 700 -- {q(base + "/inputs")} {q(base + "/grants")} {q(base + "/tools")}; ')
    flags = ['--authorization', base + '/grants/candidate-authorization.json',
             '--controller-consumption', base + '/grants/controller-consumption.json',
             '--inputs-dir', base + '/inputs', '--verification-tools', base + '/tools',
             '--gh-bin', base + '/tools/gh', '--docker-bin', '/usr/bin/docker',
             '--install-dir', installation, '--docker-engine-id', target['engine_id'],
             '--harness-source-sha', context['harness_source_sha'], '--phase', context['phase'],
             '--run-id', str(context['run_id']), '--run-attempt', str(context['run_attempt']),
             '--nonce', context['nonce']]
    checks = ([(context['operator_sha256'], base + '/marty-deploy')]
              if context['phase'] == 'staged' else []) + [
                  (TOOLS['gh'][0], base + '/tools/gh'),
                  (TOOLS['cosign'][0], base + '/tools/cosign')]
    hash_commands = ''.join("printf '%s  %s\\n' " + q(digest) + ' ' + q(path) +
                            ' | /usr/bin/sha256sum --check --status --strict; ' for digest, path in checks)
    if context['phase'] == 'staged':
        invoke = ('set -eu; PATH=/usr/bin:/bin; export PATH; umask 077; '
                  f'chmod 600 -- {q(base)}/inputs/* {q(base)}/grants/*; '
                  f'chmod 700 -- {q(base)}/tools/gh {q(base)}/tools/cosign; '
                  f'(set -C; cat -- {q(base)}/inputs/marty-deploy-linux-amd64 > {q(base)}/marty-deploy); '
                  f'chmod 700 -- {q(base)}/marty-deploy; '
                  + hash_commands + 'exec env -i HOME=' + q(home) + ' PATH=/usr/bin:/bin ' +
                  shlex.join([base + '/marty-deploy', 'install-candidate', *flags]))
    else:
        release.require(authorization is not None and bootstrap_source is not None,
                        'published dispatch needs authenticated bootstrap')
        authorization_record = release.decode(authorization)
        public_flags = ['--base', base, '--grants', base + '/grants', '--tools', base + '/tools',
                        '--inputs', base + '/inputs', '--install-dir', installation,
                        '--source-sha', context['source_sha'], '--release-tag', context['release_tag'],
                        '--operator-sha256', context['operator_sha256'], '--nonce', context['nonce'],
                        '--harness-source-sha', context['harness_source_sha'],
                        '--engine-id', target['engine_id'], '--guest-id', target['guest_id'],
                        '--disk-id', target['disk_id'], '--installation-id', target['installation_id'],
                        '--run-id', str(context['run_id']), '--run-attempt', str(context['run_attempt']),
                        '--build-run-id', str(authorization_record['build_run_id']),
                        '--build-run-attempt', str(authorization_record['build_run_attempt'])]
        invoke = ('set -eu; PATH=/usr/bin:/bin; export PATH; umask 077; '
                  f'chmod 600 -- {q(base)}/grants/*; '
                  f'chmod 700 -- {q(base)}/tools/gh {q(base)}/tools/cosign; '
                  + hash_commands + 'exec env -i HOME=' + q(home) + ' PATH=/usr/bin:/bin ' +
                  shlex.join(['/usr/bin/python3', '-I', '-c', bootstrap_source, *public_flags]))
    return base, setup, invoke


def registry_unchanged(held, path):
    current = _directory(path)
    try:
        a, b = os.fstat(held), os.fstat(current)
        release.require((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino), 'controller registry replaced')
    finally:
        os.close(current)


def dispatch(*, assets, grants, context_file, target_file, ledger, gh, cosign,
             ssh, scp, key, known_hosts, host, port, user, home,
             clock=time.time, verifier=provenance.command, run=command):
    release.require(os.name == 'posix', 'Linux controller required')
    release.require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}', host) is not None,
                    'invalid pinned guest host')
    release.require(type(port) is int and 1 <= port <= 65535, 'invalid guest SSH port')
    for path in (ssh, scp):
        executable(path)
    for path in (key, known_hosts, ledger, context_file, target_file):
        private_file(path, 65536)
    ssh_inputs = {path: private_file(path, 65536) for path in (key, known_hosts)}
    context, target = release.decode(read_record(context_file)), release.decode(read_record(target_file))
    parent = _directory(ledger.parent)
    locked = False
    owner = os.getpid()
    try:
        locked = True
        fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        registry_unchanged(parent, ledger.parent)
        authorization, receipt, inventory, files = verify(assets=assets, grants=grants, context=context,
            target=target, ledger=ledger, gh=gh, cosign=cosign, now=int(clock()), runner=verifier)
        release.bind_controller_consumption(receipt, authorization, inventory, expected=context,
            expected_engine=target['engine_id'], now=int(clock()))
        source = verified_bootstrap(context['harness_source_sha']) if context['phase'] == 'published' else None
        base, setup, invoke = remote_plan(home, user, context, target,
            authorization=authorization, bootstrap_source=source)
        intent = Path(str(ledger) + '.dispatch.json')
        registry_unchanged(parent, ledger.parent)
        write_exclusive(intent, release.encode(dict(schema='elevenid.installer-candidate-dispatch/v1',
            context_sha256=release.candidate_context_sha256(context), receipt_sha256=release.digest(receipt),
            target=target, ssh_host=host, ssh_port=port, ssh_user=user, guest_staging=base,
            known_hosts_sha256=private_file(known_hosts, 65536)[0], started_at=int(clock()),
            installation_ready=False)))
        options = ssh_options(key, known_hosts, port)
        with tempfile.TemporaryDirectory(prefix='marty-candidate-dispatch-') as local_home:
            env = {'HOME': local_home, 'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
            def guarded_run(argv, timeout):
                registry_unchanged(parent, ledger.parent)
                release.require(read_record(ledger) == receipt, 'controller ledger changed')
                release.bind_controller_consumption(receipt, authorization, inventory, expected=context,
                    expected_engine=target['engine_id'], now=int(clock()))
                for path, expected in ssh_inputs.items():
                    release.require(private_file(path, 65536) == expected, 'SSH custody changed')
                return run(argv, env=env, timeout=timeout)
            def remote(script, timeout=60):
                return guarded_run([str(ssh), *options, '-T', user + '@' + host, script], timeout)
            remote(setup)
            transfers = []
            if context['phase'] == 'staged':
                transfers.append(([assets / (n + s) for n in SUBJECTS for s in SUFFIXES], '/inputs'))
            transfers.append(([grants / (n + s) for n in ('candidate-authorization.json', 'controller-consumption.json') for s in SUFFIXES], '/grants'))
            for names, destination in transfers:
                guarded_run([str(scp), *options, *map(str, names), user + '@' + host + ':' + base + destination + '/'], 300)
            for name, source in [('gh', gh), ('cosign', cosign)]:
                guarded_run([str(scp), *options, str(source), user + '@' + host + ':' + base + '/tools/' + name], 180)
            for path, expected in files.items():
                release.require(private_file(path, expected[1], executable=path in (gh, cosign)) == expected,
                                'dispatch source changed')
            release.bind_controller_consumption(receipt, authorization, inventory, expected=context,
                expected_engine=target['engine_id'], now=int(clock()))
            release.require(read_record(ledger) == receipt, 'controller ledger changed')
            registry_unchanged(parent, ledger.parent)
            write_exclusive(Path(str(ledger) + '.invoke.json'), release.encode(dict(
                schema='elevenid.installer-candidate-invocation/v1', receipt_sha256=release.digest(receipt),
                installation_id=target['installation_id'], invoked_at=int(clock()), installation_ready=False)))
            remote(invoke, timeout=1800)
        result = dict(schema='elevenid.installer-candidate-dispatch-result/v1',
                      installation_id=target['installation_id'], command_returned_zero=True,
                      installation_ready=False, acceptance_report=False)
        registry_unchanged(parent, ledger.parent)
        write_exclusive(Path(str(ledger) + '.dispatch-result.json'), release.encode(result))
        return result
    finally:
        try:
            if locked and os.getpid() == owner:
                while True:
                    try:
                        fcntl.flock(parent, fcntl.LOCK_UN)
                        break
                    except InterruptedError:
                        continue
        finally:
            os.close(parent)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('assets', 'grants', 'context-file', 'target-file', 'ledger', 'gh', 'cosign',
                 'ssh', 'scp', 'key', 'known-hosts'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('host', 'user', 'home'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--port', required=True, type=int)
    try:
        dispatch(**vars(parser.parse_args(argv)))
    except (ValueError, OSError, TypeError, KeyError):
        parser.exit(1, 'Candidate dispatch refused, incomplete or uncertain; retain guest, ledger and all evidence. Do not retry.\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
