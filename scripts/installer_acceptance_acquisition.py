"""Collect one protected published-guest acquisition component, never admission.

Only the signed guest observer and the already authenticated controller closure
produce this record. The five-case startup report and complete functional report
are deliberately unchanged. Caller case JSON is not an input to this collector.
"""
from __future__ import annotations

from contextlib import ExitStack
import os
from pathlib import Path
import secrets
import shlex
import tempfile
import time
import uuid

import installer_candidate_dispatch as dispatch
import installer_candidate_rendezvous as transport
import installer_release as r
import installer_acceptance_startup as startup
import installer_startup_observation as observation
from installer_candidate_hosting import HeldInput
from installer_startup_transport import HeldFiles

SCHEMA = 'elevenid.installer-published-acquisition-observation/v1'
NAME = 'installer-published-acquisition-observation.json'
MAX_BYTES = 65536
OWNER_NAMES = {'intent', 'completion', 'bootstrap_intent', 'bootstrap_verified'}
NAMES = {name + suffix for name in dispatch.SUBJECTS for suffix in dispatch.SUFFIXES}


def authority(*, context, target, authorization, receipt, inventory, pins, now):
    r.require(context.get('phase') == 'published', 'guest acquisition requires published phase')
    consumed = r.bind_controller_consumption(receipt, authorization, inventory, expected=context,
        expected_engine=target['engine_id'], now=now)
    r.require(all(consumed[key] == target[key] for key in ('guest_id', 'disk_id', 'engine_id', 'installation_id')),
              'guest acquisition target differs')
    r.validate_candidate_evidence(pins)
    for name, raw in (('installer-candidate-authorization.json', authorization),
                      ('installer-controller-consumption.json', receipt), ('installer-inventory.json', inventory)):
        r.require(pins[name] == r.digest(raw), 'guest acquisition authenticated bytes changed')
    return r.decode(authorization), consumed


def _records(value):
    r.exact(value, OWNER_NAMES, 'guest acquisition owner closure')
    result = {}
    for name, item in value.items():
        r.exact(item, {'sha256', 'record'}, 'guest acquisition owner bytes')
        r.require(type(item['record']) is str, 'guest acquisition owner bytes missing')
        raw = item['record'].encode()
        r.require(0 < len(raw) <= MAX_BYTES and r.digest(raw) == item['sha256'], 'guest acquisition owner changed')
        result[name] = r.decode(raw)
    return result


def validate_native(raw, *, context, target, authorization, receipt, inventory, pins,
                    verified_assets, expected_request, observed_at):
    r.require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, 'guest acquisition observation exceeds bound')
    auth, consumed = authority(context=context, target=target, authorization=authorization, receipt=receipt,
        inventory=inventory, pins=pins, now=observed_at)
    value = r.decode(raw)
    r.exact(value, {'schema', 'phase', 'request', 'source_sha', 'release_tag', 'build_run_id', 'build_run_attempt',
        'harness_source_sha', 'run_id', 'run_attempt', 'guest_id', 'disk_id', 'installation_id', 'engine_id',
        'operator_sha256', 'context_sha256', 'authorization_sha256', 'controller_consumption_sha256',
        'inventory_sha256', 'authenticated_evidence_sha256', 'started_at', 'completed_at', 'owner_records',
        'receipts', 'installation_ready', 'acceptance', 'functional_recovery_qualified'}, 'guest acquisition observation')
    observation.request(value['request']); observation.request(expected_request)
    r.require(value['schema'] == SCHEMA and value['phase'] == 'published' and value['request'] == expected_request
        and all(value[k] == context[k] for k in ('source_sha', 'release_tag', 'harness_source_sha', 'run_id', 'run_attempt'))
        and all(value[k] == auth[k] for k in ('build_run_id', 'build_run_attempt', 'operator_sha256'))
        and all(value[k] == target[k] for k in ('guest_id', 'disk_id', 'engine_id', 'installation_id'))
        and value['context_sha256'] == r.candidate_context_sha256(context)
        and value['authorization_sha256'] == r.digest(authorization)
        and value['controller_consumption_sha256'] == r.digest(receipt)
        and value['inventory_sha256'] == r.digest(inventory)
        and value['authenticated_evidence_sha256'] == pins
        and all(value[k] is False for k in ('installation_ready', 'acceptance', 'functional_recovery_qualified')),
        'guest acquisition scope, challenge or authority differs')
    for key in ('run_id', 'run_attempt', 'build_run_id', 'build_run_attempt'):
        observation.integer(value[key], minimum=1)
    started = observation.integer(value['started_at'], minimum=consumed['consumed_at'], maximum=observed_at)
    completed = observation.integer(value['completed_at'], minimum=started, maximum=observed_at)
    r.require(completed < auth['expires_at'] and completed - started <= 120, 'guest acquisition observation window differs')
    records = _records(value['owner_records'])
    intent, result = records['intent'], records['completion']
    r.exact(intent, {'schema', 'context_sha256', 'authorization_sha256', 'controller_consumption_sha256',
                     'started_at', 'installation_ready'}, 'guest acquisition intent')
    r.exact(result, {'schema', 'phase', 'context_sha256', 'authorization_sha256', 'controller_consumption_sha256',
                     'inventory_sha256', 'intent_sha256', 'started_at', 'completed_at', 'receipts',
                     'installation_ready'}, 'guest acquisition completion')
    r.require(intent['schema'] == 'elevenid.installer-public-acquisition-intent/v1'
        and result['schema'] == 'elevenid.installer-public-acquisition-result/v2' and result['phase'] == 'published'
        and intent['installation_ready'] is False and result['installation_ready'] is False
        and all(intent[k] == result[k] == value[k] for k in ('context_sha256', 'authorization_sha256', 'controller_consumption_sha256'))
        and result['inventory_sha256'] == value['inventory_sha256']
        and result['intent_sha256'] == value['owner_records']['intent']['sha256'], 'guest acquisition completion binding differs')
    acquisition_start = observation.integer(intent['started_at'], minimum=consumed['consumed_at'], maximum=started)
    r.require(type(result['started_at']) is int and result['started_at'] == acquisition_start, 'guest acquisition start differs')
    acquisition_end = observation.integer(result['completed_at'], minimum=acquisition_start, maximum=started)
    r.require(acquisition_end < auth['expires_at'], 'guest acquisition completed outside original grant')
    r.exact(verified_assets, NAMES, 'independently verified candidate assets')
    receipts = result['receipts']
    r.require(type(receipts) is list and len(receipts) == len(NAMES) and receipts == value['receipts'],
              'guest acquisition receipts differ')
    seen = set()
    payloads = {item['name']: item for item in r.decode(inventory)['artifacts']}
    for item in receipts:
        r.exact(item, {'asset', 'bytes', 'sha256', 'hash_verified'}, 'guest download receipt')
        name = item['asset']
        r.require(type(name) is str and name in NAMES and name not in seen, 'guest receipt name differs')
        seen.add(name)
        expected = r.exact(verified_assets[name], {'sha256', 'bytes'}, 'verified public asset')
        r.sha(item['sha256'], 64)
        observation.integer(item['bytes'], minimum=1, maximum=536870912)
        r.require(item['sha256'] == expected['sha256'] and type(expected['bytes']) is int
            and item['bytes'] == expected['bytes'] and type(item['hash_verified']) is bool
            and item['hash_verified'] == (name in payloads), 'guest bytes differ from authenticated controller assets')
        if name in payloads:
            r.require(item['sha256'] == payloads[name]['sha256'] and item['bytes'] == payloads[name]['size'],
                      'guest payload differs from signed inventory')
        elif name == 'installer-inventory.json':
            r.require(item['sha256'] == r.digest(inventory) and item['bytes'] == len(inventory), 'guest inventory differs')
        else:
            r.require(item['bytes'] <= 1048576, 'guest sidecar exceeds bound')
    bootstrap, verified = records['bootstrap_intent'], records['bootstrap_verified']
    r.exact(bootstrap, {'schema', 'context_sha256', 'authorization_sha256', 'receipt_sha256', 'started_at',
                        'installation_ready'}, 'guest bootstrap intent')
    r.exact(verified, {'schema', 'context_sha256', 'inventory_sha256', 'operator_sha256', 'authorization_sha256',
                       'receipt_sha256', 'verified_at', 'installation_ready'}, 'guest bootstrap verification')
    r.require(bootstrap['schema'] == 'elevenid.installer-public-bootstrap-intent/v1'
        and verified['schema'] == 'elevenid.installer-public-bootstrap-verified/v1'
        and bootstrap['installation_ready'] is False and verified['installation_ready'] is False
        and all(bootstrap[k] == verified[k] == value[k] for k in ('context_sha256', 'authorization_sha256'))
        and bootstrap['receipt_sha256'] == verified['receipt_sha256'] == value['controller_consumption_sha256']
        and verified['inventory_sha256'] == value['inventory_sha256'] and verified['operator_sha256'] == context['operator_sha256'],
        'guest bootstrap lineage differs')
    bootstrap_start = observation.integer(bootstrap['started_at'], minimum=consumed['consumed_at'], maximum=acquisition_start)
    observation.integer(verified['verified_at'], minimum=bootstrap_start, maximum=acquisition_start)
    return value


def collect(*, output, assets, files, context, target, authorization, receipt, inventory, pins,
            ssh, key, known_hosts, port, host, user, home, bootstrap_source,
            unchanged, guarded_execute, client, clock=time.time):
    """A fixed native invocation under original live scope; no JSON-proof CLI."""
    args = dict(context=context, target=target, authorization=authorization, receipt=receipt, inventory=inventory, pins=pins)
    auth, _ = authority(**args, now=int(clock()))
    base, _, _ = dispatch.remote_plan(home, user, context, target, authorization=authorization, bootstrap_source=bootstrap_source)
    expected_run = {key: context[key] for key in ('harness_source_sha', 'run_id', 'run_attempt')}
    def active():
        run = client.request('GET', transport.REPO + '/actions/runs/' + str(context['run_id']))
        startup.validate_active_run(run, expected_run)
        authority(**args, now=int(clock()))
    verified_assets = {}
    for name in NAMES:
        value = files.get(assets / name)
        r.require(type(value) is tuple and len(value) == 2, 'verified controller asset missing')
        verified_assets[name] = dict(sha256=value[0], bytes=value[1])
    output = Path(output)
    parent = dispatch._directory(output)
    try:
        r.require(not os.path.lexists(output / NAME), 'guest acquisition observation already retained')
        with startup.HarnessSources(context['harness_source_sha']) as sources, ExitStack() as held:
            inputs = HeldFiles(); held.callback(inputs.close)
            for path, expected in files.items():
                r.require(inputs.add(path, expected[1], executable=path.name in dispatch.TOOLS) == expected,
                          'authenticated controller input changed')
            for path in (key, known_hosts):
                inputs.add(path, 65536)
            def check():
                unchanged(); sources.check(); inputs.check(); dispatch.registry_unchanged(parent, output)
            request = dict(observation_id=str(uuid.uuid4()), challenge=secrets.token_hex(32))
            flags = ['--observe-acquisition', '--base', base, '--grants', base + '/grants',
                '--tools', base + '/tools', '--inputs', base + '/inputs',
                '--install-dir', home + '/marty-install-' + target['installation_id'],
                '--source-sha', context['source_sha'], '--release-tag', context['release_tag'],
                '--operator-sha256', context['operator_sha256'], '--nonce', context['nonce'],
                '--harness-source-sha', context['harness_source_sha'], '--engine-id', target['engine_id'],
                '--guest-id', target['guest_id'], '--disk-id', target['disk_id'],
                '--installation-id', target['installation_id'], '--run-id', str(context['run_id']),
                '--run-attempt', str(context['run_attempt']), '--build-run-id', str(auth['build_run_id']),
                '--build-run-attempt', str(auth['build_run_attempt']),
                '--observation-id', request['observation_id'], '--challenge', request['challenge']]
            # Use the exact signed bootstrap's held executable, without the
            # normal dispatch prefix (which changes permissions and installs).
            invocation = ('set -eu; PATH=/usr/bin:/bin; export PATH; test "$(id -u)" -ne 0; '
                + 'test "$(id -un)" = ' + shlex.quote(user) + '; test "$HOME" = ' + shlex.quote(home)
                + '; test "$(getent passwd "$(id -u)" | cut -d: -f6)" = ' + shlex.quote(home)
                + '; exec env -i HOME=' + shlex.quote(home) + ' PATH=/usr/bin:/bin '
                + shlex.join(['/usr/bin/setpriv', '--no-new-privs', '--', '/usr/bin/python3', '-I', '-c',
                              bootstrap_source, *flags]))
            check(); active()
            with tempfile.TemporaryDirectory(prefix='marty-acquisition-observer-') as private:
                raw = guarded_execute([str(ssh), *dispatch.ssh_options(key, known_hosts, port), '-T', user + '@' + host, invocation],
                    env=dict(HOME=private, PATH='/usr/bin:/bin', LANG='C', LC_ALL='C'), timeout=150, limit=MAX_BYTES)
            check(); active()
            value = validate_native(raw, **args, verified_assets=verified_assets, expected_request=request, observed_at=int(clock()))
            fd = os.open(NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            try:
                with os.fdopen(fd, 'wb', closefd=False) as stream:
                    stream.write(raw); stream.flush(); os.fsync(fd)
                os.fsync(parent)
            finally:
                os.close(fd)
            with HeldInput(output / NAME, MAX_BYTES) as record:
                r.require(record.check() == raw, 'guest acquisition retained bytes changed')
                check(); active(); record.check()
            return value
    finally:
        os.close(parent)
