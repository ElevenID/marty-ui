"""Fixed signed startup transport and verifier, without qualification authority.

The controller may upload one bounded public startup record to its original
owned draft. The active workflow independently verifies the original five
artifact subjects and both grants before accepting those bytes for signing.
The final reader accepts only the exact completed successful workflow run.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import time
import urllib.error
import urllib.parse
import urllib.request

import installer_acceptance_startup as startup
import installer_candidate_dispatch as dispatch
import installer_candidate_receipt_upload as receipt_upload
import installer_candidate_rendezvous as transport
import installer_release as r
import installer_startup_observation as observation
import verify_installer_provenance as provenance
from installer_candidate_authorize import write_exclusive


class HeldFiles:
    """Private exact file identities, retained across every external verifier.

    Large signed payloads are hashed through retained descriptors, not loaded
    into memory. Parent replacement and same-byte inode replacement both refuse.
    """
    def __init__(self):
        self.files = {}

    @staticmethod
    def stamp(info):
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    @staticmethod
    def identity(fd, maximum, executable):
        info = os.fstat(fd)
        r.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                  and stat.S_IMODE(info.st_mode) == (0o700 if executable else 0o600)
                  and info.st_nlink == 1 and 0 < info.st_size <= maximum,
                  'startup private file ownership, mode, links or bound differ')
        return HeldFiles.stamp(info)

    @staticmethod
    def digest(fd, size):
        result = hashlib.sha256()
        offset = 0
        while offset < size:
            raw = os.pread(fd, min(1024 * 1024, size - offset), offset)
            r.require(bool(raw), 'startup input truncated')
            result.update(raw)
            offset += len(raw)
        r.require(os.pread(fd, 1, offset) == b'', 'startup input grew')
        return result.hexdigest()

    def add(self, path, maximum, *, executable=False):
        path = Path(path)
        r.require(path not in self.files and type(maximum) is int and maximum > 0,
                  'startup held file repeated or unbounded')
        parent = dispatch._directory(path.parent)
        fd = None
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=parent)
            identity = self.identity(fd, maximum, executable)
            digest = self.digest(fd, identity[6])
            r.require(self.identity(fd, maximum, executable) == identity, 'startup input changed while read')
            self.files[path] = (parent, fd, maximum, executable, identity, digest)
            return digest, identity[6]
        except BaseException:
            if fd is not None: os.close(fd)
            os.close(parent)
            raise

    def raw(self, path, maximum):
        item = self.files[Path(path)]
        r.require(item[4][6] <= maximum, 'startup record exceeds read bound')
        raw = os.pread(item[1], maximum + 1, 0)
        r.require(len(raw) == item[4][6] and r.digest(raw) == item[5], 'startup record changed')
        return raw

    def parent_stamps(self):
        """Capture a no-local-write window, including rename-and-restore ctime."""
        return {path.parent: self.stamp(os.fstat(item[0])) for path,item in self.files.items()}

    def check(self, *, parent_stamps=None):
        for path, (parent, fd, maximum, executable, identity, digest) in self.files.items():
            current_parent = dispatch._directory(path.parent)
            current = None
            try:
                a, b = os.fstat(parent), os.fstat(current_parent)
                r.require((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino), 'startup input directory replaced')
                if parent_stamps is not None:
                    r.require(self.stamp(a) == self.stamp(b) == parent_stamps[path.parent],
                              'startup input directory changed during verifier')
                current = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                  dir_fd=current_parent)
                r.require(self.identity(fd, maximum, executable) == identity
                    == self.identity(current, maximum, executable)
                    and self.digest(fd, identity[6]) == digest
                    and self.digest(current, identity[6]) == digest, 'held startup input changed')
            finally:
                if current is not None: os.close(current)
                os.close(current_parent)

    def close(self):
        for parent, fd, *_ in self.files.values():
            os.close(fd); os.close(parent)
        self.files.clear()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


def _tools(held, gh, cosign):
    for name, path in (('gh', gh), ('cosign', cosign)):
        r.require(held.add(path, dispatch.TOOLS[name][1], executable=True) == dispatch.TOOLS[name],
                  'startup verifier trust anchor differs')


class AuthenticatedInputs:
    """An actually verified local closure, including retained signed grant bytes."""
    def __init__(self, *, authorization, receipt, inventory, assets, gh, cosign,
                 verifier=provenance.command):
        self.held = HeldFiles()
        try:
            r.require(inventory == assets / 'installer-inventory.json', 'startup inventory layout differs')
            names = {name + suffix for name in dispatch.SUBJECTS for suffix in dispatch.SUFFIXES}
            r.require({path.name for path in assets.iterdir()} == names, 'startup artifact closure differs')
            self.subjects = {}
            for name in dispatch.SUBJECTS:
                entries = []
                for suffix in dispatch.SUFFIXES:
                    maximum = 1048576 if suffix else (65536 if name == 'installer-inventory.json'
                                                     else r.ARTIFACT_MAX_BYTES[name])
                    entries.append(self.held.add(assets / (name + suffix), maximum))
                self.subjects[name] = dict(sha256=entries[0][0], size_bytes=entries[0][1],
                                          signature_sha256=entries[1][0], provenance_sha256=entries[2][0])
            self.pins = {}
            for path, name in ((authorization, 'installer-candidate-authorization.json'),
                               (receipt, 'installer-controller-consumption.json')):
                for suffix in dispatch.SUFFIXES:
                    self.pins[name + suffix] = self.held.add(Path(str(path) + suffix),
                                                            1048576 if suffix else 65536)[0]
            for suffix, key in (('', 'sha256'), ('.sigstore.json', 'signature_sha256'),
                                ('.provenance.jsonl', 'provenance_sha256')):
                self.pins['installer-inventory.json' + suffix] = self.subjects['installer-inventory.json'][key]
            _tools(self.held, gh, cosign)
            self.authorization = self.held.raw(authorization, 65536)
            self.receipt = self.held.raw(receipt, 65536)
            self.inventory = self.held.raw(inventory, 65536)
            self.grant = r.decode(self.authorization)
            self.context = r.candidate_context(self.grant)
            consumed = r.decode(self.receipt)
            self.target = {key: consumed[key] for key in dispatch.TARGET_FIELDS}
            observation.authority(context=self.context, target=self.target, authorization=self.authorization,
                receipt=self.receipt, inventory=self.inventory, pins=self.pins, now=consumed['consumed_at'])
            hosting = r.candidate_hosting.check_file(self.grant, authorization.parent)
            for name, raw in hosting.items():
                path = authorization.parent / name
                self.held.add(path, r.candidate_hosting.MAX_ROOTS_BYTES)
                r.require(self.held.raw(path, r.candidate_hosting.MAX_ROOTS_BYTES) == raw,
                          'startup hosting input changed')
            build = {key: self.grant[key] for key in ('source_sha', 'release_tag', 'build_run_id', 'build_run_attempt')}
            inventory_record = r.verify_inventory_assets(assets, **build)
            tier, _ = r.classify_release_tag(self.grant['release_tag'])
            build_workflow = '.github/workflows/nightly-release.yml' if tier == 'nightly' else '.github/workflows/cd.yml'

            def guarded(argv, **kwargs):
                self.check()
                parents = self.held.parent_stamps()
                result = verifier(argv, **kwargs)
                self.held.check(parent_stamps=parents)
                return result

            for path in (authorization, receipt):
                provenance.verify_subject(path, Path(str(path) + '.provenance.jsonl'), gh=gh, cosign=cosign,
                    signature_bundle=Path(str(path) + '.sigstore.json'), workflow=r.acceptance.WORKFLOW,
                    source_sha=self.context['harness_source_sha'], run_id=self.context['run_id'],
                    run_attempt=self.context['run_attempt'], runner=guarded)
            for name in dispatch.SUBJECTS:
                provenance.verify_subject(assets / name, assets / (name + '.provenance.jsonl'),
                    gh=gh, cosign=cosign, signature_bundle=assets / (name + '.sigstore.json'),
                    workflow=build_workflow, source_sha=self.grant['source_sha'], run_id=self.grant['build_run_id'],
                    run_attempt=self.grant['build_run_attempt'], runner=guarded)
            r.require(r.verify_inventory_assets(assets, **build) == inventory_record, 'startup artifact inventory changed')
            self.check()
        except BaseException:
            self.held.close()
            raise

    def bind_report(self, value):
        r.require(value['authority'] == dict(authorization=self.authorization.decode(),
            controller_consumption=self.receipt.decode(), authenticated_evidence_sha256=self.pins),
            'startup returned authority differs from actual verified files')
        artifact = r.decode(value['owner_records']['artifacts']['record'].encode())
        r.require(artifact['subjects'] == self.subjects, 'startup artifact proof differs from independent verifier')

    def check(self): self.held.check()
    def __enter__(self): return self
    def __exit__(self, *_): self.held.close()


class Client(transport.Client):
    """Only the fixed startup subject gets the larger public-record bound."""
    def download_startup(self, asset_id, size):
        transport.positive_id(asset_id)
        r.require(type(size) is int and 0 < size <= startup.MAX_BYTES, 'startup transport size differs')
        raw = self._read(f'https://api.github.com{transport.REPO}/releases/assets/{asset_id}',
                         binary=True, maximum=size)
        r.require(len(raw) == size, 'startup transport size changed')
        return raw

    def upload_startup(self, release_id, raw):
        transport.positive_id(release_id)
        r.require(type(raw) is bytes and 0 < len(raw) <= startup.MAX_BYTES, 'startup upload exceeds bound')
        url = (f'https://uploads.github.com{transport.REPO}/releases/{release_id}/assets?'
               + urllib.parse.urlencode({'name': startup.NAME}))
        request = urllib.request.Request(url, data=raw, method='POST', headers={
            'Accept': 'application/vnd.github+json', 'Content-Type': 'application/octet-stream',
            'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'marty-installer-startup',
            'Authorization': 'Bearer ' + self.token})
        try:
            with self.opener.open(request, timeout=20) as response:
                r.require(response.status == 201, 'startup upload status differs')
                answer = response.read(transport.MAX_BYTES + 1)
        except (urllib.error.HTTPError, OSError, urllib.error.URLError):
            raise ValueError('startup upload failed or is uncertain') from None
        return transport.json_bytes(answer)


def _startup_asset(item, approved):
    r.require(type(item) is dict and type(item.get('uploader')) is dict, 'startup asset metadata differs')
    actor = item['uploader']
    r.require(type(actor.get('id')) is int and actor['id'] == approved and actor.get('type') == 'User'
        and type(actor.get('login')) is str and actor['login'] and actor['login'] != 'github-actions[bot]',
        'startup uploader differs')
    transport.positive_id(item.get('id'))
    r.require(item.get('name') == startup.NAME and item.get('state') == 'uploaded'
        and type(item.get('size')) is int and 0 < item['size'] <= startup.MAX_BYTES
        and type(item.get('digest')) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', item['digest'])
        and all(type(item.get(key)) is str and 0 < len(item[key]) <= 64 for key in ('created_at', 'updated_at')),
        'startup asset metadata differs')
    return {key: item[key] for key in ('id','name','state','size','digest','uploader','created_at','updated_at')}


def asset(items, approved, receipt):
    r.require(type(items) is list and 1 <= len(items) <= 2 and all(type(item) is dict for item in items),
              'startup transport closure differs')
    names = [item.get('name') for item in items]
    r.require(len(set(names)) == len(names) and set(names) in
        ({transport.RECEIPT}, {transport.RECEIPT, startup.NAME}), 'startup transport names differ')
    original = transport.receipt_asset([item for item in items if item.get('name') == transport.RECEIPT], approved)
    r.require(original['size'] == len(receipt) and original['digest'] == 'sha256:' + r.digest(receipt),
              'startup original controller receipt changed')
    found = [item for item in items if item.get('name') == startup.NAME]
    return _startup_asset(found[0], approved) if found else None


def _active(client, context):
    run = client.request('GET', transport.REPO + '/actions/runs/' + str(context['run_id']))
    startup.validate_active_run(run, context)
    return run


def _expected(auth):
    return dict(inventory_bytes=auth.inventory, source_sha=auth.context['source_sha'],
                release_tag=auth.context['release_tag'], phase=auth.context['phase'])


def _descriptor(held, path, auth, approved, harness_source_sha, run_id, run_attempt):
    held.add(path, 65536)
    r.require(all(auth.context[key] == value for key, value in (
        ('harness_source_sha', harness_source_sha), ('run_id', run_id), ('run_attempt', run_attempt))),
        'startup independent invocation differs')
    return transport.bound_descriptor(path, auth.authorization, auth.inventory, auth.context, auth.grant, approved)


def receive(*, client, authorization, inventory, receipt, descriptor, output, assets, gh, cosign,
            harness_source_sha, run_id, run_attempt, controller_user_id, clock=time.time,
            sleep=time.sleep, verifier=provenance.command):
    r.require(output.name == startup.NAME, 'startup signer output name differs')
    with AuthenticatedInputs(authorization=authorization, receipt=receipt, inventory=inventory,
                             assets=assets, gh=gh, cosign=cosign, verifier=verifier) as auth, HeldFiles() as held:
        approved = transport.controller_id(controller_user_id)
        owned = _descriptor(held, descriptor, auth, approved, harness_source_sha, run_id, run_attempt)
        when = r.decode(auth.receipt)['consumed_at']
        r.require(when <= int(clock()) < when + 7200, 'startup return window expired')
        _active(client, auth.context)
        endpoint = transport.REPO + '/releases/' + str(owned['id'])
        deadline = min(int(clock()) + 1800, when + 7200)
        while int(clock()) < deadline:
            transport.check_release(client.request('GET', endpoint), owned)
            selected = asset(client.request('GET', endpoint + '/assets?per_page=100'), approved, auth.receipt)
            if selected is None:
                sleep(min(5, max(0, deadline - int(clock()))))
                continue
            raw = client.download_startup(selected['id'], selected['size'])
            r.require(r.digest(raw) == selected['digest'][7:], 'startup transport digest differs')
            transport.check_release(client.request('GET', endpoint), owned)
            r.require(asset(client.request('GET', endpoint + '/assets?per_page=100'), approved, auth.receipt) == selected,
                      'startup asset changed during download')
            value = startup.decode(raw)
            startup.validate_active_payload(value, run=_active(client, auth.context), **_expected(auth))
            auth.bind_report(value)
            r.require(when <= value['observed_at'] <= int(clock()) < deadline, 'startup return timing differs')
            auth.check(); held.check()
            evidence = dict(schema='elevenid.installer-startup-transport/v1', release_id=owned['id'],
                startup_sha256=r.digest(raw), receipt_sha256=r.digest(auth.receipt),
                context_sha256=r.candidate_context_sha256(auth.context), controller_user_id=approved,
                verified_at=int(clock()), asset={key: selected[key] for key in
                    ('id','name','size','digest','created_at','updated_at')},
                installation_ready=False, functional_recovery_qualified=False, load_characterized=False)
            _active(client, auth.context)
            auth.check(); held.check()
            write_exclusive(Path(str(output) + '.transport.json'), r.encode(evidence))
            write_exclusive(output, raw)
            auth.check(); held.check()
            return value
    raise ValueError('startup return deadline expired')


def upload(*, client, report, authorization, inventory, receipt, descriptor, ledger, output, assets, gh, cosign,
           harness_source_sha, run_id, run_attempt, controller_user_id, clock=time.time,
           verifier=provenance.command):
    r.require(report.name == startup.NAME, 'startup upload name differs')
    parent = dispatch._directory(ledger.parent)
    try:
        fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        dispatch.registry_unchanged(parent, ledger.parent)
        with AuthenticatedInputs(authorization=authorization, receipt=receipt, inventory=inventory,
                                 assets=assets, gh=gh, cosign=cosign, verifier=verifier) as auth, HeldFiles() as held:
            held.add(report, startup.MAX_BYTES)
            held.add(ledger, 65536)
            r.require(ledger.name == auth.context['nonce'] + '.json'
                and held.raw(ledger, 65536) == auth.receipt, 'startup durable consumption differs')
            approved = transport.controller_id(controller_user_id)
            owned = _descriptor(held, descriptor, auth, approved, harness_source_sha, run_id, run_attempt)
            raw = held.raw(report, startup.MAX_BYTES)
            value = startup.decode(raw)
            startup.validate_active_payload(value, run=_active(client, auth.context), **_expected(auth))
            auth.bind_report(value)
            actor = client.whoami()
            r.require(type(actor) is dict and type(actor.get('id')) is int and actor['id'] == approved
                and actor.get('type') == 'User' and type(actor.get('login')) is str and actor['login']
                and actor['login'] != 'github-actions[bot]', 'startup controller identity differs')
            when = r.decode(auth.receipt)['consumed_at']
            r.require(when <= value['observed_at'] <= int(clock()) < when + 7200, 'startup upload window expired')
            endpoint = transport.REPO + '/releases/' + str(owned['id'])

            def unchanged():
                auth.check(); held.check(); dispatch.registry_unchanged(parent, ledger.parent)
                transport.check_release(client.request('GET', endpoint), owned)
                r.require(asset(client.request('GET', endpoint + '/assets?per_page=100'), approved, auth.receipt) is None,
                          'startup draft already has a payload')
                _active(client, auth.context)
                r.require(int(clock()) < when + 7200, 'startup upload window expired')

            unchanged()
            intent = dict(schema='elevenid.installer-startup-upload/v1', release_id=owned['id'],
                controller_user_id=approved, nonce=auth.context['nonce'], run_id=run_id, run_attempt=run_attempt,
                startup_sha256=r.digest(raw), startup_size=len(raw), receipt_sha256=r.digest(auth.receipt),
                context_sha256=r.candidate_context_sha256(auth.context))
            receipt_upload.write_registry_intent(parent, auth.context['nonce'] + '.startup.upload-intent.json', r.encode(intent))
            unchanged()
            posted = _startup_asset(client.upload_startup(owned['id'], raw), approved)
            r.require(posted['size'] == len(raw) and posted['digest'] == 'sha256:' + r.digest(raw),
                      'startup upload response differs')
            transport.check_release(client.request('GET', endpoint), owned)
            r.require(asset(client.request('GET', endpoint + '/assets?per_page=100'), approved, auth.receipt) == posted,
                      'startup uploaded asset differs')
            r.require(client.download_startup(posted['id'], posted['size']) == raw, 'startup uploaded bytes differ')
            transport.check_release(client.request('GET', endpoint), owned)
            r.require(asset(client.request('GET', endpoint + '/assets?per_page=100'), approved, auth.receipt) == posted,
                      'startup uploaded asset changed')
            auth.check(); held.check(); dispatch.registry_unchanged(parent, ledger.parent)
            result = dict(intent, asset={key: posted[key] for key in
                ('id','name','size','digest','created_at','updated_at')}, verified_at=int(clock()))
            write_exclusive(output, r.encode(result))
            return result
    finally:
        os.close(parent)


def verify_return(*, client, report, signature_bundle, provenance: Path, inventory, gh, cosign,
                  verifier=None):
    # Keep the public CLI's --provenance spelling without shadowing the module.
    import verify_installer_provenance as verification
    verifier = verification.command if verifier is None else verifier
    r.require(report.name == startup.NAME, 'startup return subject name differs')
    with HeldFiles() as held:
        held.add(report, startup.MAX_BYTES)
        for path in (signature_bundle, provenance): held.add(path, 1048576)
        for suffix in dispatch.SUFFIXES:
            held.add(Path(str(inventory) + suffix), 1048576 if suffix else 65536)
        _tools(held, gh, cosign)
        raw = held.raw(report, startup.MAX_BYTES)
        value = startup.decode(raw)
        inv = held.raw(inventory, 65536)
        expected = dict(inventory_bytes=inv, source_sha=value['source_sha'],
                        release_tag=value['release_tag'], phase=value['phase'])

        def completed():
            run = client.request('GET', transport.REPO + '/actions/runs/' + str(value['run_id']))
            return startup.validate_completed_return(value, run=run, **expected)

        def guarded(argv, **kwargs):
            held.check()
            parents = held.parent_stamps()
            result = verifier(argv, **kwargs)
            held.check(parent_stamps=parents)
            return result

        completed()
        auth = r.decode(value['authority']['authorization'].encode())
        tier, _ = r.classify_release_tag(value['release_tag'])
        workflow = '.github/workflows/nightly-release.yml' if tier == 'nightly' else '.github/workflows/cd.yml'
        verification.verify_subject(inventory, Path(str(inventory) + '.provenance.jsonl'),
            gh=gh, cosign=cosign, signature_bundle=Path(str(inventory) + '.sigstore.json'),
            workflow=workflow, source_sha=value['source_sha'], run_id=auth['build_run_id'],
            run_attempt=auth['build_run_attempt'], runner=guarded)
        verification.verify_subject(report, provenance, gh=gh, cosign=cosign, signature_bundle=signature_bundle,
            workflow=r.acceptance.WORKFLOW, source_sha=value['harness_source_sha'], run_id=value['run_id'],
            run_attempt=value['run_attempt'], runner=guarded)
        completed(); held.check()
        return dict(schema='elevenid.installer-startup-return/v1', startup_sha256=r.digest(raw),
            installation_id=value['scope']['installation_id'], engine_id=value['scope']['engine_id'],
            run_id=value['run_id'], run_attempt=value['run_attempt'], profile=value['profile'],
            startup_observed=True, installation_ready=False, functional_recovery_qualified=False,
            load_characterized=False)
