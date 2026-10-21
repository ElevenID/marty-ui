"""Concrete data-equivalence and production-isolation recovery boundaries."""
from pathlib import Path
import io
import runpy
import tarfile

import pytest

MODULE = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'scripts/recover_unchanged_beta_cutover.py'))


def test_dump_normalization_preserves_data_comments_and_inner_nonce_text():
    normalize = MODULE['normalized_dump']
    prefix = b'\\restrict ' + b'a' * 64 + b'\n'
    suffix = b'\\unrestrict ' + b'a' * 64 + b'\n'
    body = b'-- database comment\nCOPY t FROM stdin;\n--real-data\n\\\\restrict embedded\n\\.\n'
    other = prefix.replace(b'a' * 64, b'b' * 64) + body + suffix.replace(b'a' * 64, b'b' * 64)
    assert normalize(prefix + body + suffix) == normalize(other)
    assert normalize(prefix + body.replace(b'--real-data', b'--changed-data') + suffix) != normalize(other)
    assert b'-- database comment' in normalize(other)
    assert b'\\\\restrict embedded' in normalize(other)


@pytest.mark.parametrize('mutation', ['production', 'different_image', 'running'])
def test_unchanged_container_recovery_rejects_foreign_or_changed_state(mutation):
    record = {'service': 'auth', 'container_id': 'a' * 64, 'image_id': 'sha256:' + 'b' * 64}
    current = {'Id': record['container_id'], 'Image': record['image_id'], 'State': {'Running': False},
               'Config': {'Labels': {'com.docker.compose.project': 'elevenid-beta',
                                      'com.docker.compose.service': 'auth'}}}
    if mutation == 'production':
        current['Config']['Labels']['com.docker.compose.project'] = 'marty-selfhost-prod'
    elif mutation == 'different_image':
        current['Image'] = 'sha256:' + 'c' * 64
    else:
        current['State']['Running'] = True
    with pytest.raises(RuntimeError):
        MODULE['check_container'](record, current)


def archive(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as stream:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o600
            stream.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def snapshot(state):
    return archive({'meta.json': b'{"Index":1}', 'state.bin': state,
                    'SHA256SUMS': b'fixture', 'SHA256SUMS.sealed': b'sealed fixture'})


@pytest.mark.parametrize('mutation', ['none', 'redis_dirty', 'redis_snapshot', 'kms_state', 'kms_custody'])
def test_recovery_auxiliary_proof_requires_unchanged_redis_and_all_kms_custody(tmp_path, monkeypatch, mutation):
    proof = MODULE['verify_auxiliary_state']
    backup = tmp_path / 'backup'
    backup.mkdir()
    (backup / 'redis-dump.rdb').write_bytes(b'original redis state')
    (backup / 'openbao-raft.snap').write_bytes(snapshot(b'original KMS state including keys and tokens'))
    custody = archive({'root.token': b'unit fixture only', 'tls/ca.crt': b'original CA'})
    (backup / 'openbao-data.tar.gz').write_bytes(custody)
    rows = [{'service': service, 'container_id': service, 'volume_name': service + '-data'}
            for service in ['redis', 'openbao']]

    def observe(container):
        return {'Id': container, 'State': {'Running': True}, 'Config': {'Labels': {
            'com.docker.compose.project': 'elevenid-beta', 'com.docker.compose.service': container}},
            'Mounts': [{'Type': 'volume', 'Name': container + '-data'}]}

    def transport(*args):
        assert args[0] not in ['start', 'stop'], 'State proof must not change service lifecycle'
        if 'INFO persistence' in args[-1]:
            dirty = '1' if mutation == 'redis_dirty' else '0'
            return ('loading:0\nrdb_changes_since_last_save:' + dirty
                    + '\nrdb_bgsave_in_progress:0\naof_rewrite_in_progress:0\n').encode()
        if args[0] == 'cp':
            if args[1].endswith('/data/dump.rdb'):
                return archive({'dump.rdb': b'changed' if mutation == 'redis_snapshot' else b'original redis state'})
            name = args[1].rsplit('/', 1)[1]
            return archive({name: snapshot(b'changed' if mutation == 'kms_state' else b'original KMS state including keys and tokens')})
        if args[0] == 'run':
            return archive({'root.token': b'changed', 'tls/ca.crt': b'original CA'}) if mutation == 'kms_custody' else custody
        return b''

    monkeypatch.setitem(proof.__globals__, 'inspect', observe)
    monkeypatch.setitem(proof.__globals__, 'docker', transport)
    if mutation == 'none':
        result = proof({'state_volumes': rows}, tmp_path)
        assert result['redisUnsnapshottedChanges'] == 0
        assert result['openBaoStaticCustodyUnchanged'] is True
    else:
        with pytest.raises(RuntimeError, match='Redis|OpenBao'):
            proof({'state_volumes': rows}, tmp_path)


def test_recovery_archive_rejects_custody_links():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as stream:
        link = tarfile.TarInfo('tls/ca.crt')
        link.type, link.linkname = tarfile.SYMTYPE, '/outside'
        stream.addfile(link)
    with pytest.raises(RuntimeError, match='state archive member'):
        MODULE['archive_inventory'](buffer.getvalue())
