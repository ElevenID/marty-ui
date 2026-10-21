"""Concrete data-equivalence and production-isolation recovery boundaries."""
from pathlib import Path
import runpy

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
