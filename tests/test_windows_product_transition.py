"""Admitted-product planning boundaries; no runtime or release publication."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys

import pytest

sys.path[:0] = [str(Path(__file__).resolve().parents[1]/'scripts'), str(Path(__file__).resolve().parent)]
import selfhost_windows_product as product
from test_selfhost_windows_renewal import model


def candidate(tmp_path):
    before = model(tmp_path)
    before['services']['ui'] = {'image': 'nginx@sha256:'+'1'*64, 'environment': {'ORIGIN': 'https://example.invalid'},
        'volumes': [
            {'type': 'bind', 'source': 'C:/synthetic/dist', 'target': '/opt/marty-ui-static', 'read_only': True},
            './ui/nginx.spa.conf:/etc/nginx/conf.d/default.conf:ro',
            './scripts/load-secrets-env.sh:/scripts/load-secrets-env.sh:ro',
            './scripts/ui-selfhost-start.sh:/docker-entrypoint.d/40-ui-selfhost.sh:ro']}
    images = {role: 'example.invalid/'+role+'@sha256:'+'2'*64 for role in before['services']
              if role not in product.PROVIDER_ROLES}
    admitted = {'schema': product.composition.SCHEMA, 'platform': 'linux/amd64', 'kms_provider': 'openbao',
        'production_pages': 'full', 'images': images, 'openbao_didcomm_image': 'example.invalid/bao@sha256:'+'3'*64,
        'application': {'image': {'uri': images['ui'].split('@')[0], 'digest': 'sha256:'+'2'*64, 'platform': 'linux/amd64'}}}
    return before, admitted


def test_exact_image_update_replaces_local_ui_code_but_preserves_all_other_inputs(tmp_path):
    before, admitted = candidate(tmp_path);saved = deepcopy(before)
    after = product.product_model(before, admitted)
    assert before == saved
    assert after['secrets'] == before['secrets']
    for role, original in before['services'].items():
        changed = deepcopy(after['services'][role]);changed['image'] = original['image']
        if role == 'ui':changed['volumes'] = original['volumes']
        assert changed == original
    change = product.checked_model_change(before, after, admitted)
    assert set(change['mutable_roles']).isdisjoint(product.HISTORICAL_ROLES | product.renewal.INITIALIZERS)
    assert change['historical_roles'] == ['openbao-tls-init']
    assert 'openbao' in change['mutable_roles'] and 'ui' in change['mutable_roles']


@pytest.mark.parametrize('fault', ['missing', 'extra', 'tag', 'provider-tag', 'app-digest', 'platform', 'audience'])
def test_unbound_or_incomplete_product_inputs_are_refused(tmp_path, fault):
    before, admitted = candidate(tmp_path)
    if fault == 'missing':admitted['images'].pop('gateway')
    elif fault == 'extra':admitted['images']['extra'] = 'example.invalid/x@sha256:'+'2'*64
    elif fault == 'tag':admitted['images']['gateway'] = 'example.invalid/gateway:latest'
    elif fault == 'provider-tag':admitted['openbao_didcomm_image'] = 'example.invalid/bao:latest'
    elif fault == 'app-digest':admitted['application']['image']['digest'] = 'sha256:'+'4'*64
    elif fault == 'platform':admitted['platform'] = 'linux/arm64'
    else:admitted['production_pages'] = 'public'
    with pytest.raises(ValueError):product.product_model(before, admitted)


@pytest.mark.parametrize('fault', ['rw-long', 'rw-short', 'partial', 'duplicate'])
def test_ui_fixture_removal_never_hides_writable_or_ambiguous_mounts(tmp_path, fault):
    before, admitted = candidate(tmp_path);mounts = before['services']['ui']['volumes']
    if fault == 'rw-long':mounts[0]['read_only'] = False
    elif fault == 'rw-short':mounts[1] = mounts[1].removesuffix(':ro')+':rw'
    elif fault == 'partial':mounts.pop()
    else:mounts.append(deepcopy(mounts[0]))
    with pytest.raises(ValueError):product.product_model(before, admitted)


@pytest.mark.parametrize('source', ['customer_config', 'C:/unrecognized/config', '../other/config'])
def test_read_only_target_does_not_authorize_removing_another_fixture_source(tmp_path, source):
    before, admitted = candidate(tmp_path)
    before['services']['ui']['volumes'][1] = source+':/etc/nginx/conf.d/default.conf:ro'
    with pytest.raises(ValueError):product.product_model(before, admitted)


@pytest.mark.parametrize('field', ['environment', 'ports', 'volumes', 'secrets', 'networks'])
def test_admitted_images_do_not_authorize_other_model_mutations(tmp_path, field):
    before, admitted = candidate(tmp_path);after = product.product_model(before, admitted)
    after['services']['gateway'][field] = {'UNAUTHORIZED': True}
    with pytest.raises(ValueError):product.checked_model_change(before, after, admitted)


def test_unrelated_ui_mounts_and_packaged_ui_shape_are_preserved(tmp_path):
    before, admitted = candidate(tmp_path)
    extra = {'type': 'bind', 'source': 'C:/synthetic/user-data', 'target': '/user-data', 'read_only': False}
    before['services']['ui']['volumes'].append(extra)
    after = product.product_model(before, admitted)
    assert after['services']['ui']['volumes'] == [extra]
    assert product.product_model(after, admitted) == after


def test_migration_fingerprints_bind_real_git_blobs_and_detect_new_unicode_sql(tmp_path):
    def git(*args):
        return subprocess.run(['git', '-C', str(tmp_path), *args], capture_output=True,
                              encoding='utf-8', check=True, timeout=30).stdout.strip()
    git('init');git('config', 'user.name', 'Synthetic Test');git('config', 'user.email', 'synthetic@example.invalid')
    for name in product.MIGRATION_INPUTS:
        path = tmp_path/name;path.parent.mkdir(parents=True, exist_ok=True);path.write_text('SYNTHETIC', encoding='utf-8')
    path = tmp_path/'rust/services/example/migrations/001.sql';path.parent.mkdir(parents=True);path.write_text('SELECT 1;', encoding='utf-8')
    git('add', '.');git('-c', 'commit.gpgsign=false', 'commit', '-m', 'Synthetic baseline')
    first = product.migration_sources(tmp_path, git('rev-parse', 'HEAD'))
    (tmp_path/'README.md').write_text('Unrelated source documentation', encoding='utf-8')
    git('add', '.');git('-c', 'commit.gpgsign=false', 'commit', '-m', 'Unrelated documentation')
    assert product.migration_sources(tmp_path, git('rev-parse', 'HEAD'))['sha256'] == first['sha256']
    new = path.parent/'002-\u00fc.sql';new.write_text('ALTER TABLE synthetic ADD COLUMN x int;', encoding='utf-8')
    git('add', '.');git('-c', 'commit.gpgsign=false', 'commit', '-m', 'New migration')
    changed = product.migration_sources(tmp_path, git('rev-parse', 'HEAD'))
    assert changed['sha256'] != first['sha256'] and new.relative_to(tmp_path).as_posix() in changed['files']


def runtime_candidate(tmp_path):
    old_model, admitted = candidate(tmp_path)
    new_model = product.product_model(old_model, admitted)
    before = []
    for index, role in enumerate(sorted(set(old_model['services'])-product.renewal.INITIALIZERS), 1):
        before.append({'Id': f'{index:064x}', 'Image': 'sha256:'+'1'*64,
            'Config': {'Labels': {'com.docker.compose.project': 'marty-production-synthetic',
                                 'com.docker.compose.service': role}},
            'Mounts': [{'Type': 'volume', 'Name': role+'-data', 'Source': '/data/'+role,
                        'Destination': '/data', 'RW': True},
                       {'Type': 'bind', 'Source': 'C:/synthetic/token',
                        'Destination': '/run/secrets/token', 'RW': False}]})
    ui = next(item for item in before if product.renewal._service(item) == 'ui')
    ui['Mounts'].extend({'Type': 'bind', 'Source': 'C:/synthetic/code'+str(index),
                         'Destination': target, 'RW': False}
                        for index, target in enumerate(sorted(product.UI_FIXTURE_TARGETS)))
    after = deepcopy(before)
    image_ids = {product.renewal._service(item): 'sha256:'+'2'*64 for item in before
                 if product.renewal._service(item) not in product.HISTORICAL_ROLES}
    for item in after:
        role = product.renewal._service(item)
        if role in product.HISTORICAL_ROLES:continue
        item['Image'] = image_ids[role]
        item['Id'] = 'f'+item['Id'][1:]
        if role == 'ui':item['Mounts'] = [m for m in item['Mounts'] if m['Destination'] not in product.UI_FIXTURE_TARGETS]
    return before, after, old_model, new_model, admitted, image_ids


def test_runtime_edge_preserves_data_and_credentials_with_historical_initializer(tmp_path):
    import selfhost_windows_selection as selection
    args = runtime_candidate(tmp_path)
    result = product.checked_runtime_change(*args)
    assert result['before_sha256'] == selection.digest(selection.packed(product.renewal.data_mounts(args[0])))
    assert result['after_sha256'] == selection.digest(selection.packed(product.renewal.data_mounts(args[1])))
    assert result['before_sha256'] != result['after_sha256'] and result['ui_fixture_mounts_removed']


@pytest.mark.parametrize('fault', ['storage', 'credential', 'image', 'initializer', 'missing-role',
                                  'extra-role', 'duplicate-role', 'project', 'duplicate-mount',
                                  'rw-fixture', 'missing-fixture', 'extra-image-id', 'missing-image-id'])
def test_runtime_edge_refuses_unqualified_or_unpreserved_state(tmp_path, fault):
    before, after, old, new, admitted, ids = runtime_candidate(tmp_path)
    gateway = next(item for item in after if product.renewal._service(item) == 'gateway')
    if fault == 'storage':gateway['Mounts'][0]['Name'] = 'other-data'
    elif fault == 'credential':gateway['Mounts'][1]['Source'] = 'C:/other/token'
    elif fault == 'image':gateway['Image'] = 'sha256:'+'3'*64
    elif fault == 'initializer':next(item for item in after if product.renewal._service(item) == 'openbao-tls-init')['Id'] = 'a'*64
    elif fault == 'missing-role':after.pop()
    elif fault == 'extra-role':
        extra = deepcopy(gateway);extra['Config']['Labels']['com.docker.compose.service'] = 'unknown';after.append(extra)
    elif fault == 'duplicate-role':after.append(deepcopy(gateway))
    elif fault == 'project':gateway['Config']['Labels']['com.docker.compose.project'] = 'other'
    elif fault == 'duplicate-mount':gateway['Mounts'].append(deepcopy(gateway['Mounts'][0]))
    elif fault in {'rw-fixture', 'missing-fixture'}:
        ui = next(item for item in before if product.renewal._service(item) == 'ui')
        if fault == 'rw-fixture':ui['Mounts'][-1]['RW'] = True
        else:ui['Mounts'].pop()
    elif fault == 'extra-image-id':ids['unknown'] = 'sha256:'+'2'*64
    else:ids.pop('gateway')
    with pytest.raises(ValueError):product.checked_runtime_change(before, after, old, new, admitted, ids)


@pytest.mark.parametrize('field', ['entrypoint', 'command'])
def test_local_ui_startup_override_is_not_carried_into_packaged_ui(tmp_path, field):
    before, admitted = candidate(tmp_path)
    before['services']['ui'][field] = ['unqualified-startup']
    with pytest.raises(ValueError):product.product_model(before, admitted)
