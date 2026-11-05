"""Forward-only Windows adoption through the existing signed composition owner.

No image pulls, initializers, volume deletion, credential rotation or rollback.
An incomplete/uncertain attempt keeps its project guard; it is never replayed.
"""
from copy import deepcopy
import argparse
import json
import os
from pathlib import Path
import re
import uuid

import selfhost_windows_product as product
import selfhost_windows_product_journal as journal
import selfhost_windows_product_probe as probe
import selfhost_windows_selection as selection
from selfhost_windows_inputs import _held_private_input

renewal = product.renewal
require = selection.require


def qualified_images(docker, before, after, owned):
    """Require already cached exact amd64 subjects and existing volume targets."""
    by_role = {renewal._service(item): item for item in owned}
    roles = set(before['services'])-renewal.INITIALIZERS-product.HISTORICAL_ROLES
    require(set(by_role) == roles | product.HISTORICAL_ROLES)
    result = {};cache = {}
    for role in sorted(roles):
        reference = after['services'][role]['image']
        require(isinstance(reference, str) and product.IMAGE.fullmatch(reference))
        if reference not in cache:
            rows = docker.json(['image', 'inspect', reference])
            require(type(rows) is list and len(rows) == 1)
            image = rows[0]
            require(image.get('Os') == 'linux' and image.get('Architecture') == 'amd64'
                    and isinstance(image.get('Id'), str) and re.fullmatch(r'sha256:[0-9a-f]{64}', image['Id'])
                    and reference in image.get('RepoDigests', []))
            cache[reference] = image
        image = cache[reference]
        targets = image.get('Config', {}).get('Volumes') or {}
        require(type(targets) is dict and all(isinstance(target, str) and target.startswith('/') for target in targets))
        retained = {mount['Destination'] for mount in by_role[role]['Mounts']}
        if role == 'ui':retained -= product.UI_FIXTURE_TARGETS
        require(set(targets) <= retained)
        # An image-only application transition does not qualify database formats.
        if role in {'postgres', 'redis'}:
            require(reference == before['services'][role]['image'] and image['Id'] == by_role[role]['Image'])
        result[role] = image['Id']
    return result


def predicted_edge(owned, before, after, admitted, image_ids, project):
    """Predict only the storage fingerprint; actual post-state is proved later."""
    predicted = deepcopy(owned)
    change = product.checked_model_change(before, after, admitted)
    for item in predicted:
        role = renewal._service(item)
        if role not in change['mutable_roles']:continue
        item['Image'] = image_ids[role]
        item['Config']['Image'] = after['services'][role]['image']
        if role == 'ui':
            item['Mounts'] = [mount for mount in item['Mounts'] if mount['Destination'] not in product.UI_FIXTURE_TARGETS]
    return product.checked_runtime_change(owned, predicted, before, after, admitted, image_ids, expected_project=project)


def _copy_subject(path, body, maximum, stack):
    """Retain original binary subjects, fsynced before any runtime operation."""
    require(isinstance(body, bytes) and 0 < len(body) <= maximum)
    with path.open('xb') as output:
        require(output.write(body) == len(body));output.flush();os.fsync(output.fileno())
    require(stack.enter_context(renewal.hold_private_input(path, max_bytes=maximum)) == body)


def start(config, choice, values, record, raw, source, assets, *, gh, cosign, registry_config, stack):
    """Called by the selected lease under its project lock; never standalone.

    Fresh verification consumes the original six subjects. Local retained
    admission receipts are evidence of this call, never verifier substitutes.
    """
    require(os.name == 'nt' and not renewal.recovery_pending(config)
            and journal.INTENT not in raw and journal.DECISION not in raw)
    assets = Path(assets)
    require(assets.is_absolute())
    stack.enter_context(renewal.hold_storage_namespace(assets))
    stack.enter_context(_held_private_input(assets, directory=True))
    require({path.name for path in assets.iterdir()} == journal.ARTIFACTS)
    bodies = {}
    for name in sorted(journal.ARTIFACTS):
        maximum = 256*1024*1024 if name == 'web-composition.zip' else 4*1024*1024
        bodies[name] = stack.enter_context(renewal.hold_private_input(assets/name, max_bytes=maximum))
    admitted, _payload = stack.enter_context(product.composition.verified_package(assets,
        gh=Path(gh), cosign=Path(cosign), registry_config=Path(registry_config)))
    old_raw = stack.enter_context(renewal.hold_private_input(Path(config['compose_file']), max_bytes=2*1024*1024))
    require(selection.digest(old_raw) == config['compose_sha256'])
    old = selection.decode(old_raw);new = product.product_model(old, admitted)
    change = product.checked_model_change(old, new, admitted)
    observed = selection._inspect(config, choice, values, stack, expected_data=record['data_sha256'])
    docker = observed['docker'];owned = observed['owned'];roles = observed['services']
    require(roles == set(old['services'])-renewal.INITIALIZERS)
    ids = qualified_images(docker, old, new, owned)
    edge = predicted_edge(owned, old, new, admitted, ids, config['project'])
    require(edge['before_sha256'] == record['data_sha256'])
    schema_before = selection.packed(probe.schema_snapshot(docker, owned, config['project']))
    provider_before = selection.packed(probe.provider_snapshot(docker, owned, config['project'], config['native']['ca_file']))
    cycle = uuid.uuid4().hex;parent = Path(config['current_secrets']).parent
    root = parent/('windows-product-'+cycle)
    target = parent/('.'+config['project']+'.generation-product-'+cycle)
    new_path = Path(config['compose_file']).with_name('product-'+cycle+'.compose.json')
    require(not any(renewal.namespace_entry_exists(path) for path in (root, target, new_path)))
    with _held_private_input(parent, directory=True):pass
    with _held_private_input(new_path.parent, directory=True):pass
    root.mkdir();stack.enter_context(renewal.hold_storage_namespace(root))
    with _held_private_input(root, directory=True):pass
    selection._new_private(new_path, selection.packed(new))
    require(stack.enter_context(renewal.hold_private_input(new_path, max_bytes=2*1024*1024)) == selection.packed(new))
    binding = {'compose_file': str(new_path), 'compose_sha256': selection.digest(selection.packed(new))}
    successor = journal.successor_configuration(config, binding, root)
    selection._new_private(root/'config.private.json', selection.packed(successor))
    stack.enter_context(renewal.hold_private_input(root/'config.private.json'))
    for name in ('inputs', 'activation'):
        (root/name).mkdir()
        with _held_private_input(root/name, directory=True):pass
    for name, body in bodies.items():
        _copy_subject(root/'inputs'/name, body, 256*1024*1024 if name == 'web-composition.zip' else 4*1024*1024, stack)
    outputs = [Path(successor[key]) for key in ('intent', 'result', 'new_log', 'rollback_log')]
    outputs += [Path(path) for step in successor['step_receipts'] for path in step.values()]
    for path in outputs:selection._new_private(path, b'')
    for name in ('inputs', 'activation'):stack.enter_context(_held_private_input(root/name, directory=True))
    prefix = 'renewed' if choice == 'new' else 'current'
    command = docker.compose(config['project'], Path(config[prefix+'_env']), new_path)
    normalized = docker.json(command[len(docker.prefix):]+['--profile', '*', 'config', '--format', 'json'])
    product.checked_model_change(observed['model'], normalized, admitted)
    layers = renewal.dependency_layers(normalized, roles, set(change['mutable_roles']))
    hashes = {'old': docker.hashes(observed['command']), 'new': docker.hashes(command)}
    hashes = {side: {role: entries[role] for role in ids} for side, entries in hashes.items()}
    context = product.ProductContext(docker, config['project'], observed['baseline'], docker.volumes(),
        config['native']['helper_image'], old_model=old, new_model=new, admitted=admitted,
        image_ids=ids, configuration_hashes=hashes)
    expected = selection.decode(raw['owner.json'])['binding']
    _first, anchored, generation = journal.anchor(raw, expected)
    require(anchored == record)
    marker = {'schema': journal.SCHEMA, 'project': config['project'], 'engine_id': config['engine_id'],
        'source_dir': str(source), 'target_dir': str(target),
        'source_sha256': {name: selection.digest(body) for name, body in raw.items()},
        'selection_sequence': record['sequence'], 'generation_sequence': generation,
        'selection_sha256': selection.digest(raw[f'{record["sequence"]:06}.selection.json']),
        'selected_sha256': selection.digest(selection.packed(record['selected'])),
        'old': {'compose_file': config['compose_file'], 'compose_sha256': config['compose_sha256']}, 'new': binding,
        'attempt_dir': str(root), 'config_sha256': selection.digest(selection.packed(successor)),
        'composition_sha256': {name: selection.digest(body) for name, body in bodies.items()},
        'image_ids': ids, 'configuration_hashes': hashes, 'data_before_sha256': edge['before_sha256'],
        'data_after_sha256': edge['after_sha256'], 'observations_before_sha256': selection.digest(selection.packed(owned)),
        'schema_before_sha256': selection.digest(schema_before), 'provider_before_sha256': selection.digest(provider_before),
        'native': expected['native'], 'native_mirror': record['selected']['native_mirror'],
        'minimum_ttl': config['native']['minimum_ttl'], 'candidate_only': True}
    names = journal.PHASES | {f'{index:03}.{event}.json' for index in range(len(layers)) for event in ('started', 'completed')}
    for name in names:selection._new_private(root/name, b'')
    def write(name, body):
        renewal.write_empty_private_file(root/name, body.decode())
        require(stack.enter_context(renewal.hold_private_input(root/name, max_bytes=2*1024*1024)) == body)
    write('intent.json', selection.packed(marker))
    write('before.json', selection.packed(owned))
    write('schema-before.json', schema_before);write('provider-before.json', provider_before)
    write('admission.json', selection.packed({'schema': journal.SCHEMA, 'composition_id': admitted['composition_id'],
        'subjects_verified': True, 'images_verified': True}))
    context.check(before_intent=True)
    selection._append(source, raw, journal.INTENT, marker, stack)
    journal.validate_marker(raw, expected, marker['old'], source)
    guard = renewal.product_transition_guard(config)
    selection._new_private(guard, selection.packed(marker))
    require(stack.enter_context(renewal.hold_private_input(guard)) == selection.packed(marker))
    authority = '/control/recovery-session-'+cycle+'/token'
    def native(side):
        receipt = {'schema': journal.SCHEMA, 'operation': 'native-current', 'side': side,
            'native': marker['native'], 'native_mirror': marker['native_mirror'],
            'minimum_ttl': marker['minimum_ttl'], 'selected_sha256': marker['selected_sha256']}
        write('native-'+side+'.started.json', selection.packed(dict(receipt, event='started')))
        context.check()
        if side == 'before':
            from selfhost_windows_renewal_native import reauthenticate
            require(reauthenticate(config['native'], config['project'], docker.prefix, authority.rsplit('/', 1)[0]) == authority)
        selection._native_current(config, choice, values, docker, authority)
        context.check()
        write('native-'+side+'.completed.json', selection.packed(dict(receipt, event='completed')))
    native('before')
    def progress(event, index, layer):
        require(layer == layers[index] and event in {'started', 'completed'})
        context.check()
        write(f'{index:03}.{event}.json', selection.packed({'index': index, 'roles': layer, 'event': event}))
        context.check()
    renewal.recreate(docker, command, set(change['mutable_roles']), roles, normalized, root/'new.log', progress=progress)
    after = context.check()
    after_owned = [item for item in after if renewal._project(item) == config['project']]
    require(product.checked_runtime_change(owned, after_owned, old, new, admitted, ids,
        expected_project=config['project']) == edge)
    write('after.json', selection.packed(after_owned))
    require(renewal.windows_healthy(renewal.statuses(command, cwd=new_path.parent), roles, normalized))
    schema_after = selection.packed(probe.schema_snapshot(docker, after_owned, config['project']))
    provider_after = selection.packed(probe.provider_snapshot(docker, after_owned, config['project'], config['native']['ca_file']))
    require(schema_after == schema_before and provider_after == provider_before)
    write('schema-after.json', schema_after);write('provider-after.json', provider_after)
    native('after')
    write('result.json', selection.packed({'schema': journal.SCHEMA, 'project': config['project'],
        'result': 'product-transitioned', 'generation_sequence': generation, 'selected_sha256': marker['selected_sha256'],
        'data_sha256': edge['after_sha256'], 'composition_id': admitted['composition_id'], 'credential_rotation': False}))
    phase_hashes = {name: selection.digest(stack.enter_context(renewal.hold_private_input(root/name, max_bytes=2*1024*1024)))
                    for name in names}
    journal.hold_transition(marker, phase_hashes, stack)
    return {'marker': marker, 'phases': phase_hashes, 'authority_file': authority,
            'result': {'result': 'product-transitioned', 'credential_rotation': False, 'candidate_only': True}}


def deploy_once(config_path, assets, *, gh, cosign, registry_config):
    """One explicit forward attempt. Publication occurs on the held lease exit."""
    with selection.selected_inputs(config_path) as lease:
        result = lease.transition_product(assets, gh=gh, cosign=cosign, registry_config=registry_config)
    state = selection.status(config_path)
    require(state['state'] == 'selected' and state['decision'].startswith('product-selected-'))
    return dict(result, result='product-selected', generation_sequence=state['generation_sequence'])


def reconcile_once(config_path, *, authority_file):
    """Publish only a completely executed attempt; never repeat any operation.

    The caller must supply an existing supported scoped authority. Expired
    authority and missing phase completions require operator recovery, not an
    automatic mint, initializer, rollback or Compose replay.
    """
    with renewal.hold_private_input(Path(config_path)) as body:
        cfg = selection.decode(body)
        guard = renewal.product_transition_guard(cfg)
        with renewal.hold_private_input(guard) as marker_raw:pass
    sha = selection.digest(marker_raw)
    with selection._session(config_path, _pending_product_sha256=sha) as (_cfg, _body, expected, source, raw, stack):
        from selfhost_windows_model import history
        _intents, records = selection._parse(raw, expected)
        marker = journal.validate_marker(raw, expected, history(raw, expected, records)[1], source)
        require(marker_raw == selection.packed(marker))
        root = Path(marker['attempt_dir'])
        stack.enter_context(renewal.hold_storage_namespace(root))
        stack.enter_context(_held_private_input(root, directory=True))
        names = {path.name for path in root.iterdir()}-{'inputs', 'activation', 'config.private.json'}
        require(journal.PHASES <= names and len(names) <= 512
                and all(name in journal.PHASES or re.fullmatch(r'[0-9]{3}\.(?:started|completed)\.json', name) for name in names))
        phases = {name: selection.digest(stack.enter_context(renewal.hold_private_input(root/name, max_bytes=2*1024*1024)))
                  for name in names}
        journal.hold_transition(marker, phases, stack)
    return journal.finish(config_path, marker, phases, authority_file=authority_file)


def main(argv=None):
    class PrivateParser(argparse.ArgumentParser):
        def error(self, _message):raise ValueError('Invalid Windows product arguments')
    parser = PrivateParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    for name in ('assets', 'gh', 'cosign', 'registry-config'):
        parser.add_argument('--'+name, type=Path)
    parser.add_argument('--reconcile', action='store_true')
    parser.add_argument('--authority-file', help='existing scoped token path inside the private control volume')
    try:
        args = parser.parse_args(argv)
        forward = (args.assets, args.gh, args.cosign, args.registry_config)
        if args.reconcile:
            require(args.authority_file is not None and not any(forward))
            result = reconcile_once(args.config, authority_file=args.authority_file)
        else:
            require(all(forward) and args.authority_file is None)
            result = deploy_once(args.config, args.assets, gh=args.gh, cosign=args.cosign, registry_config=args.registry_config)
    except Exception:
        raise SystemExit('Windows product transition refused; preserve the pending guard and private receipts for operator reconciliation') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':main()
