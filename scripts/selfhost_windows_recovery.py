"""Start existing managed-candidate IDs while its selection lease remains held.

No task installation, initialization, creation, recreation, restart,
image pulls or public routing. Failed/uncertain attempts retain their guard and
receipts for operator reconciliation; they are never automatically replayed.
"""
import argparse
import os
import re
import sys
import time
import uuid
from contextlib import ExitStack
from pathlib import Path

import selfhost_windows_renewal as renewal
import selfhost_windows_selection as selection
from selfhost_windows_inputs import _held_private_input

SCHEMA = 'marty.windows-existing-recovery/v1'
COMPLETED = renewal.COMPLETED_SERVICES | {'openbao-tls-init'}
PREPARATION_SCHEMA = 'marty.windows-existing-stop/v1'
STOP_COMPLETION_SCHEMA = 'marty.windows-existing-stop-completion/v1'


def _prepared_stop(config, observed, record, root, stack, expected):
    """Validate an explicit completed-stop handoff; never infer CLI completion."""
    marker = renewal.recovery_preparation_guard(config)
    selection.require(type(expected) is str and re.fullmatch(r'[0-9a-f]{64}', expected))
    with renewal.hold_private_input(marker) as raw:
        selection.require(selection.digest(raw) == expected)
        value = selection.decode(raw)
        selection.require(set(value) == {'schema', 'project', 'engine_id', 'sequence', 'compose_sha256',
            'data_sha256', 'output_dir', 'targets', 'preserved', 'protected_sha256', 'completion_file'})
        selection.require(value['schema'] == PREPARATION_SCHEMA and value['project'] == config['project']
            and value['engine_id'] == config['engine_id'] and type(value['sequence']) is int
            and value['sequence'] == record['sequence'] and value['compose_sha256'] == config['compose_sha256']
            and value['data_sha256'] == record['data_sha256'] and value['output_dir'] == str(root))
        by_role = {renewal._service(x): x for x in observed['owned']}
        targets = {r: x['Id'] for r, x in by_role.items() if r not in COMPLETED}
        preserved = {r: x['Id'] for r, x in by_role.items() if r in COMPLETED}
        selection.require(value['targets'] == targets and value['preserved'] == preserved)
        selection.require(all(by_role[r]['State']['Status'] == 'exited' for r in targets))
        protected = renewal.observations(observed['baseline'], config['project'], set(targets))
        selection.require(value['protected_sha256'] == selection.digest(selection.packed(protected)))
        completion = Path(value['completion_file'])
        selection.require(completion.is_absolute() and completion.name == 'completed.json'
            and completion.parent.parent == root.parent and completion.parent.name.startswith('windows-stop-'))
        stop_raw = stack.enter_context(renewal.hold_private_input(completion))
        stopped = selection.decode(stop_raw)
        selection.require(stopped == {'schema': STOP_COMPLETION_SCHEMA, 'preparation_sha256': expected,
            'stop_cli_returned': True, 'stopped_ids': targets, 'preserved_ids': preserved})
        selection.require(stopped['stop_cli_returned'] is True)
    return ({'marker_sha256': expected, 'completion_file': str(completion),
             'completion_sha256': selection.digest(stop_raw),
             'preparation_copy': 'preparation.json', 'completion_copy': 'stop-completed.json'}, raw, stop_raw)


def plan(observed):
    owned = observed['owned'];services = observed['services'];model = observed['model']
    by_role = {renewal._service(x): x for x in owned}
    selection.require(len(by_role) == len(owned) and set(by_role) == services)
    for role, item in by_role.items():
        selection.require(re.fullmatch(r'[0-9a-f]{64}', item['Id']))
        state = item['State']['Status']
        if role in COMPLETED:
            selection.require(state == 'exited' and item['State']['ExitCode'] == 0)
        else:
            selection.require(state in {'created', 'exited', 'running', 'restarting'})
    running = services - COMPLETED
    selection.require({'openbao', 'openbao-unseal'} <= running)
    renewal.dependency_layers(model, services, running)
    foundation = ['openbao', 'openbao-unseal']
    bao_dependencies = model['services']['openbao'].get('depends_on', {})
    selection.require(set(bao_dependencies) <= COMPLETED)
    selection.require(all(spec.get('condition') == 'service_completed_successfully'
                          for spec in bao_dependencies.values()))
    unseal_dependencies = model['services']['openbao-unseal'].get('depends_on', {})
    selection.require(set(unseal_dependencies) <= {'openbao'} | COMPLETED)
    selection.require(all(spec.get('condition') == ('service_started' if role == 'openbao'
                          else 'service_completed_successfully') for role, spec in unseal_dependencies.items()))
    application = running - set(foundation)
    selection.require(application)
    layers = [foundation, *renewal.dependency_layers(model, services, application)]
    selection.require(set(x for layer in layers for x in layer) == running)
    return by_role, layers


def _unchanged(observed, current, started):
    project = renewal._project(observed['owned'][0])
    owned = [x for x in current if renewal._project(x) == project]
    selection.require({renewal._service(x): x['Id'] for x in owned}
                      == {renewal._service(x): x['Id'] for x in observed['owned']})
    selection.require(renewal.data_mounts(owned) == renewal.data_mounts(observed['owned']))
    selection.require(renewal.observations(current, project, started)
                      == renewal.observations(observed['baseline'], project, started))
    # Config/secret mount identity is also preserved for started IDs; the only
    # permitted changes are runtime state/start time/restart count for those IDs.
    for original in observed['owned']:
        item = next(x for x in owned if x['Id'] == original['Id'])
        selection.require(item['Config'] == original['Config']
                          and renewal.canonical_mounts(item['Mounts']) == renewal.canonical_mounts(original['Mounts']))


def _ready(observed, selected, deadline):
    while True:
        selection.require(time.monotonic() < deadline)
        items = renewal.statuses(observed['command'], cwd=observed['cwd'])
        selection.require(time.monotonic() < deadline)
        selection.require(len(items) == len(observed['services'])
                          and {x['Service'] for x in items} == observed['services'])
        checked = [x for x in items if x['Service'] in selected]
        if renewal.windows_healthy(checked, selected, observed['model']):
            return
        for item in checked:
            state = item['State'].lower()
            if item['Service'] in COMPLETED:
                selection.require(state == 'exited' and item.get('ExitCode') == 0)
            else:
                selection.require(state in {'running', 'restarting'})
        time.sleep(2)


def start_existing(config, choice, values, record, output_dir, stack, *, authority_file=None,
                   preparation_sha256=None, fresh_authority=False):
    """Return a provisional result; publication follows ALL selection exit checks."""
    selection.require(os.name == 'nt')
    selection.require(type(fresh_authority) is bool and not (fresh_authority and authority_file is not None))
    session_dir='/control/recovery-session-'+uuid.uuid4().hex if fresh_authority else None
    guard = renewal.recovery_guard(config)
    selection.require(not renewal.namespace_entry_exists(guard))
    has_preparation = renewal.namespace_entry_exists(renewal.recovery_preparation_guard(config))
    selection.require(has_preparation == (preparation_sha256 is not None))
    root = Path(output_dir)
    generation_root = Path(config['current_secrets']).parent
    selection.require(root.is_absolute() and root.parent == generation_root and root.name.startswith('windows-recovery-'))
    stack.enter_context(renewal.hold_storage_namespace(root))
    with _held_private_input(root, directory=True):pass
    selection.require(not list(root.iterdir()))
    observed = selection._inspect(config, choice, values, stack,
                                  expected_data=record['data_sha256'], require_ready=False)
    by_role, layers = plan(observed)
    preparation = None;preparation_raw = None;stop_raw = None
    if has_preparation:
        preparation, preparation_raw, stop_raw = _prepared_stop(config, observed, record, root, stack, preparation_sha256)
    docker = observed['docker'];project = config['project']
    names = ['intent.json', 'result.json', 'diagnostic.private.log']
    if preparation is not None:names.extend(['preparation.json', 'stop-completed.json'])
    for index in range(len(layers)):
        names.extend([f'{index:03}.started.json', f'{index:03}.completed.json'])
    for name in names:
        with (root/name).open('xb'):pass
    if preparation is not None:
        renewal.write_empty_private_file(root/'preparation.json', preparation_raw.decode())
        renewal.write_empty_private_file(root/'stop-completed.json', stop_raw.decode())
        stack.enter_context(renewal.hold_private_input(root/'preparation.json'))
        stack.enter_context(renewal.hold_private_input(root/'stop-completed.json'))
    intent = {'schema': SCHEMA, 'project': project, 'engine_id': config['engine_id'],
              'sequence': record['sequence'], 'selected': record['selected'],
              'data_sha256': record['data_sha256'], 'output_dir': str(root),
              'ids': {role: item['Id'] for role, item in by_role.items()}, 'layers': layers,
              'preparation': preparation,
              'candidate_only': True}
    raw_intent = selection.packed(intent)
    if session_dir is not None:
        intent['authority_session']=session_dir
        raw_intent=selection.packed(intent)
    # This exclusive marker is shared with renewal/selection admission. Never
    # clear it in a failure path or infer daemon quiescence from a killed CLI.
    with guard.open('xb'):pass
    renewal.write_empty_private_file(guard, raw_intent.decode())
    renewal.write_empty_private_file(root/'intent.json', raw_intent.decode())
    stack.enter_context(renewal.hold_private_input(guard))
    stack.enter_context(renewal.hold_private_input(root/'intent.json'))
    if preparation is not None:
        marker = renewal.recovery_preparation_guard(config)
        selection.require(selection.digest(renewal.read_private_bytes(marker)) == preparation_sha256)
        # Core intent and marker are durable before preparation loses authority.
        # A crash at any boundary leaves at least one shared admission marker.
        marker.unlink()
    started = set();ready = observed['services'] & COMPLETED;tail = b'';uncertain = None
    deadline = time.monotonic()+600
    try:
        for index, layer in enumerate(layers):
            selection.require(time.monotonic() < deadline)
            current = docker.containers();_unchanged(observed, current, started)
            current_by_role = {renewal._service(x): x for x in current if renewal._project(x) == project}
            to_start = [role for role in layer if current_by_role[role]['State']['Status'] in {'created', 'exited'}]
            ids = [by_role[role]['Id'] for role in to_start]
            receipt = {'roles': layer, 'started_roles': to_start, 'ids': ids}
            renewal.write_empty_private_file(root/f'{index:03}.started.json', selection.packed(receipt).decode())
            stack.enter_context(renewal.hold_private_input(root/f'{index:03}.started.json'))
            if ids:
                remaining = min(120, deadline-time.monotonic());selection.require(remaining > 0)
                p = renewal.run_owned_mutation([*docker.prefix, 'start', *ids], timeout=remaining)
                tail = (tail+p.stdout+p.stderr)[-60000:]
                selection.require(p.returncode == 0)
                started.update(to_start)
            ready |= set(layer)
            _ready(observed, ready, deadline)
            if index == 0:
                # Bao may have been stopped. Its retained TLS/Raft/unseal IDs
                # can start first; no application start precedes native admission.
                if session_dir is not None:
                    from selfhost_windows_renewal_native import reauthenticate
                    authority_file=reauthenticate(config['native'],project,docker.prefix,session_dir)
                selection._native_current(config, choice, values, docker, authority_file)
                selection.require(time.monotonic() < deadline)
            _unchanged(observed, docker.containers(), started)
            renewal.write_empty_private_file(root/f'{index:03}.completed.json', selection.packed(receipt).decode())
            stack.enter_context(renewal.hold_private_input(root/f'{index:03}.completed.json'))
            selection.require(time.monotonic() < deadline)
        selection.require(selection._prove(config, choice, values, stack,
                          expected_data=record['data_sha256'], authority_file=authority_file) == record['data_sha256'])
        selection.require(time.monotonic() < deadline)
        _unchanged(observed, docker.containers(), started)
        selection.require(time.monotonic() < deadline)
    except renewal.UncertainComposeMutation as error:
        uncertain = error
        tail = (tail+error.stdout+error.stderr)[-60000:]
        raise
    finally:
        try:
            renewal.write_empty_private_file(root/'diagnostic.private.log', renewal.bounded_diagnostic(tail))
        except BaseException:
            if uncertain is not None:raise uncertain
            raise
    selection.require(time.monotonic() < deadline)
    selection.require(sorted(p.name for p in root.iterdir()) == sorted(names))
    hashes = {name: selection.digest(stack.enter_context(renewal.hold_private_input(root/name)))
              for name in names if name != 'result.json'}
    # No other writer may add entries to a private attempt during its lease.
    stack.callback(lambda: selection.require(sorted(p.name for p in root.iterdir()) == sorted(names)))
    result = {'schema': SCHEMA, 'project': project, 'result': 'recovered-existing',
              'sequence': record['sequence'], 'services': len(by_role), 'started_roles': sorted(started),
              'container_ids_retained': True, 'candidate_only': True,
              'production_admission': False, 'automatic_lifecycle': False}
    return {'root': str(root), 'guard_sha256': selection.digest(raw_intent),
            'receipt_sha256': hashes, 'result': result}


def _finish_publication(config,pending,target_name,body,*,allow_existing=False):
    """One guard-clearing boundary for ordinary and reconciled completion."""
    root=Path(pending['root']);guard=renewal.recovery_guard(config)
    parent=Path(config['current_secrets']).parent
    names=set(pending['receipt_sha256'])|{target_name}
    selection.require(target_name in {'result.json','reconciliation.json'})
    selection.require(pending['receipt_sha256'].get('intent.json')==pending['guard_sha256'])
    with ExitStack() as protected:
        protected.enter_context(renewal.hold_storage_namespace(parent))
        protected.enter_context(renewal.hold_storage_namespace(root))
        protected.enter_context(_held_private_input(root,directory=True))
        with ExitStack() as receipts:
            with renewal.hold_private_input(parent/f'.{config["project"]}.renewal.lock',exclusive=True):
                selection.require(not renewal.namespace_entry_exists(renewal.recovery_preparation_guard(config)))
                selection.require(not renewal.namespace_entry_exists(renewal.renewal_staging_guard(config)))
                selection.require(not renewal.namespace_entry_exists(renewal.model_repair_guard(config)))
                selection.require(set(p.name for p in root.iterdir())==names)
                for name,sha in pending['receipt_sha256'].items():
                    selection.require(selection.digest(receipts.enter_context(renewal.hold_private_input(root/name)))==sha)
                selection.require(selection.digest(receipts.enter_context(renewal.hold_private_input(guard)))==pending['guard_sha256'])
                saved=renewal.read_private_bytes(root/target_name)
                selection.require(not saved or allow_existing and saved==body)
                if not saved:renewal.write_empty_private_file(root/target_name,body.decode())
                selection.require(protected.enter_context(renewal.hold_private_input(root/target_name))==body)
            # Receipt, decision and directory handles survive publication-lock
            # exit. Decision/directory proofs also survive receipt exit checks.
            selection.require(set(p.name for p in root.iterdir())==names)
        selection.require(set(p.name for p in root.iterdir())==names)
    for name,sha in pending['receipt_sha256'].items():
        selection.require(selection.digest(renewal.read_private_bytes(root/name))==sha)
    selection.require(renewal.read_private_bytes(root/target_name)==body)
    selection.require(selection.digest(renewal.read_private_bytes(guard))==pending['guard_sha256'])
    selection.require(set(p.name for p in root.iterdir())==names)
    guard.unlink()


def finish_existing(config,pending):
    """A written result remains provisional until the shared guard is cleared."""
    _finish_publication(config,pending,'result.json',selection.packed(pending['result']))


def verify_terminal(lease, guard_raw, *, authority_file=None):
    """Prove completed boundaries and current state; issue no workload command."""
    intent = selection.decode(guard_raw)
    required={'schema','project','engine_id','sequence','selected','data_sha256',
              'output_dir','ids','layers','preparation','candidate_only'}
    selection.require(set(intent) in (required,required|{'authority_session'}))
    if 'authority_session' in intent:
        selection.require(isinstance(intent['authority_session'],str)
                          and re.fullmatch(r'/control/recovery-session-[0-9a-f]{32}',intent['authority_session']))
        if authority_file is None:authority_file=intent['authority_session']+'/token'
    selection.require(intent['schema'] == SCHEMA and intent['candidate_only'] is True
        and intent['project'] == lease.project and intent['engine_id'] == lease.engine_id
        and type(intent['sequence']) is int and intent['sequence'] == lease.sequence
        and selection.digest(selection.packed(intent['selected'])) == lease.selected_sha256)
    root = Path(intent['output_dir'])
    selection.require(root.is_absolute() and root.parent == lease.secrets_dir.parent
                      and root.name.startswith('windows-recovery-'))
    docker = renewal.Docker(lease.docker_host,lease.engine_id)
    before = docker.containers();owned = [x for x in before if renewal._project(x) == lease.project]
    ids = {renewal._service(x):x['Id'] for x in owned}
    selection.require(len(ids) == len(owned) and intent['ids'] == ids)
    command = docker.compose(lease.project,lease.env_file,lease.compose_file)
    model = docker.json(command[len(docker.prefix):]+['--profile','*','config','--format','json'])
    observed = {'owned':owned,'services':set(ids),'model':model}
    _,layers = plan(observed);selection.require(intent['layers'] == layers)
    names = ['intent.json','result.json','diagnostic.private.log']
    if intent['preparation'] is not None:names += ['preparation.json','stop-completed.json']
    for index in range(len(layers)):names += [f'{index:03}.started.json',f'{index:03}.completed.json']
    with ExitStack() as held:
        held.enter_context(renewal.hold_storage_namespace(root))
        with _held_private_input(root,directory=True):pass
        selection.require(set(p.name for p in root.iterdir()) <= set(names)|{'reconciliation.json'})
        raw = {name:held.enter_context(renewal.hold_private_input(root/name)) for name in names}
        selection.require(raw['intent.json'] == guard_raw)
        if intent['preparation'] is not None:
            prep = intent['preparation']
            selection.require(set(prep) == {'marker_sha256','completion_file','completion_sha256','preparation_copy','completion_copy'})
            selection.require(prep['preparation_copy'] == 'preparation.json' and prep['completion_copy'] == 'stop-completed.json')
            selection.require(selection.digest(raw['preparation.json']) == prep['marker_sha256']
                and selection.digest(raw['stop-completed.json']) == prep['completion_sha256'])
        started = set()
        for index,layer in enumerate(layers):
            begin,end = raw[f'{index:03}.started.json'],raw[f'{index:03}.completed.json']
            selection.require(begin and end and begin == end)
            receipt = selection.decode(begin)
            selection.require(set(receipt) == {'roles','started_roles','ids'} and receipt['roles'] == layer)
            roles = receipt['started_roles']
            selection.require(isinstance(roles,list) and all(isinstance(r,str) for r in roles)
                and len(set(roles)) == len(roles) and set(roles) <= set(layer)
                and receipt['ids'] == [ids[r] for r in roles])
            started.update(roles)
        expected = {'schema':SCHEMA,'project':lease.project,'result':'recovered-existing',
            'sequence':lease.sequence,'services':len(ids),'started_roles':sorted(started),
            'container_ids_retained':True,'candidate_only':True,'production_admission':False,'automatic_lifecycle':False}
        if raw['result.json']:
            selection.require(selection.packed(selection.decode(raw['result.json'])) == selection.packed(expected))
        selection.require(lease.check_current(authority_file=authority_file) == intent['data_sha256'])
        selection.require(renewal.observations(docker.containers(),lease.project,set())
                          == renewal.observations(before,lease.project,set()))
        decision = {'schema':'marty.windows-existing-recovery-reconciliation/v1','project':lease.project,
            'sequence':lease.sequence,'result':'reconciled-terminal-existing','services':len(ids),
            'started_roles':sorted(started),'intent_sha256':selection.digest(guard_raw),
            'original_result_sha256':selection.digest(raw['result.json']),'data_sha256':intent['data_sha256'],
            'workload_commands_issued':False,'production_admission':False,'automatic_lifecycle':False}
        target = root/'reconciliation.json'
        if not renewal.namespace_entry_exists(target):
            with target.open('xb'):pass
        saved = held.enter_context(renewal.hold_private_input(target))
        selection.require(not saved or saved == selection.packed(decision))
        selection.require(set(p.name for p in root.iterdir()) == set(names)|{'reconciliation.json'})
        hashes = {name:selection.digest(value) for name,value in raw.items()}
    selection.require(set(p.name for p in root.iterdir()) == set(names)|{'reconciliation.json'})
    return {'root':str(root),'guard_sha256':selection.digest(guard_raw),'receipt_sha256':hashes,'decision':decision}


def finish_terminal(config,pending):
    """Keep original results; clear the marker only after fresh proof exit checks."""
    _finish_publication(config,pending,'reconciliation.json',selection.packed(pending['decision']),allow_existing=True)


def wait_for_engine(host,engine_id,*,timeout=300):
    """Bounded read-only startup wait; a responding foreign engine refuses now."""
    selection.require(host in {'npipe:////./pipe/dockerDesktopLinuxEngine','npipe:////./pipe/docker_engine'})
    selection.require(isinstance(engine_id,str) and 10<=len(engine_id)<=128)
    selection.require(type(timeout) is int and 1<=timeout<=300)
    deadline=time.monotonic()+timeout
    while True:
        remaining=deadline-time.monotonic();selection.require(remaining>0)
        # Reuse the owned job and continuously bounded pipe drains. Even a
        # read-only CLI must not hang on a descendant retaining its pipes.
        # Only ordinary returned unavailability is retryable; abnormal child
        # cleanup/timeout refuses immediately without any recovery intent.
        fields='{"ID":{{json .ID}},"OSType":{{json .OSType}},"DockerRootDir":{{json .DockerRootDir}}}'
        p=renewal.run_owned_mutation(['docker','--host',host,'info','--format',fields],
                                    timeout=min(10,remaining))
        if p.returncode==0:
            info=selection.decode(p.stdout)
            selection.require(isinstance(info,dict) and info.get('OSType')=='linux'
                and info.get('ID')==engine_id and info.get('DockerRootDir')=='/var/lib/docker')
            selection.require(time.monotonic()<deadline)
            return
        remaining=deadline-time.monotonic();selection.require(remaining>0)
        time.sleep(min(5,remaining))


def main(argv=None):
    """Managed dispatch used by the existing Windows recovery wrapper."""
    class PrivateParser(argparse.ArgumentParser):
        def error(self,_message):
            raise ValueError('Invalid managed command arguments')
    parser=PrivateParser(description='Recover or renew the retained Windows candidate')
    parser.add_argument('--configuration',required=True)
    parser.add_argument('--check-only',action='store_true')
    parser.add_argument('--wait-for-engine',action='store_true')
    parser.add_argument('--renew-once',action='store_true')
    parser.add_argument('--logical-project')
    try:
        args=parser.parse_args(argv)
        selection.require(os.name=='nt')
        selection.require(bool(args.logical_project)==args.renew_once)
        if args.renew_once:
            selection.require(re.fullmatch(r'marty-(?:selfhost|production)-[a-z0-9][a-z0-9-]{0,59}',args.logical_project))
        with renewal.hold_private_input(Path(args.configuration)) as raw:
            config=selection.decode(raw)
            selection.require(set(config)=={'schema','selection_file'}
                and config['schema']=='marty.windows-managed-recovery/v1')
            selection.require(isinstance(config['selection_file'],str) and Path(config['selection_file']).is_absolute())
            if args.renew_once and not args.check_only:
                if args.wait_for_engine:
                    with selection.selected_inputs(Path(config['selection_file'])) as lease:
                        wait_for_engine(lease.docker_host,lease.engine_id)
                # renew_once acquires its own fresh lease. Never call it under
                # the waiting/configuration lease and deadlock the project lock.
                result=selection.renew_once(Path(config['selection_file']),args.logical_project)
            else:
                with selection.selected_inputs(Path(config['selection_file'])) as lease:
                    if args.wait_for_engine:wait_for_engine(lease.docker_host,lease.engine_id)
                    if args.check_only:
                        result=lease.check_configuration()
                        if args.renew_once:result=dict(result,renewal_requested=True,renewal_executed=False)
                    else:
                        output=lease.secrets_dir.parent/('windows-recovery-'+uuid.uuid4().hex)
                        output.mkdir()
                        result=lease.recover_existing(output,fresh_authority=True)
            if not args.check_only and not args.renew_once:
                result=selection.decode(renewal.read_private_bytes(output/'result.json'))
                result['attempt_dir']=str(output)
                selection.require(not renewal.recovery_pending({'project':lease.project,'current_secrets':str(lease.secrets_dir)}))
        sys.stdout.write(selection.packed(result).decode())
        return 0
    except SystemExit as error:
        return 0 if error.code==0 else 1 # intentional --help only
    except BaseException:
        sys.stderr.write('Managed Windows recovery refused; preserve its configuration, markers and receipts.\n')
        return 1


if __name__=='__main__':
    sys.modules.setdefault('selfhost_windows_recovery',sys.modules[__name__])
    raise SystemExit(main())
