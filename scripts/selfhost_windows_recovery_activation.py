"""Guarded recovery activation; never rolls back to expired credentials."""
from contextlib import ExitStack
from pathlib import Path

import selfhost_windows_selection as selection
import selfhost_windows_renewal as renewal
import selfhost_windows_renewal_native as native
from selfhost_windows_staging_recovery import _recovery_candidate_inputs


def activate_recovery_candidate(config_path, output_dir, *, operator_successor=None):
    """Activate once under fresh proof; retain both guards pending selection.

    Any interrupted attempt requires reconciliation. This function never deletes
    either guard, retries a phase, runs an initializer, or rolls back.
    """
    with ExitStack() as coordination:
        with _recovery_candidate_inputs(config_path, output_dir, operator_successor,
                                        _coordination=coordination) as lease:
            selection.require(lease['markers']==['publication.json'])
            cfg, observed, stack, root = (lease[name] for name in ('config','observed','stack','root'))
            docker=observed['docker'];project=cfg['project'];source=Path(cfg['compose_file'])
            activation=root/'activation'
            selection.require(not renewal.namespace_entry_exists(activation)
                              and not renewal.namespace_entry_exists(Path(cfg['renewed_env'])))
            before=stack.enter_context(renewal.hold_private_input(Path(cfg['current_env'])))
            lines=before.splitlines(keepends=True)
            indices=[index for index,line in enumerate(lines) if line.startswith(b'SELFHOST_SECRET_DIR=')]
            selection.require(len(indices)==1)
            index=indices[0];ending=b'\r\n' if lines[index].endswith(b'\r\n') else b'\n'
            lines[index]=b'SELFHOST_SECRET_DIR='+Path(cfg['renewed_secrets']).as_posix().encode()+ending
            after=b''.join(lines)
            selection.require(renewal.env_body(before,Path(cfg['current_secrets']))==
                              renewal.env_body(after,Path(cfg['renewed_secrets'])))
            selection._new_private(Path(cfg['renewed_env']),after)
            lease['names'].add(Path(cfg['renewed_env']).name)
            stack.enter_context(renewal.hold_private_input(Path(cfg['renewed_env'])))
            activation.mkdir();lease['names'].add('activation')
            stack.enter_context(renewal.hold_storage_namespace(activation))
            stack.enter_context(selection._held_private_input(activation,directory=True,mutable_directory=True))
            outputs={name:Path(cfg[name]) for name in ('intent','result','new_log','rollback_log')}
            steps=cfg['step_receipts']
            paths=[*outputs.values(),*(Path(path) for step in steps for path in step.values())]
            selection.require(len(set(paths))==len(paths) and all(path.parent==activation for path in paths))
            for path in paths:selection._new_private(path,b'')
            def membership():selection.require({p.name for p in activation.iterdir()}=={p.name for p in paths})
            membership();stack.callback(membership)
            command=docker.compose(project,Path(cfg['renewed_env']),source)
            model=docker.json(command[len(docker.prefix):]+['--profile','*','config','--format','json'])
            renewal.checked_models(observed['model'],model,Path(cfg['current_secrets']),
                                   Path(cfg['renewed_secrets']),sorted(lease['old_bytes']))
            changing=renewal.owned_roles(model,observed['services'])
            layers=renewal.dependency_layers(model,observed['services'],changing)
            selection.require(len(steps)==len(layers))
            hashes=docker.hashes(command)
            baseline=docker.containers();owned=[item for item in baseline if renewal._project(item)==project]
            data_before=renewal.data_mounts(owned)
            selection.require(selection.digest(selection.packed(data_before))==lease['proof']['data_sha256'])
            context=renewal.ForeignContext(docker,project,changing,baseline,docker.volumes(),cfg['native']['helper_image'])
            native.preflight_recovery(cfg['native'],project,lease['old_bytes'],lease['new_bytes'],docker.prefix)
            context.check(before_intent=True)
            intent={'schema':'marty.windows-recovery-activation/v1','project':project,
                    'publication_sha256':selection.digest(selection.packed(lease['proof'])),
                    'data_mounts_before':data_before,'layers':layers,'rollback_to_expired':False}
            renewal.write_empty_private_file(outputs['intent'],selection.packed(intent).decode())
            stack.enter_context(renewal.hold_private_input(outputs['intent']))
            def progress(event,index,layer):
                selection.require(event in ('started','completed') and layer==layers[index])
                context.check()
                path=Path(steps[index]['new_'+event])
                renewal.write_empty_private_file(path,selection.packed({'roles':layer,'event':event}).decode())
                stack.enter_context(renewal.hold_private_input(path))
            renewal.recreate(docker,command,changing,observed['services'],model,outputs['new_log'],progress=progress)
            current=context.check();current_owned=[item for item in current if renewal._project(item)==project]
            selection.require(renewal.data_mounts(current_owned)==data_before)
            selection.require(renewal.windows_healthy(renewal.statuses(command,cwd=source.parent),observed['services'],model))
            renewal.checked_live_configuration(current_owned,hashes,cfg['tls_init_receipt'])
            mounts=renewal.checked_secret_mounts(current_owned,project,Path(cfg['renewed_secrets']),
                observed['services'],model,path_equal=renewal.windows_mount_path_equal)
            selected_native=dict(cfg['native'],current=cfg['native']['renewed'])
            native.preflight_current(selected_native,project,lease['new_bytes'],docker.prefix)
            result={'schema':intent['schema'],'result':'activated-unselected','project':project,
                    'secret_mounts':mounts,'data_sha256':lease['proof']['data_sha256'],
                    'guards_retained':True,'rollback_to_expired':False,'credential_admission':False}
        # All held proof exits passed. Project coordination still excludes writers.
        renewal.write_empty_private_file(outputs['result'],selection.packed(result).decode())
    return result
