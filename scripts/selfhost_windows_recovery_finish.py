"""Commit an executed recovery to a successor journal, retaining both guards."""
from contextlib import ExitStack
from pathlib import Path
import re

import selfhost_windows_selection as selection
import selfhost_windows_recovery_journal as recovery


def outputs(config):
    return [Path(config[key]) for key in ('intent','result','new_log','rollback_log')] + [
        Path(path) for step in config['step_receipts'] for path in step.values()]


def admit(previous, staged, stage, base, stack, option):
    """Refresh operator trust; serialized admission alone grants no authority."""
    require=selection.require
    import selfhost_windows_renewal_native as native
    prefix=['docker','--host',base['docker_host']]
    if option is None:
        require(stage['operator_admission'] is None and all(staged['native'][key]==previous['native'][key]
            for key in recovery.OPERATOR_FIELDS))
        native.require_recovery_capability(staged['native'],prefix)
    else:
        from selfhost_windows_recovery_operator import admitted_operator
        successor,admission=stack.enter_context(admitted_operator(previous['native'],
            option['assets'],option['expected'],gh=option['gh'],cosign=option['cosign'],
            verifier_sha256=option['verifier_sha256'],docker_prefix=prefix))
        require(stage['operator_admission']==admission and all(staged['native'][key]==successor[key]
            for key in recovery.OPERATOR_FIELDS))


def finish(config_path, source_dir, output_dir, *, operator_successor=None):
    """Reprove execution and live custody before publishing a sealed successor.

    Missing/empty target seed files may be completed. An empty or partial
    source intent/decision requires reconciliation and is never overwritten.
    This owner never replays
    activation, credentials, initialization, or an expired rollback. Both live
    guards remain present even after successful publication.
    """
    from selfhost_windows_inputs import _held_private_input
    from selfhost_windows_model import history, effective_config
    from selfhost_windows_continuation import checkpoint
    from selfhost_windows_staging_recovery import RECOVERY_RECEIPTS
    renewal=selection.renewal;require=selection.require
    source,root=Path(source_dir),Path(output_dir)
    require(source.is_absolute() and root.is_absolute())
    pending_sha=None
    if renewal.namespace_entry_exists(source/recovery.INTENT):
        pending_sha=selection.digest(renewal.read_private_bytes(source/recovery.INTENT))
    with ExitStack() as coordination:
        with selection._session(config_path,_pending_recovery_sha256=pending_sha,
                                _coordination=coordination) as (base,_,expected,journal,raw,stack):
            require(journal==source and root.parent==source.parent==Path(expected['root'])
                    and re.fullmatch(r'windows-renewal-[0-9a-f]{32}',root.name))
            coordination.enter_context(renewal.hold_storage_namespace(source))
            require(not any(renewal.namespace_entry_exists(getter(base)) for getter in (
                renewal.recovery_preparation_guard,renewal.model_repair_guard,renewal.continuation_guard)))
            intents,records=selection._parse(raw,expected)
            require(records and len(intents)==len(records))
            current_model=history(raw,expected,records)[1]
            previous_raw=stack.enter_context(renewal.hold_private_input(Path(intents[len(records)]['config_path'])))
            require(selection.digest(previous_raw)==intents[len(records)]['config_file_sha256'])
            previous=effective_config(selection.decode(previous_raw),current_model)
            stage_raw=stack.enter_context(renewal.hold_private_input(root/'intent.json'))
            stage=selection.decode(stage_raw)
            require(stage_raw==selection.packed(stage))
            require(stack.enter_context(renewal.hold_private_input(renewal.recovery_guard(base)))==stage_raw)
            failed_raw=stack.enter_context(renewal.hold_private_input(Path(stage['failed_root'])/'intent.json'))
            require(stack.enter_context(renewal.hold_private_input(renewal.renewal_staging_guard(base)))==failed_raw)
            require(selection.digest(failed_raw)==stage['failed_proof']['guard_sha256'])
            staged_raw=stack.enter_context(renewal.hold_private_input(root/'config.private.json'))
            staged=selection.decode(staged_raw)
            require(selection.digest(staged_raw)==stage['config_sha256'])
            admit(previous,staged,stage,base,stack,operator_successor)
            ordinary=recovery.successor_configuration(staged,root)
            ordinary_path=root/'selection.config.private.json'
            require(all(path.parent==root/'selection' for path in outputs(ordinary)))
            stack.enter_context(renewal.hold_storage_namespace(root))
            if not renewal.namespace_entry_exists(root/'selection'):(root/'selection').mkdir()
            stack.enter_context(renewal.hold_storage_namespace(root/'selection'))
            with _held_private_input(root/'selection',directory=True):pass
            require({p.name for p in (root/'selection').iterdir()} <= {p.name for p in outputs(ordinary)})
            for path in outputs(ordinary):
                if not renewal.namespace_entry_exists(path):selection._new_private(path,b'')
                require(stack.enter_context(renewal.hold_private_input(path))==b'')
            ordinary_raw=selection.packed(ordinary)
            if not renewal.namespace_entry_exists(ordinary_path):selection._new_private(ordinary_path,ordinary_raw)
            elif renewal.read_private_bytes(ordinary_path)==b'':
                renewal.write_empty_private_file(ordinary_path,ordinary_raw.decode())
            require(stack.enter_context(renewal.hold_private_input(ordinary_path))==ordinary_raw)
            names=set(RECOVERY_RECEIPTS)|{'intent.json','config.private.json','publication.json','renewed.env',
                'selection.config.private.json',*(p.relative_to(root).as_posix() for p in outputs(staged)+outputs(ordinary))}
            evidence={name:selection.digest(stack.enter_context(renewal.hold_private_input(root/name,
                max_bytes=2*1024*1024))) for name in names}
            carry=checkpoint(raw)
            marker={'schema':recovery.SCHEMA,'project':expected['project'],'engine_id':expected['engine_id'],
                'source_dir':str(source),'target_dir':str(source.parent/('.'+expected['project']+
                    '.generation-recovery-'+root.name.removeprefix('windows-renewal-'))),
                'source_sha256':{name:selection.digest(body) for name,body in raw.items() if name not in recovery.FILES},
                'attempt_dir':str(root),'config_sha256':selection.digest(staged_raw),
                'generation_sequence':len(records)+(carry['sequence_offset'] if carry else 0),
                'evidence_sha256':evidence,'candidate_only':True}
            marker_raw=selection.packed(marker)
            if recovery.INTENT in raw:require(raw[recovery.INTENT]==marker_raw)
            prospective=dict(raw);prospective[recovery.INTENT]=marker_raw
            initial=recovery.seed(prospective,expected,current_model,marker,stack)
            values,snapshots=selection._inputs(ordinary,stack)
            require(snapshots==selection.decode(initial['000001.intent.json'])['inputs'])
            require(selection._prove(ordinary,'new',values,stack,
                expected_data=records[len(records)]['data_sha256'])==records[len(records)]['data_sha256'])
            if recovery.INTENT not in raw:selection._append(source,raw,recovery.INTENT,marker,stack)
            target=Path(marker['target_dir'])
            if not renewal.namespace_entry_exists(target):target.mkdir()
            coordination.enter_context(renewal.hold_storage_namespace(target))
            with _held_private_input(target,directory=True):pass
            require({p.name for p in target.iterdir()}<=set(initial))
            for name,body in initial.items():
                path=target/name
                if not renewal.namespace_entry_exists(path):selection._new_private(path,body)
                elif renewal.read_private_bytes(path)==b'':renewal.write_empty_private_file(path,body.decode())
                require(stack.enter_context(renewal.hold_private_input(path))==body)
            stack.enter_context(_held_private_input(target,directory=True))
            require({p.name for p in target.iterdir()}==set(initial))
            decision_raw=selection.packed(recovery.decision(marker,initial))
            if recovery.DECISION in raw:require(raw[recovery.DECISION]==decision_raw)
            else:
                if recovery.PENDING not in raw:
                    selection._append(source,raw,recovery.PENDING,selection.decode(decision_raw),stack)
                require(raw[recovery.PENDING]==decision_raw)
            # Every proof and namespace exit runs before visibility changes.
        if recovery.DECISION not in raw:
            with _held_private_input(source/recovery.PENDING,_rename_to=source/recovery.DECISION) as held:
                require(held==decision_raw)
        return {'schema':recovery.SCHEMA,'result':'selected-guarded','project':expected['project'],
                'journal':str(target),'generation_sequence':marker['generation_sequence']+1,
                'guards_retained':True,'credential_admission':False}


def finalize(config_path, source_dir, output_dir, *, operator_successor=None):
    """Freshly prove a committed, running successor, then archive its guards.

    Each archive is a same-handle, no-overwrite rename. Interruption between
    them leaves one active guard blocking normal work and can be reconciled by
    this owner after repeating all proofs. No guard bytes or history are deleted.
    A failed check after a rename is an uncertain outcome, never a rollback.
    A later normal operation must perform its own current native admission.
    """
    from selfhost_windows_inputs import _held_private_input
    from selfhost_windows_continuation import CHECKPOINT
    renewal=selection.renewal;require=selection.require
    source,root=Path(source_dir),Path(output_dir)
    require(source.is_absolute() and root.is_absolute())
    with ExitStack() as coordination:
        with selection._session(config_path,_coordination=coordination) as (base,_,expected,target,raw,stack):
            require(root.parent==source.parent==target.parent==Path(expected['root']))
            coordination.enter_context(renewal.hold_storage_namespace(source))
            coordination.enter_context(renewal.hold_storage_namespace(target))
            marker_raw=stack.enter_context(renewal.hold_private_input(source/recovery.INTENT))
            marker=selection.decode(marker_raw)
            require(marker_raw==selection.packed(marker) and marker['source_dir']==str(source)
                    and marker['target_dir']==str(target) and marker['attempt_dir']==str(root))
            require(not renewal.namespace_entry_exists(source/recovery.PENDING))
            carry=selection.decode(raw[CHECKPOINT])
            require(carry['schema']==recovery.SCHEMA and carry['intent_sha256']==selection.digest(marker_raw))
            intents,records=selection._parse(raw,expected)
            require(len(intents)==len(records)==1 and intents[1]['operation']=='recovery-successor'
                    and records[1]['choice']=='new')
            cfg_raw=stack.enter_context(renewal.hold_private_input(Path(intents[1]['config_path'])))
            require(selection.digest(cfg_raw)==intents[1]['config_file_sha256'])
            cfg=selection.decode(cfg_raw)
            require(selection.config_digest(cfg)==intents[1]['config_sha256'])
            stage_raw=stack.enter_context(renewal.hold_private_input(root/'intent.json'))
            stage=selection.decode(stage_raw)
            staged=selection.decode(stack.enter_context(renewal.hold_private_input(root/'config.private.json')))
            previous_native=dict(staged['native'])
            # The predecessor owner was validated by normal resolver replay.
            predecessor=selection.decode(stack.enter_context(renewal.hold_private_input(source/'owner.json')))['binding']
            for key in recovery.OPERATOR_FIELDS:previous_native[key]=predecessor['native'][key]
            admit({'native':previous_native},staged,stage,base,stack,operator_successor)
            failed_raw=stack.enter_context(renewal.hold_private_input(Path(stage['failed_root'])/'intent.json'))
            require(selection.digest(failed_raw)==stage['failed_proof']['guard_sha256'])
            suffix=root.name.removeprefix('windows-renewal-')
            require(re.fullmatch(r'[0-9a-f]{32}',suffix))
            guards=[]
            for path,body,kind in ((renewal.recovery_guard(base),stage_raw,'recovery'),
                                  (renewal.renewal_staging_guard(base),failed_raw,'renewal-staging')):
                archive=path.parent/('.'+base['project']+'.'+kind+'-retired-'+suffix+'.json')
                present=renewal.namespace_entry_exists(path)
                require(present != renewal.namespace_entry_exists(archive))
                keeper=stack if present else coordination
                require(keeper.enter_context(renewal.hold_private_input(path if present else archive))==body)
                guards.append((path,archive,body,present))
            require(not any(renewal.namespace_entry_exists(getter(base)) for getter in (
                renewal.recovery_preparation_guard,renewal.model_repair_guard,renewal.continuation_guard)))
            values,snapshots=selection._inputs(cfg,stack)
            require(snapshots==intents[1]['inputs'])
            require(selection._prove(cfg,'new',values,stack,
                expected_data=records[1]['data_sha256'])==records[1]['data_sha256'])
        # The selected successor is immutable history; each later operation
        # still needs normal admission. Project/source/target identities stay held.
        for path,archive,body,present in guards:
            if present:
                with _held_private_input(path,_rename_to=archive) as saved:require(saved==body)
                require(coordination.enter_context(renewal.hold_private_input(archive))==body)
            else:
                with renewal.hold_private_input(archive) as saved:require(saved==body)
        return {'schema':recovery.SCHEMA,'project':base['project'],'result':'recovery-finalized',
                'journal':str(target),'guards_archived':True,'credential_admission':False}
