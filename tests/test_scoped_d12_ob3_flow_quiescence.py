"""Focused Flow quiescence dispatch checks without Docker, SQL, or credentials."""
import json
import pathlib
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))
import scoped_d12_native_execution as execution
from scoped_native_runtime import ref


@pytest.mark.parametrize("fault",[None,"foreign-role","foreign-cid","unknown-stop"])
def test_flow_pending_dispatch_stops_exact_prefix_without_replacement(tmp_path,monkeypatch,fault):
    def save(name,value):
        path=tmp_path/name
        path.write_text(json.dumps(value),encoding="utf-8")
        return ref(path)
    prefix=[f"role-{n}" for n in range(17)]
    roles=[*prefix,"flow"]
    cids={role:f"{n+1:064x}" for n,role in enumerate(roles)}
    original_state={"phase":"START_INSPECTION_PENDING","startAcks":{"role-0":{"containerId":cids["role-0"]}}}
    recovery={"operation":"QUIESCE_OB3_FLOW_PENDING_STARTS",
              "originalOperationState":save("original-state.json",original_state),
              "currentOwned22":save("current22.json",{role:{"Id":cid} for role,cid in cids.items()}),
              "stopContracts":{role:save("contract-"+role+".json",{"allowedExitCodes":[0,1,143] if role=="flow" else [0]})
                                   for role in roles}}
    recovery_ref=save("recovery.json",recovery)
    before={"roles":[]};proof={"schema":"synthetic"};verified={"schema":"synthetic"}
    calls=[]
    value=execution.D12CurrentExecution.__new__(execution.D12CurrentExecution)
    value.i={"d12Authority":save("authority.json",{}),"runId":"SYNTHETIC"}
    value.profile="d05-membership-current-functional"
    value.read_only_preflight=False
    value.state={}
    value.store=SimpleNamespace(read=lambda name:original_state if name=="build-state.json" else {},
                                specification={})
    monkeypatch.setattr(execution,"flow_pending_ob3_checkpoint",
                        lambda *args,**kwargs: ({"uiRevision":"old","coreRevision":"old"},proof,verified,prefix))
    steps=[{"role":role,"containerId":cids[role],"argv":["docker","stop",cids[role]]}
           for role in reversed(roles)]
    if fault=="foreign-role":steps[0]["role"]="auth"
    if fault=="foreign-cid":steps[0]["containerId"]="f"*64
    def stop(_,step):
        calls.append(("stop",step["role"]))
        if fault=="unknown-stop":raise ValueError("OWNED_STOP_UNKNOWN")
        return {"containerId":step["containerId"],"state":"exited","running":False,
                "hostPid":0,"oomKilled":False,"containerExitCode":1 if step["role"]=="flow" else 0}
    value.g={"operation_lock_held":lambda:True,"recording_lock_held":lambda:True,
             "ob3_flow_quiesce_authorization_verified":lambda *args:True,
             "ob3_flow_quiesce_steps":lambda *args:steps,
             "ob3_flow_stop_owned_role":stop,
             "ob3_flow_observe_quiescence":lambda *args:save("actual-quiescence.json",{})}
    value.record=lambda phase,**fields:(calls.append(("record",phase)),value.state.update(phase=phase,**fields))
    value.command=lambda *args,**kwargs:pytest.fail("QUIESCENCE_CANNOT_CREATE_OR_REPLAY_SQL")
    if fault:
        with pytest.raises((ValueError,KeyError)):
            value.quiesce_ob3_flow_pending_starts(recovery_ref)
        if fault=="unknown-stop":assert ("record","OB3_FLOW_STOP_PENDING") in calls
    else:
        result=value.quiesce_ob3_flow_pending_starts(recovery_ref)
        assert result["schema"]=="marty.d12-ob3-flow-quiescence/v1"
        assert [item[1] for item in calls if item[0]=="stop"]==list(reversed(roles))
        assert value.state["phase"]=="OB3_FLOW_PARTIAL_QUIESCENT"
        assert value.state["startAcks"]=={} and value.state["priorStartAcks"]==original_state["startAcks"]


def test_completed_database_verification_uses_historical_revision_without_sql(tmp_path,monkeypatch):
    def save(name,value):
        path=tmp_path/name
        path.write_text(json.dumps(value),encoding="utf-8")
        return ref(path)
    from scoped_native_database import schema_steps
    steps={step for command in ("migrate","verify-owned-schema")
           for step,_role in schema_steps(True,command)}
    operations=[{"stepId":step,"receipt":save(f"receipt-{n}.json",{"stepId":step})}
                for n,step in enumerate(sorted(steps))]
    proof={"operationState":save("dbstate.json",{"operations":operations})}
    verified={"verified":"historical"}
    value=execution.D12CurrentExecution.__new__(execution.D12CurrentExecution)
    value.profile="d05-membership-current-functional"
    value.build_profile=SimpleNamespace(ui_revision="new-source",core_revision="new-core")
    value.i={"runId":"synthetic","selection":{"sha256":"a"*64},
             "databaseBefore":{"sha256":"b"*64}}
    contexts=[]
    database=SimpleNamespace(baseline_refs={},engine_id="engine",tenant_id="tenant",
        node=lambda operation,**kwargs:contexts.append((operation,kwargs["context"])) or verified,
        command=lambda *args:pytest.fail("NO_SQL_REPLAY"))
    value._verify_completed_recovery_database(database,
        {"executorSource":{"sha256":"c"*64},"uiRevision":"old-source","coreRevision":"old-core"},
        proof,verified,historical_revision=True)
    assert len(database.commands)==len(steps)
    assert contexts[0][0]=="verify"
    assert contexts[0][1]["sourceRevision"]=="old-source"
    assert contexts[0][1]["coreRevision"]=="old-core"
