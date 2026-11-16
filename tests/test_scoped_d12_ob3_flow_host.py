"""Flow crash-stop host gates; every transport is a local fake."""
import pathlib
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))
import scoped_d12_native_effect_host as host_module


@pytest.mark.parametrize("fault",[None,"pending-cid","phase","observed-cid"])
def test_flow_stop_requires_durable_exact_cid_before_transport(monkeypatch,fault):
    owner=object.__new__(host_module.D12CurrentHostBindings)
    owner.assert_inputs=lambda:None
    owner.lock=SimpleNamespace(held=lambda:True)
    owner.docker="docker-test-only"
    owner.environment={}
    owner.save_bytes=lambda *args:None
    owner.save=lambda *args:None
    authority={"sha256":"a"*64}
    owner._ob3_flow_approval=authority
    step={"role":"flow","containerId":"c"*64,"imageId":"i"*64,
          "argv":["docker","stop","--signal","SIGTERM","--time","-1","c"*64]}
    owner._ob3_flow_stop_steps={"flow":step}
    state={"phase":"OB3_FLOW_STOP_PENDING","pendingStep":"OB3_FLOW_STOP_flow",
           "pendingArgv":step["argv"],"pendingContainerId":step["containerId"],
           "recoveryAuthority":authority}
    if fault=="pending-cid":state["pendingContainerId"]="f"*64
    if fault=="phase":state["phase"]="OB3_FLOW_STOP_TERMINAL"
    owner.store=SimpleNamespace(read=lambda name:state)
    row={"containerId":step["containerId"],"imageId":step["imageId"],
         "state":"restarting","running":True,"hostPid":0,"containerExitCode":1,
         "paused":False,"oomKilled":False}
    if fault=="observed-cid":row["containerId"]="f"*64
    owner.observer=SimpleNamespace(inspect_role=lambda role:row)
    calls=[]
    def fake_transport(*args,**kwargs):
        calls.append(args)
        row.update(state="exited",running=False,hostPid=0,containerExitCode=1)
        return SimpleNamespace(returncode=0,stdout=b"",stderr=b"",
            observation={"timedOut":False,"failures":[]})
    monkeypatch.setattr(host_module,"bounded_run",fake_transport)
    if fault:
        with pytest.raises(ValueError):owner.ob3_flow_stop_owned_role(authority,step)
        assert calls==[]
    else:
        assert owner.ob3_flow_stop_owned_role(authority,step)["state"]=="exited"
        assert len(calls)==1
