"""Exact new KMS generation plus premigrated Flow model, source only."""
from copy import deepcopy
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
from scoped_native_database import _recovery_trust_models
from scoped_native_runtime import ref


def fixture(tmp_path):
    def save(name, value):
        path=tmp_path/name
        path.write_text(json.dumps(value),encoding="utf-8")
        return ref(path)
    generation=tmp_path/"new-generation"
    old={"secrets": {
        "trust_profile_workload_server_cert": {"file": str(tmp_path/"old-cert")},
        "trust_profile_tls_kms_token": {"file": str(tmp_path/"old-token")}},
        "services": {"flow": {"environment": {"MARTY_ORG_ID": "synthetic"}},
                     "issuance-native": {"environment": {"MARTY_SCHEMA_STARTUP_MODE": "validate"}}}}
    new=deepcopy(old)
    new["secrets"]["trust_profile_workload_server_cert"]["file"]=str(generation/"trust_profile_workload_server_cert")
    new["secrets"]["trust_profile_tls_kms_token"]["file"]=str(generation/"trust_profile_workload_server_kms_token")
    new["services"]["flow"]["environment"]["MARTY_SCHEMA_STARTUP_MODE"]="validate"
    ui=save("ui.json",{"name":"synthetic-ui"})
    original={"plannedModels": {"elevenid-beta":save("old.json",old),"elevenid-beta-ui":ui}}
    inputs={"plannedModels":{"elevenid-beta":save("new.json",new),"elevenid-beta-ui":ui},
            "runScopedTrustLeaseProof":save("lease.json",{"generationDirectory":str(generation)})}
    return original,inputs,new,save


@pytest.mark.parametrize("fault",[None,"default-mode","stale-token","missing-flow-mode","extra-flow-env","other-service"])
def test_exact_flow_and_generation_delta(tmp_path,fault):
    original,inputs,model,save=fixture(tmp_path)
    changed=deepcopy(model)
    if fault=="stale-token":changed["secrets"]["trust_profile_tls_kms_token"]["file"]="old-token"
    elif fault=="missing-flow-mode":del changed["services"]["flow"]["environment"]["MARTY_SCHEMA_STARTUP_MODE"]
    elif fault=="extra-flow-env":changed["services"]["flow"]["environment"]["OTHER"]="drift"
    elif fault=="other-service":changed["services"]["issuance-native"]["environment"]["OTHER"]="drift"
    if changed!=model:inputs["plannedModels"]["elevenid-beta"]=save("changed.json",changed)
    if fault:
        with pytest.raises(ValueError):
            _recovery_trust_models(original,inputs,allow_ob3_flow_validate=fault!="default-mode")
    else:
        _recovery_trust_models(original,inputs,allow_ob3_flow_validate=True)
