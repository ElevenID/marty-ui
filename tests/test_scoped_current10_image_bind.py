"""Only current10 image-owned -> exact selected RO executable transitions; no effects."""
from copy import deepcopy
import json,sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from scoped_native_profiles import D05_MEMBERSHIP_LATEST,D12_PASSPORT_CURRENT
from scoped_native_runtime import ref,D12_CURRENT_RUNTIME_ROLES
from scoped_beta_binary_overlay import binary_overlay,validate_delta,validate_runtime_after,CURRENT10
from test_scoped_passport_maintenance import fixture
SIX={"compliance-profile","credential-template","flow","organization","presentation-policy","trust-profile"}

def source_fixture(tmp_path):
    _,before,_,_,_=fixture(tmp_path)
    roles=dict(D05_MEMBERSHIP_LATEST.roles)
    model={"name":"elevenid-beta","services":{},"networks":{"kept":{}}}
    inspections=[];binaries={}
    for row in before["roles"]:
        if row["role"]=="canvas-sandbox":row["role"]="event-stream"
        binary=roles.get(row["role"],row["binary"])
        row.update(binary=binary,kind="SIGNED_NIGHTLY_IMAGE",effectiveUid=10001,configuredRuntimeUid=10001,
            health="healthy",processExecutableSha256=row["sha256"],executablePath="/usr/local/bin/"+binary if binary else None)
        row["binaryMounts"]=[]
        volumes=[{"type":"bind","source":"/public/unchanged","target":"/run/unchanged","read_only":True}]
        actual_mounts=[{"Type":"bind","Source":"/public/unchanged","Destination":"/run/unchanged","RW":False}]
        if row["role"] in roles:
            path=tmp_path/binary;path.write_bytes(b"synthetic-selected-elf")
            binaries[row["role"]]=ref(path)
            if row["role"] not in SIX:
                row["binaryMounts"]=[{"type":"bind","source":"/old/"+binary,"destination":"/usr/local/bin/"+binary,"writable":False}]
                volumes.append({"type":"bind","source":"/old/"+binary,"target":"/usr/local/bin/"+binary,"read_only":True})
                actual_mounts.append({"Type":"bind","Source":"/old/"+binary,"Destination":"/usr/local/bin/"+binary,"RW":False})
        if row["project"]=="elevenid-beta":model["services"][row["role"]]={"image":row["imageId"],"environment":{"KEEP":"unchanged"},"entrypoint":["/usr/local/bin/"+binary] if binary else [],"command":[],"volumes":volumes}
        inspections.append({"Id":row["containerId"],"role":row["role"],"Image":row["imageId"],"Mounts":actual_mounts,"State":{"StartedAt":row["startedAt"],"Pid":row["hostPid"],"Running":True}})
    def freeze(name,data):
        p=tmp_path/name;p.write_text(json.dumps(data));return ref(p)
    preimage={"binding":freeze("before.json",before),"inspections":freeze("inspections.json",inspections)}
    return before,model,inspections,binaries,preimage,freeze

def merge(model,patch):
    after=deepcopy(model)
    for role,change in patch["services"].items():
        mounts={x["target"]:x for x in after["services"][role]["volumes"]}
        mounts.update({x["target"]:x for x in change["volumes"]})
        after["services"][role]["volumes"]=list(mounts.values())
    return after

def test_six_image_roles_gain_one_selected_bind_and_four_replacements_keep_their_shape(tmp_path):
    before,model,inspections,binaries,preimage,_=source_fixture(tmp_path)
    patch=binary_overlay(binaries,CURRENT10,before=model,native_preimage=preimage)
    after=merge(model,patch);validate_delta(model,after,binaries,CURRENT10,native_preimage=preimage)
    assert {r for r in binaries if len(after["services"][r]["volumes"])==len(model["services"][r]["volumes"])+1}==SIX
    runtime=deepcopy(before)
    for index,row in enumerate(runtime["roles"]):
        row.update(startedAt="2026-10-28T15:00:00Z",hostPid=index+500)
        if row["role"] in binaries:
            bound=binaries[row["role"]];target="/usr/local/bin/"+dict(D05_MEMBERSHIP_LATEST.roles)[row["role"]]
            row.update(containerId=f"{index+100:064x}",source=D05_MEMBERSHIP_LATEST.ui_revision,coreSource=D05_MEMBERSHIP_LATEST.core_revision,kind="SCOPED_NATIVE_FUNCTIONAL_OVERLAY",sha256=bound["sha256"],processExecutableSha256=bound["sha256"],binaryMounts=[{"type":"bind","source":bound["path"],"destination":target,"writable":False}])
            row.update(requiredContainerId=row["containerId"],requiredStartedAt=row["startedAt"],requiredHostPid=row["hostPid"],requiredEffectiveUid=10001,requiredBinaryMounts=deepcopy(row["binaryMounts"]))
    proof=validate_runtime_after(before,runtime,binaries,D12_CURRENT_RUNTIME_ROLES-set(binaries),CURRENT10,native_preimage=preimage)
    assert len(proof["roleBinaries"])==10
    # The maintained create observer must carry the same zero-to-one lineage.
    from scoped_d12_native_effect_host import D12CurrentEffectObserver
    observer=D12CurrentEffectObserver.__new__(D12CurrentEffectObserver)
    observer.profile=CURRENT10;observer.build_profile=D05_MEMBERSHIP_LATEST
    observer.original={x["role"]:x for x in before["roles"]};observer.current=deepcopy(observer.original)
    for index,role in enumerate(sorted(SIX)):
        row=observer.current[role];target="/usr/local/bin/"+dict(D05_MEMBERSHIP_LATEST.roles)[role]
        row["containerId"]=f"{index+200:064x}"
        row["binaryMounts"]=[{"type":"bind","source":binaries[role]["path"],"destination":target,"writable":False}]
        actual={"Id":row["containerId"],"Image":row["imageId"],"Config":{"Labels":{"com.docker.compose.project":"elevenid-beta","com.docker.compose.service":role}},
                "Mounts":[{"Type":"bind","Source":binaries[role]["path"],"Destination":target,"RW":False}],
                "State":{"StartedAt":row["startedAt"],"Running":False,"Paused":False,"Pid":0,"Status":"created","ExitCode":0,"OOMKilled":False}}
        assert observer._project(role,actual)["state"]=="created"
        actual["Mounts"].append({"Type":"bind","Source":"/unreviewed","Destination":"/usr/local","RW":False})
        with pytest.raises(ValueError,match="MOUNT_AMBIGUOUS"):observer._project(role,actual)

@pytest.mark.parametrize("change",["model_ancestor","actual_ancestor","actual_duplicate","image","process_path"])
def test_missing_or_ambiguous_image_owned_preimage_refuses(tmp_path,change):
    before,model,actual,binaries,preimage,freeze=source_fixture(tmp_path)
    if change=="model_ancestor":model["services"]["flow"]["volumes"].append({"type":"bind","target":"/usr/local/bin","source":"/unreviewed","read_only":True})
    if change=="actual_ancestor":next(x for x in actual if x["role"]=="flow")["Mounts"].append({"Destination":"/usr/local","Source":"/unreviewed","Type":"bind","RW":False});preimage["inspections"]=freeze("changed-inspections.json",actual)
    if change=="actual_duplicate":
        row=next(x for x in actual if x["role"]=="flow");row["Mounts"].append(deepcopy(row["Mounts"][0]));preimage["inspections"]=freeze("changed-inspections.json",actual)
    if change=="image":model["services"]["flow"]["image"]="sha256:"+"d"*64
    if change=="process_path":next(x for x in before["roles"] if x["role"]=="flow")["executablePath"]="/unreviewed";preimage["binding"]=freeze("changed-before.json",before)
    with pytest.raises(ValueError):binary_overlay(binaries,CURRENT10,before=model,native_preimage=preimage)

def test_new_bind_cannot_change_unrelated_environment_or_mounts_and_old_three_stays_closed(tmp_path):
    before,model,_,binaries,preimage,_=source_fixture(tmp_path)
    patch=binary_overlay(binaries,CURRENT10,before=model,native_preimage=preimage);after=merge(model,patch)
    for edit in (lambda v:v["services"]["flow"]["environment"].update(KEEP="changed"),lambda v:v["services"]["flow"]["volumes"][0].update(source="/changed")):
        changed=deepcopy(after);edit(changed)
        with pytest.raises(ValueError):validate_delta(model,changed,binaries,CURRENT10,native_preimage=preimage)
    old={role:binaries[role] for role,_ in D12_PASSPORT_CURRENT.roles}
    with pytest.raises(ValueError,match="EXISTING_READ_ONLY_EXECUTABLE_BIND_REQUIRED"):
        binary_overlay(old,"d12-passport-current-functional",before=model,native_preimage=preimage)


def test_real_retained_current10_repo_digest_links_exact_actual_image_id(tmp_path):
    # Image fields projected from the retained619246d7 model, a1b4bfa1 binding
    # and1155a4d2 inspection receipt. No private environment is a test input.
    before,model,actual,binaries,preimage,freeze=source_fixture(tmp_path)
    reference='ghcr.io/elevenid/marty-ui-oss/services@sha256:166c1c1bcbb2d952c354c4fa59268c23367687fbb96caa3dff374a9d1df4108d'
    image_id='sha256:166c1c1bcbb2d952c354c4fa59268c23367687fbb96caa3dff374a9d1df4108d'
    for row in before["roles"]:
        if row["role"] in SIX:row["imageId"]=image_id
    for row in actual:
        if row["role"] in SIX:row["Image"]=image_id
    for role in SIX:model["services"][role]["image"]=reference
    preimage={"binding":freeze("retained-reference-before.json",before),
              "inspections":freeze("retained-reference-inspections.json",actual)}
    patch=binary_overlay(binaries,CURRENT10,before=model,native_preimage=preimage)
    validate_delta(model,merge(model,patch),binaries,CURRENT10,native_preimage=preimage)
    from scoped_beta_binary_overlay import _current10_configured_image_matches
    assert all(_current10_configured_image_matches(model["services"][r]["image"],image_id) for r in SIX)
    assert _current10_configured_image_matches(image_id,image_id)
    for wrong in (reference.rsplit(":",1)[0]+":"+"f"*64,
                  "ghcr.io/elevenid/marty-ui-oss/services:nightly",
                  "unapproved.invalid/services@"+image_id,reference+"-suffix"):
        changed=deepcopy(model);changed["services"]["flow"]["image"]=wrong
        with pytest.raises(ValueError):binary_overlay(binaries,CURRENT10,before=changed,native_preimage=preimage)
    assert not _current10_configured_image_matches(reference,"sha256:"+"d"*64)
