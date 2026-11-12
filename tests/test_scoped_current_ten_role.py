"""Closed source-selection controls only; never executes a service or database command."""
from copy import deepcopy
import sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from scoped_native_profiles import D12_PASSPORT_CURRENT,D05_MEMBERSHIP_LATEST,D12_CURRENT_ROLLOUT,D05_CURRENT_ROLLOUT,current_rollout_build
from scoped_native_runtime import selected_sources,runtime_roles,D12_CURRENT_RUNTIME_ROLES
from scoped_passport_successor import terminal_current_build
from scoped_beta_binary_overlay import overlay_roles,compose_recreate_arguments

def build_fixture(build):
    roles=dict(build.roles)
    prepared={"buildProfile":build.name,"uiRevision":build.ui_revision,"coreRevision":build.core_revision,"roleBinaries":roles,"runId":"synthetic"}
    receipt={**prepared,"state":"BUILD_SUCCEEDED","exitCode":0,"oomKilled":False,"preparationSha256":"a"*64,"binaries":{b:{} for b in roles.values()},"releaseQualified":False,"recordingQualified":False}
    return prepared,receipt

def test_legacy_three_role_default_is_unchanged():
    prepared,receipt=build_fixture(D12_PASSPORT_CURRENT)
    assert terminal_current_build(receipt,prepared,"a"*64)==dict(D12_PASSPORT_CURRENT.roles)
    assert overlay_roles(D12_CURRENT_ROLLOUT)==dict(D12_PASSPORT_CURRENT.roles)
    assert current_rollout_build(D12_CURRENT_ROLLOUT) is D12_PASSPORT_CURRENT

def test_ten_role_source_requires_exact_product_core_and_complete_receipt():
    prepared,receipt=build_fixture(D05_MEMBERSHIP_LATEST)
    assert terminal_current_build(receipt,prepared,"a"*64,D05_CURRENT_ROLLOUT)==dict(D05_MEMBERSHIP_LATEST.roles)
    for changes in ({"uiRevision":D12_PASSPORT_CURRENT.ui_revision},{"uiRevision":"82862f78876f2885a32353ba99a34ccba284faac"},{"coreRevision":D12_PASSPORT_CURRENT.core_revision},{"binaries":{"marty-flow":{}}},{"exitCode":False},{"canonicalAllServices":True},{"releaseQualified":True}):
        with pytest.raises(ValueError):terminal_current_build({**receipt,**changes},prepared,"a"*64,D05_CURRENT_ROLLOUT)
    with pytest.raises(ValueError):terminal_current_build(receipt,prepared,"a"*64)

def test_ten_role_overlay_is_closed_and_create_only():
    roles=dict(D05_MEMBERSHIP_LATEST.roles)
    assert len(roles)==10 and overlay_roles(D05_CURRENT_ROLLOUT)==roles
    assert runtime_roles(D05_CURRENT_ROLLOUT)==D12_CURRENT_RUNTIME_ROLES
    for selected in ([],["flow"],list(roles)+["flow"],list(roles)+["applicant"],list(roles)[:-1]):
        with pytest.raises(ValueError):overlay_roles(D05_CURRENT_ROLLOUT,selected)
    argv=["docker","compose","-p","elevenid-beta","--project-directory","/owned","-f","/owned/base.yml"]
    actual=compose_recreate_arguments(argv,"/owned/overlay.yml",D05_CURRENT_ROLLOUT,list(roles),no_start=True)
    assert actual[-10:]==list(roles) and "--no-start" in actual and "--detach" not in actual
    with pytest.raises(ValueError):compose_recreate_arguments(argv,"/owned/overlay.yml",D05_CURRENT_ROLLOUT,list(roles))

def test_ten_role_rollout_cannot_relabel_old_build_or_mixed_compose_source_as_product():
    plan={"rolloutProfile":D05_CURRENT_ROLLOUT,"buildProfile":None,"uiRevision":D05_MEMBERSHIP_LATEST.ui_revision,"coreRevision":D05_MEMBERSHIP_LATEST.core_revision,"roleBinaries":dict(D05_MEMBERSHIP_LATEST.roles),"releaseQualified":False,"recordingQualified":False}
    selected_sources(plan,D05_CURRENT_ROLLOUT)
    for changes in ({"uiRevision":D12_PASSPORT_CURRENT.ui_revision},{"uiRevision":"82862f78876f2885a32353ba99a34ccba284faac"},{"buildProfile":D05_MEMBERSHIP_LATEST.name},{"roleBinaries":dict(D12_PASSPORT_CURRENT.roles)}):
        with pytest.raises(ValueError):selected_sources({**plan,**changes},D05_CURRENT_ROLLOUT)
    for profile in (None,"arbitrary","d05-membership-current-native-ten-role"):
        with pytest.raises(ValueError):current_rollout_build(profile)


def test_selected_tenant_and_auth_startup_effects_need_exact_authority():
    from scoped_native_database import current_tenant,schema_environment_bytes
    tenant="750e8400-e29b-41d4-a716-446655440001"
    authority={"approvedTenantId":tenant,"approvedStartupSchemaRoles":["auth"]}
    assert current_tenant({"tenantId":tenant},authority)==tenant
    assert schema_environment_bytes("private-db-url")==b"DATABASE_URL=private-db-url\n"
    assert schema_environment_bytes("private-db-url",tenant)==("DATABASE_URL=private-db-url\nMARTY_ORG_ID="+tenant+"\n").encode()
    for value in (None,"",tenant.upper(),"00000000-0000-0000-0000-000000000000",tenant+"\nUNREVIEWED=1"):
        with pytest.raises(ValueError):current_tenant({"tenantId":value},authority)
    for changed in ({},{"approvedTenantId":tenant},{"approvedTenantId":tenant,"approvedStartupSchemaRoles":["auth","organization"]}):
        with pytest.raises(ValueError):current_tenant({"tenantId":tenant},changed)


@pytest.mark.parametrize("failure",[None,"ledger","tenant","profile"])
def test_native_startup_schema_observation_uses_actual_db_and_closed_read_only_query(tmp_path,failure):
    import json,subprocess
    from types import SimpleNamespace
    from scoped_native_database import current_ten_startup_schema_observation
    from scoped_native_runtime import ref
    tenant="750e8400-e29b-41d4-a716-446655440001"
    projection={"schema":"marty.current-ten-startup-schema/v1","tenantId":tenant,
                **{k:True for k in ("authLedger","organizationLedger","organizationExists","flowTenantOwned","bootstrapTenantOwned")}}
    if failure=="ledger":projection["authLedger"]=False
    if failure=="tenant":projection["tenantId"]="750e8400-e29b-41d4-a716-446655440002"
    calls=[]
    def save(name,data):
        p=tmp_path/name;p.write_bytes(data);return ref(p)
    def result(argv,*,input):
        calls.append(argv)
        assert argv[:3]==["docker","exec","-i"]
        assert "tenant="+tenant in argv and b"BEGIN READ ONLY;" in input and input.endswith(b"ROLLBACK;\n")
        assert b"INSERT " not in input and b"UPDATE " not in input
        return subprocess.CompletedProcess(argv,0,json.dumps(projection).encode(),b"")
    database=SimpleNamespace(rollout_profile="unreviewed" if failure=="profile" else D05_CURRENT_ROLLOUT,tenant_id=tenant,
        identity={"containerId":"a"*64},g={"save_bytes":save},guard=lambda:calls.append("guard"),result=result)
    if failure is None:
        observed=current_ten_startup_schema_observation(database)
        assert observed["projection"]==projection and observed["databaseIdentity"]==database.identity
        assert calls[0]==calls[-1]=="guard" and len(calls)==3
    else:
        with pytest.raises(ValueError):current_ten_startup_schema_observation(database)
        if failure=="profile":assert calls==[]


def test_metadata_order_extends_only_closed_current_ten_with_owned_org_commands():
    import subprocess,json
    module=Path(__file__).parent/"scripts/native-maintenance-metadata.js"
    script="const m=require(process.argv[1]);process.stdout.write(JSON.stringify({old:m.currentDatabaseOrder({}),next:m.currentDatabaseOrder({profile:m.D05_PROFILE}),legacy:m.DATABASE_ORDER}));"
    value=json.loads(subprocess.check_output(["node","-e",script,str(module)]))
    assert value["old"]==value["legacy"]
    assert [x for x in value["next"] if x[0].startswith("ORGANIZATION_")]==[["ORGANIZATION_MIGRATE","rust","organization:migrate"],["ORGANIZATION_VERIFY","rust","organization:verify-owned-schema"]]
    assert [x for x in value["next"] if not x[0].startswith("ORGANIZATION_")]==value["old"]


@pytest.mark.parametrize("profile",[D12_CURRENT_ROLLOUT,D05_CURRENT_ROLLOUT])
def test_current_runtime_positive_keeps_selected_source_and_retained_generations(tmp_path,profile):
    from test_scoped_passport_maintenance import fixture
    from scoped_beta_binary_overlay import validate_runtime_after
    build=current_rollout_build(profile);roles=dict(build.roles)
    _,before,_,_,_=fixture(tmp_path)
    for row in before["roles"]:
        if row["role"]=="canvas-sandbox":row["role"]="event-stream"
        binary=roles.get(row["role"],row["binary"])
        row.update(binary=binary,effectiveUid=10001,configuredRuntimeUid=10001,
                   health="healthy",coreSource="old",kind="native",processExecutableSha256=row["sha256"],
                   executablePath="/usr/local/bin/"+binary if binary else None)
        if binary:row["binaryMounts"]=[{"type":"bind","source":"/old/"+binary,"destination":"/usr/local/bin/"+binary,"writable":False}]
    after=deepcopy(before)
    binaries={role:{"path":"/selected/"+binary,"sha256":"f"*64} for role,binary in roles.items()}
    for index,row in enumerate(after["roles"]):
        row.update(startedAt="2026-10-28T15:00:00Z",hostPid=index+500)
        if row["role"] in roles:
            row.update(containerId=f"{index+100:064x}",source=build.ui_revision,coreSource=build.core_revision,
                       kind="SCOPED_NATIVE_FUNCTIONAL_OVERLAY",sha256="f"*64,processExecutableSha256="f"*64)
            row["binaryMounts"][0]["source"]=binaries[row["role"]]["path"]
            row.update(requiredContainerId=row["containerId"],requiredStartedAt=row["startedAt"],
                       requiredHostPid=row["hostPid"],requiredEffectiveUid=10001,requiredBinaryMounts=deepcopy(row["binaryMounts"]))
    proof=validate_runtime_after(before,after,binaries,D12_CURRENT_RUNTIME_ROLES-set(roles),profile)
    assert proof["uiRevision"]==build.ui_revision and proof["coreRevision"]==build.core_revision
    assert proof["roleBinaries"]==roles and len(proof["maintenanceRestartRoles"])==22-len(roles)


@pytest.mark.parametrize("change",[None,"changed","outside"])
def test_frozen_sources_keep_current_client_identity_and_exact_private_custody(tmp_path,monkeypatch,change):
    import hashlib,json
    import scoped_linux_journal as client
    root=tmp_path/".codex/private";private=root/"operation";private.mkdir(parents=True)
    monkeypatch.setattr(Path,"home",classmethod(lambda cls:tmp_path))
    monkeypatch.setattr(client,"client_path",lambda path:"/unit-test-no-transport/"+Path(path).name)
    worker=private/"scoped_linux_journal.py";worker.write_bytes(b"# previously reviewed frozen worker\n")
    shared=private/"scoped_native_runtime.py";shared.write_bytes(b"# previously reviewed frozen shared source\n")
    transport=private/"desktop_journal_transport.py"
    transport.write_text("import json,subprocess\nclass DesktopPrivateJournalTransport:\n def __init__(self,private,run_id,spec):self.private=private\n def execute(self,request_file,request_sha,worker_file,shared_file,aliases):\n  assert worker_file.parent==shared_file.parent==self.private\n  return subprocess.CompletedProcess([],0,json.dumps({'ok':True,'rootProof':{'root':'/home/canvasrunner/.codex/private/d02-build-journal-11111111-1111-4111-8111-111111111111','device':1,'inode':2,'uid':1000,'mode':448},'bootstrapParent':{'supported':True,'synced':True}}).encode(),b'')\n")
    def bound(p):return {"path":str(p),"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"bytes":p.stat().st_size}
    refs={"worker":bound(worker),"shared":bound(shared),"transport":bound(transport)}
    backend={"schema":1,"backend":"DOCKER_DESKTOP_PRIVATE_JOURNAL_V1","workerSha256":refs["worker"]["sha256"],"sharedSha256":refs["shared"]["sha256"],"rootProof":None,"bootstrapParent":None,"desktop":{"transportSha256":refs["transport"]["sha256"]}}
    if change=="outside":
        outside=root/"outside";outside.mkdir()
        target=outside/worker.name;target.write_bytes(worker.read_bytes());refs["worker"]=bound(target)
        with pytest.raises(ValueError,match="SOURCE_PATH"):client.LinuxBuildJournal(private,"11111111-1111-4111-8111-111111111111",backend,initializing=True,sourceFiles=refs)
        return
    store=client.LinuxBuildJournal(private,"11111111-1111-4111-8111-111111111111",backend,initializing=True,sourceFiles=refs)
    assert type(store) is client.LinuxBuildJournal
    assert hashlib.sha256(Path(client.__file__).read_bytes()).hexdigest()!=backend["workerSha256"]
    if change=="changed":
        shared.write_bytes(b"# changed\n")
        with pytest.raises(ValueError,match="SOURCE_CHANGED"):store.invoke("initialize",None)
        assert list(private.glob("linux-journal-request-*.json"))==[]
    else:
        assert store.invoke("initialize",None)["ok"] is True
        assert list(private.glob("linux-journal-request-*.json"))==[]
