import copy
import json
import os
from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from repair_beta_release_metadata import (
    rendered_delta,
    retire_failed_lock,
    process_identity,
)
from beta_release_metadata import gateway_metadata_model, ui_metadata_model
from scoped_native_runtime import ref


def test_rendered_delta_reuses_model_generators_and_refuses_nonmetadata():
    marker = dict(
        component_revisions={"marty-ui": "a" * 40},
        image_digests={"gateway": "sha256:" + "b" * 64},
    )
    for role in ("gateway", "ui-prod"):
        old = dict(
            services={
                role: dict(
                    image="same",
                    environment={
                        "ELEVENID_COMPONENT_REVISIONS_JSON": "old",
                        "ELEVENID_IMAGE_DIGESTS_JSON": "old",
                    },
                    volumes=[],
                )
            }
        )
        new = (
            gateway_metadata_model(old, marker)
            if role == "gateway"
            else ui_metadata_model(old, "C:/public.json")
        )
        rendered_delta(role, old, new, marker, "C:/public.json")
        bad = copy.deepcopy(new)
        bad["services"][role]["image"] = "changed"
        with pytest.raises(ValueError, match="RENDER_CHANGED_OUTSIDE_METADATA_DELTA"):
            rendered_delta(role, old, bad, marker, "C:/public.json")


def recovery(tmp_path):
    def save(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value), encoding="utf8")
        return ref(path)

    source = "a" * 64
    original = save("input.json", dict(sourceSha256=source))
    lock = save(
        "lock.json",
        dict(
            pid=12345,
            creation=100,
            purpose="BETA_GATEWAY_UI_METADATA",
            runId="owned",
            sourceSha256=source,
        ),
    )
    invocation = save("invocation.json", dict(sourceSha256=source, input=original))
    failure = save("failure.json", dict(sourceSha256=source))
    return dict(
        runId="owned",
        sourceSha256=source,
        failedLock=dict(lock=lock, invocation=invocation, failure=failure),
    )


def test_live_original_owner_cannot_retire_lock(tmp_path):
    config = recovery(tmp_path)
    with pytest.raises(ValueError, match="FAILED_OPERATOR_STILL_LIVE"):
        retire_failed_lock(config, lambda pid: dict(pid=pid, creation=100, live=True))
    assert (tmp_path / "lock.json").exists()


def test_exited_original_lock_retirement_preserves_failure(tmp_path):
    config = recovery(tmp_path)
    result = retire_failed_lock(config, lambda pid: None)
    assert result["state"] == "OWNED_FAILED_METADATA_LOCK_RETIRED"
    assert not (tmp_path / "lock.json").exists()
    assert (tmp_path / "failure.json").exists()


def test_actual_process_creation_reader_is_read_only():
    if os.name != "nt":
        pytest.skip("Windows process API")
    row = process_identity(os.getpid())
    assert row["pid"] == os.getpid() and row["live"] and row["creation"] > 0


def test_recovery_context_is_disabled_and_refuses_unknown_create():
    from repair_beta_release_metadata import recovery_context

    original = dict(
        runId="same",
        sourceSha256="a" * 64,
        oldCids={"ui-prod": "b" * 64, "gateway": "c" * 64},
        executeAuthorized=True,
    )
    failed = dict(
        **{k: original[k] for k in ("runId", "sourceSha256", "oldCids")},
        newCids={},
        before={"path": "before"},
        pending="apply-stop-ui-prod",
    )
    result = recovery_context(
        original,
        failed,
        {"path": "state"},
        {"path": "failure"},
        {"path": "invocation"},
        {"path": "lock"},
        "fresh-root",
    )
    assert result["recoveryMode"] == "rollback"
    assert all(
        result[key] is False
        for key in (
            "executeAuthorized",
            "preflightAuthorized",
            "rollbackAuthorized",
            "helperCleanupAuthorized",
            "lockRetirementAuthorized",
        )
    )
    assert result["failedLock"]["failure"] == {"path": "failure"}
    assert original["executeAuthorized"] is True
    failed["pending"] = "apply-create-ui-prod"
    with pytest.raises(
        ValueError, match="UNKNOWN_CREATE_REQUIRES_READONLY_RECONCILIATION"
    ):
        recovery_context(original, failed, {}, {}, {}, {}, "fresh-root")


def test_actual_operator_imports_from_the_complete_isolated_source_closure(tmp_path):
    import shutil
    import subprocess
    from repair_beta_release_metadata import SOURCE_FILES

    source = Path(__file__).resolve().parents[2] / "scripts"
    isolated = tmp_path / "isolated" / "scripts"
    isolated.mkdir(parents=True)
    for filename in SOURCE_FILES:
        target = isolated / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / filename, target)
    code = (
        "import sys; sys.path.insert(0, "
        + repr(str(isolated))
        + "); import repair_beta_release_metadata; print('IMPORTED_CLOSED_OPERATOR')"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, timeout=30
    )
    assert result.returncode == 0, (
        "Isolated operator import failed before any Docker command"
    )
    assert result.stdout.strip() == b"IMPORTED_CLOSED_OPERATOR"


def nginx_principal_fixture():
    ui = dict(
        Id="ui",
        Image="image",
        Config=dict(User="0"),
        State=dict(Pid=900, StartedAt="current"),
    )
    master = dict(
        startTicks=100, executablePath="/usr/sbin/nginx", executableSha256="a" * 64
    )
    workers = [
        dict(
            namespacePids=[901 + index, 2 + index],
            parentHostPid=900,
            startTicks=101 + index,
            uids=[101] * 4,
            gids=[101] * 4,
            supplementaryGroups=[101, 101],
            executablePath=master["executablePath"],
            executableSha256=master["executableSha256"],
        )
        for index in range(2)
    ]
    witness = dict(
        state="ACTUAL_NGINX_SERVING_PRINCIPAL_AND_EXE_VERIFIED_READONLY",
        containerId="ui",
        imageId="image",
        masterHostPid=900,
        containerStartedAt="current",
        master=master,
        workers=workers,
    )
    raw = b"MASTER\t100\nWORKER\t2\t1\t101\t101,101,101,101\t101,101,101,101\t101,101\nWORKER\t3\t1\t102\t101,101,101,101\t101,101,101,101\t101,101\n"
    return ui, witness, raw


def test_nginx_serving_identity_comes_from_workers_and_keeps_root_master():
    from repair_beta_release_metadata import validate_nginx_principal

    ui, witness, raw = nginx_principal_fixture()
    result = validate_nginx_principal(ui, witness, raw, raw)
    assert result == dict(uid=101, gid=101, permissionGroups=[101], workerCount=2)
    assert ui["Config"]["User"] == "0"


def test_nginx_changed_missing_root_worker_and_wrong_witness_refuse():
    from repair_beta_release_metadata import validate_nginx_principal

    ui, witness, raw = nginx_principal_fixture()
    with pytest.raises(ValueError, match="NGINX_WORKER_IDENTITY_CHANGED"):
        validate_nginx_principal(
            ui,
            witness,
            raw.replace(b"2\t1\t101", b"2\t1\t999"),
            raw.replace(b"2\t1\t101", b"2\t1\t999"),
        )
    missing = b"\n".join(raw.splitlines()[:-1]) + b"\n"
    with pytest.raises(ValueError, match="NGINX_WORKER_SET_CHANGED"):
        validate_nginx_principal(ui, witness, missing, missing)
    root = copy.deepcopy(witness)
    for worker in root["workers"]:
        worker["uids"] = [0] * 4
    root_raw = raw.replace(
        b"101,101,101,101\t101,101,101,101", b"0,0,0,0\t101,101,101,101"
    )
    with pytest.raises(ValueError, match="NGINX_NONROOT_SERVING_PRINCIPAL_REQUIRED"):
        validate_nginx_principal(ui, root, root_raw, root_raw)
    with pytest.raises(ValueError, match="NGINX_EXE_WITNESS_REQUIRED"):
        validate_nginx_principal(ui, {**witness, "state": "UNVERIFIED"}, raw, raw)


def test_wrong_nginx_witness_hash_refuses_before_any_docker_command(
    tmp_path, monkeypatch
):
    import repair_beta_release_metadata as operator

    public = tmp_path / "public.json"
    public.write_text("{}", encoding="utf8")
    op = operator.Operation.__new__(operator.Operation)
    op.c = dict(publicManifest=ref(public), uiServingPrincipal=dict(sha256="0" * 64))
    op.models = {"ui-prod": dict(services={"ui-prod": dict(image="unchanged")})}
    monkeypatch.setattr(operator, "acl_digest", lambda _: "a" * 64)
    with pytest.raises(ValueError, match="REVIEWED_NGINX_PRINCIPAL_REQUIRED"):
        op.readability(set())


def test_public_metadata_uses_honest_audit_agent_and_preserves_byte_guards(tmp_path, monkeypatch):
    import repair_beta_release_metadata as operator

    marker = {"release": "actual"}
    manifest = b'{"functional":true}'
    calls = []

    class Response:
        status = 200

        def __init__(self, request):
            self.url = request.full_url

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            assert limit == 4 * 1024 * 1024 + 1
            return json.dumps(marker).encode() if self.url.endswith("marty-release") else manifest

    def open_request(request, timeout):
        assert request.get_header("User-agent") == "marty-demo-audit/1.0"
        assert request.get_header("Accept-encoding") == "identity"
        assert timeout == 20
        calls.append(request.full_url)
        return Response(request)

    monkeypatch.setattr(operator.urllib.request, "urlopen", open_request)
    op = operator.Operation.__new__(operator.Operation)
    op.output = tmp_path
    expected = {"sha256": operator.hashlib.sha256(manifest).hexdigest()}
    result = op.public(marker, expected)
    assert len(calls) == 2
    assert result["manifest"]["sha256"] == expected["sha256"]


@pytest.mark.parametrize("refuse", [False, True])
def test_execute_delegates_preview_generation_to_existing_guard(tmp_path, refuse):
    import repair_beta_release_metadata as operator
    from types import SimpleNamespace

    previous = {role: {"Id": role, "NetworkSettings": {"unchanged": True}} for role in operator.ROLES}
    calls = []

    def old_guard(row, *, running):
        assert running is True
        calls.append(row["Id"])
        if refuse:
            raise RuntimeError("OLD_MOUNTS_CHANGED")
        return copy.deepcopy(row)

    refs = {}
    for role, row in previous.items():
        file = tmp_path / (role + ".json")
        file.write_text(json.dumps(row), encoding="utf8")
        refs[role] = ref(file)
    op = operator.Operation.__new__(operator.Operation)
    op.g, op.output, op.state = SimpleNamespace(old_guard=old_guard), tmp_path, {}
    op.baseline = lambda: (set(previous), copy.deepcopy(previous))
    op.persist = lambda: None
    op.models = {role: {} for role in previous}
    op.c = {"oldCids": {role: role for role in previous}}
    reached = []

    def stop(*args):
        reached.append(args)
        raise RuntimeError("PRE_EFFECT_BOUNDARY_REACHED")

    op.stop_generation = stop
    with pytest.raises(RuntimeError, match="OLD_MOUNTS_CHANGED" if refuse else "PRE_EFFECT_BOUNDARY_REACHED"):
        op.execute({"allIds": sorted(previous), "before": refs})
    assert calls == ([operator.ROLES[0]] if refuse else list(operator.ROLES))
    assert bool(reached) is not refuse
    assert (tmp_path / "before.json").exists() is not refuse
