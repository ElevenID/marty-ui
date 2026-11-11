"""Exercise recovery with authenticated-artifact and cluster doubles only."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
from types import SimpleNamespace
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from test_inspect_kubernetes_legacy_credentials import (
    flow, archive, ROOT_TOKEN, RECOVERY_KEY, KUBECONFIG_KEY, POD_UID,
)
import bootstrap_kubernetes_openbao as bootstrap
from test_bootstrap_kubernetes_openbao import assert_private_directory_command, capture_private_directory_commands
import inspect_kubernetes_legacy_credentials as inspection
import recover_kubernetes_legacy_credentials as recovery


pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux private recovery transport")


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode()


@pytest.fixture
def recovery_flow(flow, monkeypatch):
    item = flow
    item.args.operation_dir = item.args.operation_dir.with_name("recovery")
    item.args.stage_only, item.args.activate_existing_secrets = True, False
    item.clock = SimpleNamespace(wall=1800000000.0, monotonic=1000.0)
    monkeypatch.setattr(recovery, "time", SimpleNamespace(
        time=lambda: item.clock.wall, monotonic=lambda: item.clock.monotonic))
    item.remote, item.patch_calls, item.patch_timeouts = {}, [], []
    item.stage_calls = item.qualification_calls = 0
    item.tamper_plan = item.tamper_stage = None
    item.patch_failure = None
    item.patch_failure_index = 0
    item.after_qualification = None
    item.export_calls = []
    item.plan_bytes = None
    item.replacements = (set(bootstrap.SELFHOST_TLS_FILES) - {"workload_identity_ca_cert"}
        | bootstrap.KEYCLOAK_FILES | set(bootstrap.TOKEN_FILES.values()) - {"openbao_bootstrap_token"})
    assert len(item.replacements) == 51 and item.replacements <= set(item.snapshot)
    catalog = json.loads((bootstrap.ROOT / "deploy-config/catalog/kubernetes-secrets.json").read_bytes())
    item.mappings, item.secrets = {}, {}
    for secret in catalog["secrets"]:
        fields = {key: field["env"].lower() for key, field in secret["fields"].items()
                  if field.get("env", "").lower() in item.replacements}
        if not fields:
            continue
        item.mappings[secret["name"]] = fields
        data = {key: b64(item.snapshot[file][0].replace(b"\r", b"").rstrip(b"\n")) for key, file in fields.items()}
        for key in secret["fields"]:
            data.setdefault(key, b64(("PRIVATE_UNCHANGED_" + key).encode()))
        data.update({"foreign.binary": b64(b"\0\xff\r\n"), "foreign.empty": ""})
        item.secrets[secret["name"]] = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
            "metadata": {"name": secret["name"], "namespace": item.binding["namespace"],
                "uid": str(uuid.UUID(int=100 + len(item.secrets))), "resourceVersion": str(1000 + len(item.secrets)),
                "labels": {"retained": "yes"}, "annotations": {"example.test/keep": "retained"},
                "managedFields": [{"manager": "original-owner"}]}, "data": data}
    assert len(item.mappings) == 34 and sum(map(len, item.mappings.values())) == 51
    item.names = sorted(item.mappings)
    item.original_secrets = deepcopy(item.secrets)
    item.bound = recovery.full_binding(item.complete, item.binding, item.args.chart_source_sha)

    def stage_output():
        candidate = deepcopy(item.snapshot)
        for name in item.replacements:
            candidate[name] = (b"PRIVATE_REPLACEMENT_" + name.encode(), candidate[name][1])
            item.remote["stage/inputs/" + name] = candidate[name][0], 0o600
        item.candidate = candidate
        item.remote.update({"stage/candidate/" + name: value for name, value in candidate.items()})
        attempt = {"schema": recovery.STAGE_SCHEMA, "binding": item.bound,
            "inspectionSha256": recovery.sha256(item.remote["inspection.json"][0]),
            "replacementFiles": sorted(item.replacements), "activation": False}
        complete = {"schema": recovery.STAGE_SCHEMA, "binding": item.bound, "status": "staged-not-activated",
            "candidate": "candidate", "replacementCount": 51, "inputBindings": recovery.input_bindings(candidate),
            "completedRequests": 120, "activation": False}
        item.remote["stage/attempt.json"] = bootstrap.encoded(attempt), 0o600
        for index in range(120):
            item.remote[f"stage/request-{index:03}.json"] = bootstrap.encoded({"syntheticRequest": index}), 0o600
            item.remote[f"stage/response-{index:03}.json"] = bootstrap.encoded({"privateSyntheticResponse": index}), 0o600
        complete["journalBindings"] = {f"{kind}-{index:03}.json": recovery.sha256(item.remote[f"stage/{kind}-{index:03}.json"][0])
            for kind in ("request", "response") for index in range(120)}
        item.remote["stage/complete.json"] = bootstrap.encoded(complete), 0o600
        if item.tamper_stage:
            item.tamper_stage(item.remote)
        return {"schema": recovery.STAGE_SCHEMA, "status": "staged-not-activated",
            "candidate": recovery.REMOTE_STAGE + "/candidate", "replacementCount": 51, "activation": False,
            "stagingReceiptSha256": recovery.sha256(item.remote["stage/complete.json"][0])}

    def qualified_output():
        observed = json.loads(item.remote["secrets.json"][0])
        entries = []
        for old in observed["items"]:
            name, metadata = old["metadata"]["name"], old["metadata"]
            patch = [{"op": "test", "path": "/metadata/uid", "value": metadata["uid"]},
                     {"op": "test", "path": "/metadata/resourceVersion", "value": metadata["resourceVersion"]},
                     {"op": "test", "path": "/data", "value": old["data"]}]
            patch.extend({"op": "replace", "path": "/data/" + key, "value": b64(item.candidate[file][0])}
                         for key, file in sorted(item.mappings[name].items()))
            entries.append({"name": name, "namespace": item.binding["namespace"], "uid": metadata["uid"],
                            "resourceVersion": metadata["resourceVersion"], "patch": patch})
        native = {"schema": recovery.PLAN_SCHEMA, "status": "planned-not-qualified-or-activated", "private": True,
            "credentialsQualified": False, "activationPerformed": False, "atomicAcrossSecrets": False,
            "binding": item.bound, "currentInputs": recovery.input_bindings(item.snapshot),
            "candidateInputs": recovery.input_bindings(item.candidate), "secrets": entries}
        report_hash = recovery.sha256(item.remote["inspection.json"][0])
        plan = {"schema": recovery.QUALIFICATION_SCHEMA, "binding": item.bound, "status": "qualified-not-activated",
            "qualifiedAtUnixSeconds": int(item.clock.wall), "validBeforeUnixSeconds": int(item.clock.wall) + 300,
            "inspectionSha256": report_hash, "stagingReceiptSha256": recovery.sha256(item.remote["stage/complete.json"][0]),
            "credentialsQualified": True, "credentialsIssued": False, "activation": False, "nativePlan": native}
        item.remote["qualification/attempt.json"] = bootstrap.encoded({"schema": recovery.QUALIFICATION_SCHEMA,
            "binding": item.bound, "inspectionSha256": report_hash, "startedAtUnixSeconds": int(item.clock.wall),
            "currentInputs": recovery.input_bindings(item.snapshot), "candidateInputs": recovery.input_bindings(item.candidate),
            "credentialsIssued": False, "activation": False}), 0o600
        for index in range(51):
            item.remote[f"qualification/request-{index:03}.json"] = bootstrap.encoded({"syntheticRequest": index}), 0o600
            item.remote[f"qualification/response-{index:03}.json"] = bootstrap.encoded({"privateSyntheticResponse": index}), 0o600
        plan["qualificationJournalBindings"] = {f"{kind}-{index:03}.json": recovery.sha256(
            item.remote[f"qualification/{kind}-{index:03}.json"][0])
            for kind in ("request", "response") for index in range(51)}
        if item.tamper_plan:
            item.tamper_plan(plan)
        item.plan_bytes = bootstrap.encoded(plan)
        item.remote["qualification/plan.json"] = item.plan_bytes, 0o600
        return {"schema": recovery.QUALIFICATION_SCHEMA, "status": "qualified-not-activated",
            "credentialsQualified": True, "credentialsIssued": False, "activation": False, "secretCount": 34,
            "replacementCount": 51, "validBeforeUnixSeconds": plan["validBeforeUnixSeconds"],
            "privatePlanWritten": True, "privatePlanSha256": recovery.sha256(item.plan_bytes)}

    base_transport = bootstrap.Transport
    class Transport(base_transport):
        def __init__(self, operation, kubeconfig, namespace, kubectl):
            super().__init__(operation, kubeconfig, namespace, kubectl)
            self.base = [kubectl, "--kubeconfig", str(kubeconfig), "--namespace", namespace]

        def kubectl(self, operation, *command, data=None, **kwargs):
            if operation == "legacy Secret observation":
                assert command[:2] == ("get", "secret") and command[-2:] == ("-o", "json")
                item.events.append(operation)
                if item.failure == "missing-secret" and command[2] == item.names[-1]:
                    raise bootstrap.BootstrapError("synthetic absent existing Secret")
                return bootstrap.encoded(item.secrets[command[2]])
            return super().kubectl(operation, *command, data=data, **kwargs)

        def upload(self, pod, destination, contents, **kwargs):
            super().upload(pod, destination, contents, **kwargs)
            if destination == recovery.REMOTE_SECRETS:
                item.remote["secrets.json"] = contents, 0o600

        def execute(self, pod, command, *, data=None, **kwargs):
            if command[0] == "sha256sum":
                sources = {inspection.REMOTE_OPERATOR: item.operator, inspection.REMOTE_ROOT: ROOT_TOKEN}
                if item.failure == "remote-root-drift" and item.qualification_calls:
                    sources[inspection.REMOTE_ROOT] = b"foreign-root"
                return b"".join(hashlib.sha256(sources[path]).hexdigest().encode() + b"  " + path.encode() + b"\n"
                                for path in command[1:])
            if command[:3] == ["/bin/sh", "-ec", bootstrap.REMOTE_ARCHIVE_COMMAND]:
                item.export_calls.append(set(item.remote))
                if item.failure == "export-stage" and item.stage_calls:
                    raise bootstrap.BootstrapError("synthetic interrupted evidence export")
                if item.failure == "export-qualified" and item.qualification_calls:
                    raise bootstrap.BootstrapError("synthetic interrupted qualified export")
                if item.after_qualification and item.qualification_calls:
                    callback, item.after_qualification = item.after_qualification, None
                    callback(item)
                return archive(item.remote)
            if command[:3] == [inspection.REMOTE_OPERATOR, "operator", "kubernetes-legacy-recovery-targets"]:
                assert json.loads(data)["current"] == inspection.REMOTE_CURRENT
                return bootstrap.encoded({"schema": recovery.TARGETS_SCHEMA, "namespace": item.binding["namespace"],
                                          "names": item.names, "replacementCount": 51})
            if command[:3] == [inspection.REMOTE_OPERATOR, "operator", "kubernetes-legacy-recovery-stage"]:
                item.stage_calls += 1
                assert kwargs["timeout"] <= 600 and item.stage_calls == 1
                request = json.loads(data)
                assert request["output"] == recovery.REMOTE_STAGE and request["inspection"] == inspection.REMOTE_REPORT
                value = stage_output()
                if item.failure == "stage-uncertain":
                    raise bootstrap.BootstrapError("synthetic native outcome unavailable")
                if item.failure == "stage-hash":
                    value["stagingReceiptSha256"] = "0" * 64
                return bootstrap.encoded(value)
            if command[:3] == [inspection.REMOTE_OPERATOR, "operator", "kubernetes-legacy-recovery-qualify"]:
                item.qualification_calls += 1
                assert kwargs["timeout"] <= 300 and item.qualification_calls == 1
                request = json.loads(data)
                assert request["output"] == recovery.REMOTE_QUALIFICATION and request["staged"] == recovery.REMOTE_STAGE
                assert request["secrets"] == recovery.REMOTE_SECRETS
                value = qualified_output()
                if item.failure == "qualification-uncertain":
                    raise bootstrap.BootstrapError("synthetic qualification outcome unavailable")
                if item.failure == "plan-hash":
                    value["privatePlanSha256"] = "0" * 64
                return bootstrap.encoded(value)
            result = super().execute(pod, command, data=data, **kwargs)
            if command[:3] == [inspection.REMOTE_OPERATOR, "operator", "kubernetes-legacy-recovery-inspect"]:
                item.remote["inspection.json"] = bootstrap.encoded(item.report), 0o600
            return result

    base_process = subprocess.run
    def process(command, **kwargs):
        if command[-2:] == ["operator", "kubernetes-legacy-recovery-stage-contract"]:
            assert kwargs["env"] == {} and kwargs["stdin"] == subprocess.DEVNULL
            value = deepcopy(recovery.CONTRACT)
            if item.failure == "stage-contract":
                value["scopeMutation"] = True
            return SimpleNamespace(returncode=0, stdout=bootstrap.encoded(value), stderr=b"")
        if command[0] != "/synthetic/kubectl":
            return base_process(command, **kwargs)
        assert command[5:7] == ["patch", "secret"] and command[-4:] == ["--type=json", "--patch-file=/dev/stdin", "-o", "json"]
        name, index = command[7], len(item.patch_calls)
        activation = item.args.operation_dir / "activation"
        assert (item.args.operation_dir / "native-qualified-evidence.tar").is_file()
        assert (item.args.operation_dir / "qualified-plan.json").read_bytes() == item.plan_bytes
        assert len(list((item.args.operation_dir / "secret-preimages").glob("secret-*.json"))) == 34
        intent = json.loads((activation / f"intent-{index:02}.json").read_bytes())
        assert intent["name"] == name and intent["patchSha256"] == recovery.sha256(kwargs["input"])
        item.patch_calls.append((command, kwargs["input"]))
        item.patch_timeouts.append(kwargs["timeout"])
        failure = item.patch_failure if index == item.patch_failure_index else None
        if failure == "nonzero":
            return SimpleNamespace(returncode=1, stdout=b"PRIVATE_FAILED_RESPONSE", stderr=b"PRIVATE_FAILED_DIAGNOSTIC")
        old = item.secrets[name]
        if failure == "stale-rv":
            old["metadata"]["resourceVersion"] = "999999"
        after = deepcopy(old)
        for operation in json.loads(kwargs["input"]):
            if operation["op"] == "test":
                actual = after["data"] if operation["path"] == "/data" else after["metadata"][operation["path"].split("/")[-1]]
                if actual != operation["value"]:
                    return SimpleNamespace(returncode=1, stdout=b"PRIVATE_STALE_RESPONSE", stderr=b"PRIVATE_PRECONDITION_FAILURE")
            else:
                assert operation["op"] == "replace"
                key = operation["path"][len("/data/"):].replace("~1", "/").replace("~0", "~")
                assert key in after["data"]
                after["data"][key] = operation["value"]
        after["metadata"]["resourceVersion"] = str(2000 + index)
        after["metadata"]["managedFields"] = [{"manager": "recovery-json-patch"}]
        item.secrets[name] = after
        if failure == "timeout-after-write":
            raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=b"PRIVATE_PARTIAL_REPLY", stderr=b"PRIVATE_TIMEOUT_DIAGNOSTIC")
        reply = deepcopy(after)
        if failure == "foreign-data":
            reply["data"]["foreign.binary"] = b64(b"changed-outside-plan")
        if failure == "metadata":
            reply["metadata"]["labels"]["retained"] = "lost"
        if failure == "uid":
            reply["metadata"]["uid"] = str(uuid.UUID(int=999999))
        if failure == "duplicate-json":
            return SimpleNamespace(returncode=0, stdout=b'{"kind":"Secret","kind":"Secret"}', stderr=b"")
        if failure == "clock-expired":
            item.clock.monotonic += 301
        return SimpleNamespace(returncode=0, stdout=bootstrap.encoded(reply), stderr=b"PRIVATE_SUCCESS_DIAGNOSTIC")

    monkeypatch.setattr(bootstrap, "Transport", Transport)
    monkeypatch.setattr(recovery.subprocess, "run", process)
    return item


def state_snapshot(item):
    return {path.relative_to(item.args.state_dir): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
            for path in item.args.state_dir.rglob("*") if path.is_file()}


def activate(item):
    item.args.stage_only, item.args.activate_existing_secrets = False, True


def test_recovery_private_directories_clear_inherited_setgid(recovery_flow, tmp_path, monkeypatch):
    commands = capture_private_directory_commands(monkeypatch, bootstrap.Transport)
    recovery.recover(recovery_flow.args)
    assert len(commands) == 1
    assert_private_directory_command(commands[0], tmp_path)


def test_stage_only_authenticates_qualifies_exports_and_never_patches(recovery_flow, capsys):
    item = recovery_flow
    before = state_snapshot(item)
    recovery.recover(item.args)
    assert item.auth_calls == 2 and item.target_calls == 1
    assert item.stage_calls == item.qualification_calls == 1 and not item.patch_calls
    assert len(item.creates) == len(item.deletions) == 1
    assert state_snapshot(item) == before
    completion = json.loads((item.args.operation_dir / "recovery-complete.json").read_bytes())
    assert completion["status"] == "staged-and-qualified-not-activated" and completion["activation"] is False
    assert completion["credentialsIssued"] is True and completion["verifiedSecretCount"] == 0
    assert recovery.private.current_snapshot(item.args.operation_dir / "candidate") == item.candidate
    for path in item.args.operation_dir.rglob("*"):
        if path.is_dir():
            assert stat.S_IMODE(path.stat().st_mode) == 0o700
        elif path.parent.name != "candidate" and path.name != "marty-deploy":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
    uploaded = b"\n".join(value for _, value in item.uploads)
    for forbidden in (RECOVERY_KEY.encode(), KUBECONFIG_KEY.encode(), b"PRIVATE_RECOVERY_HEX_CANARY"):
        assert forbidden not in uploaded
    public = capsys.readouterr()
    assert ROOT_TOKEN.decode() not in public.out + public.err
    assert recovery.sha256(ROOT_TOKEN) not in public.out + public.err
    assert "activation was not requested" in public.out


def test_activation_exports_all_evidence_and_preimages_before_exact_34_guarded_writes(recovery_flow, capsys):
    item = recovery_flow
    activate(item)
    before = state_snapshot(item)
    recovery.recover(item.args)
    assert len(item.patch_calls) == 34 and all(0 < timeout <= 30 for timeout in item.patch_timeouts)
    assert item.stage_calls == item.qualification_calls == 1
    assert state_snapshot(item) == before and len(item.deletions) == 1
    for name, old in item.original_secrets.items():
        new = item.secrets[name]
        for key, value in old["data"].items():
            if key in item.mappings[name]:
                assert new["data"][key] == b64(item.candidate[item.mappings[name][key]][0])
            else:
                assert new["data"][key] == value
        for key, value in old["metadata"].items():
            if key not in ("resourceVersion", "managedFields"):
                assert new["metadata"][key] == value
    assert len(list((item.args.operation_dir / "activation").glob("verified-*.json"))) == 34
    completion = json.loads((item.args.operation_dir / "recovery-complete.json").read_bytes())
    assert completion["activation"] is True and completion["verifiedSecretCount"] == 34
    assert completion["workloadsRestarted"] is False
    argv = repr([command for command, _ in item.patch_calls])
    assert "PRIVATE_" not in argv and ROOT_TOKEN.decode() not in argv
    public = capsys.readouterr()
    assert "Verified 34 existing Secret updates" in public.out
    assert "PRIVATE_" not in public.out + public.err


def sealed_reload_fixture(request):
    """Exercise the real private closure at the isolated caller boundary."""
    import reload_kubernetes_legacy_workloads as reload
    evidence = reload.Evidence(request.output)
    evidence.write("projection-proof-00.json", bootstrap.encoded({"syntheticCallerBoundary": True}))
    private_evidence = evidence.complete({"schema": reload.SCHEMA, "binding": request.binding,
        "status": "new-ready-pods-with-matching-projected-credentials",
        "privatePlanSha256": request.qualified_plan_sha256, "reloadCount": 16,
        "inMemoryProviderUseProved": False, "fullEnvironmentHealthAssessed": False})
    return {"schema": reload.SCHEMA, "status": "sixteen-ready-pods-with-matching-projections", "reloadCount": 16,
            "privateEvidenceWritten": True, "privateEvidence": private_evidence,
            "fullEnvironmentHealthAssessed": False, "inMemoryProviderUseProved": False}


def test_explicit_reload_receives_verified_postimages_after_durable_credential_completion(recovery_flow, monkeypatch, capsys):
    import reload_kubernetes_legacy_workloads as reload
    item = recovery_flow
    activate(item)
    item.args.reload_owned_workloads = True
    calls = []

    def run(request, transport, freshness, phase_guard):
        assert len(item.patch_calls) == 34 and len(item.deletions) == 1
        assert request.output == item.args.operation_dir / "reload"
        assert request.original == item.original and request.binding == item.bound
        assert request.qualified_plan == item.plan_bytes
        assert request.qualified_plan_sha256 == recovery.sha256(item.plan_bytes)
        assert {name: json.loads(raw) for name, raw in request.verified_secrets.items()} == item.secrets
        credential = json.loads((item.args.operation_dir / "recovery-complete.json").read_bytes())
        assert credential["verifiedSecretCount"] == 34 and credential["workloadsRestarted"] is False
        freshness.check()
        phase_guard(SimpleNamespace(namespace=transport.namespace))
        calls.append(request)
        return sealed_reload_fixture(request)

    monkeypatch.setattr(reload, "reload_workloads", run)
    recovery.recover(item.args)
    assert len(calls) == 1
    combined = json.loads((item.args.operation_dir / "recovery-reload-complete.json").read_bytes())
    assert combined["reload"]["reloadCount"] == 16 and combined["fullEnvironmentHealthAssessed"] is False
    assert combined["credentialCompletionSha256"] == recovery.sha256((item.args.operation_dir / "recovery-complete.json").read_bytes())
    evidence = combined["reload"]["privateEvidence"]
    assert evidence["completionSha256"] == recovery.sha256((item.args.operation_dir / "reload/reload-complete.json").read_bytes())
    reload.verify_completed_evidence(item.args.operation_dir / "reload", combined["reload"], item.bound,
                                     recovery.sha256(item.plan_bytes))
    assert "16 new Ready Pods" in capsys.readouterr().out


@pytest.mark.parametrize("mutation", ["proof", "missing-proof", "extra-record", "proof-mode", "completion", "directory-mode"])
def test_post_return_journal_drift_prevents_the_callers_combined_completion(recovery_flow, monkeypatch, capsys, mutation):
    import reload_kubernetes_legacy_workloads as reload
    item = recovery_flow
    activate(item)
    item.args.reload_owned_workloads = True
    state = SimpleNamespace(returned=False, tampered=False)

    def run(request, *_):
        result = sealed_reload_fixture(request)
        state.returned = True
        return result

    original = recovery.inspection.sources.recheck

    def retained(expected):
        original(expected)
        if not state.returned or state.tampered:
            return
        output = item.args.operation_dir / "reload"
        proof = output / "projection-proof-00.json"
        if mutation == "proof":
            proof.write_bytes(proof.read_bytes() + b"\n")
        elif mutation == "missing-proof":
            proof.unlink()
        elif mutation == "extra-record":
            bootstrap.write_new(output / "observations/untracked.json", b"{}\n")
        elif mutation == "proof-mode":
            proof.chmod(0o644)
        elif mutation == "completion":
            completion = output / "reload-complete.json"
            completion.write_bytes(completion.read_bytes() + b"\n")
        elif mutation == "directory-mode":
            (output / "observations").chmod(0o755)
        state.tampered = True

    monkeypatch.setattr(reload, "reload_workloads", run)
    monkeypatch.setattr(recovery.inspection.sources, "recheck", retained)
    with pytest.raises(bootstrap.BootstrapError):
        recovery.recover(item.args)
    assert state.returned and state.tampered and len(item.patch_calls) == 34 and len(item.deletions) == 1
    assert not (item.args.operation_dir / "recovery-reload-complete.json").exists()
    assert (item.args.operation_dir / "recovery-complete.json").exists()
    stopped = json.loads((item.args.operation_dir / "recovery-reload-stopped.json").read_bytes())
    assert stopped["credentialActivationComplete"] is True and stopped["workloadReloadCompletionAccepted"] is False
    assert stopped["automaticReplay"] is False and "16 new Ready Pods" not in capsys.readouterr().out


def test_combined_receipt_write_race_preserves_evidence_and_refuses_success(recovery_flow, monkeypatch, capsys):
    import reload_kubernetes_legacy_workloads as reload
    item = recovery_flow
    activate(item)
    item.args.reload_owned_workloads = True
    monkeypatch.setattr(reload, "reload_workloads", lambda request, *_: sealed_reload_fixture(request))
    original = bootstrap.write_new

    def written(path, raw, *args, **kwargs):
        original(path, raw, *args, **kwargs)
        if path == item.args.operation_dir / "recovery-reload-complete.json":
            proof = item.args.operation_dir / "reload/projection-proof-00.json"
            proof.write_bytes(proof.read_bytes() + b"\n")

    monkeypatch.setattr(bootstrap, "write_new", written)
    with pytest.raises(bootstrap.BootstrapError):
        recovery.recover(item.args)
    assert (item.args.operation_dir / "recovery-reload-stopped.json").exists()
    assert (item.args.operation_dir / "recovery-reload-complete.json").exists()
    assert (item.args.operation_dir / "recovery-complete.json").exists()
    assert "16 new Ready Pods" not in capsys.readouterr().out


def test_reload_failure_keeps_the_completed_credential_receipt_without_claiming_full_recovery(recovery_flow, monkeypatch, capsys):
    import reload_kubernetes_legacy_workloads as reload
    item = recovery_flow
    activate(item)
    item.args.reload_owned_workloads = True

    def fail(request, transport, freshness, phase_guard):
        phase_guard(SimpleNamespace(namespace=transport.namespace))
        bootstrap.private_directory(request.output)
        bootstrap.write_new(request.output / "reload-stopped.json", bootstrap.encoded({"reloadComplete": False}))
        raise bootstrap.BootstrapError("synthetic uncertain reload; preserve evidence")

    monkeypatch.setattr(reload, "reload_workloads", fail)
    with pytest.raises(bootstrap.BootstrapError, match="uncertain reload"):
        recovery.recover(item.args)
    credential = json.loads((item.args.operation_dir / "recovery-complete.json").read_bytes())
    assert credential["activation"] is True and credential["verifiedSecretCount"] == 34
    assert credential["workloadsRestarted"] is False and len(item.deletions) == 1
    assert (item.args.operation_dir / "reload/reload-stopped.json").is_file()
    assert not (item.args.operation_dir / "recovery-reload-complete.json").exists()
    assert "Verified 34" not in capsys.readouterr().out


def test_incomplete_secret_activation_never_calls_workload_reload(recovery_flow, monkeypatch):
    import reload_kubernetes_legacy_workloads as reload
    item = recovery_flow
    activate(item)
    item.args.reload_owned_workloads = True
    item.patch_failure, item.patch_failure_index = "timeout-after-write", 1
    monkeypatch.setattr(reload, "reload_workloads", lambda *_: pytest.fail("partial Secret activation cannot restart workloads"))
    with pytest.raises(bootstrap.BootstrapError):
        recovery.recover(item.args)
    assert not (item.args.operation_dir / "recovery-complete.json").exists()
    assert not (item.args.operation_dir / "recovery-reload-complete.json").exists()


@pytest.mark.parametrize("reload_value", [True, 1, "yes"])
def test_owned_reload_needs_explicit_secret_activation_before_any_private_attempt(recovery_flow, reload_value):
    item = recovery_flow
    item.args.reload_owned_workloads = reload_value
    with pytest.raises(bootstrap.BootstrapError, match="reload requires explicit existing-Secret activation"):
        recovery.recover(item.args)
    assert not item.args.operation_dir.exists() and not item.creates


@pytest.mark.parametrize("failure", ["source-mismatch", "stage-contract", "stage-hash", "plan-hash", "missing-secret", "remote-root-drift"])
def test_contract_hash_target_or_root_failures_prevent_activation(recovery_flow, failure):
    item = recovery_flow
    activate(item)
    item.failure = failure
    with pytest.raises(bootstrap.BootstrapError):
        recovery.recover(item.args)
    assert not item.patch_calls
    assert not (item.args.operation_dir / "recovery-complete.json").exists()
    if failure in ("source-mismatch", "stage-contract"):
        assert not item.creates and "openbao-initialization.json" not in item.reads


@pytest.mark.parametrize("failure", ["stage-uncertain", "qualification-uncertain", "export-stage", "export-qualified"])
def test_uncertain_native_or_export_outcomes_retain_bounded_producer_without_retry(recovery_flow, failure):
    item = recovery_flow
    activate(item)
    item.failure = failure
    with pytest.raises(bootstrap.BootstrapError):
        recovery.recover(item.args)
    assert item.stage_calls == 1 and item.qualification_calls <= 1
    assert not item.patch_calls and not item.deletions
    pointer = json.loads((item.args.operation_dir / "transport-pod.json").read_bytes())
    assert pointer["uid"] == POD_UID and pointer["activeDeadlineSeconds"] == 1200
    retained = json.loads((item.args.operation_dir / "producer-retained.json").read_bytes())
    assert retained["completionRecorded"] is False
    assert not (item.args.operation_dir / "recovery-complete.json").exists()
    if failure.endswith("uncertain"):
        assert retained["nativeMayStillRun"] is True
        assert (item.args.operation_dir / "native-incomplete-evidence.tar").exists()


@pytest.mark.parametrize("failure", ["nonzero", "stale-rv", "timeout-after-write", "foreign-data", "metadata", "uid", "duplicate-json", "clock-expired"])
def test_one_patch_failure_stops_and_preserves_explicit_partial_state(recovery_flow, failure):
    item = recovery_flow
    activate(item)
    item.patch_failure, item.patch_failure_index = failure, 1
    with pytest.raises((bootstrap.BootstrapError, ValueError)):
        recovery.recover(item.args)
    assert len(item.patch_calls) == 2 and len(item.deletions) == 1
    assert item.stage_calls == item.qualification_calls == 1
    stopped = json.loads((item.args.operation_dir / "recovery-stopped.json").read_bytes())
    assert stopped["activationAttempted"] is True and stopped["activationComplete"] is False
    assert len(stopped["verifiedSecrets"]) == (2 if failure == "clock-expired" else 1)
    evidence = json.loads((item.args.operation_dir / "activation" / "response-01.json").read_bytes())
    assert "stdoutBase64" in evidence and "stderrBase64" in evidence
    if failure == "timeout-after-write":
        assert evidence["completed"] is False
        assert base64.b64decode(evidence["stdoutBase64"]) == b"PRIVATE_PARTIAL_REPLY"
    assert not (item.args.operation_dir / "activation" / "intent-02.json").exists()
    assert not (item.args.operation_dir / "recovery-complete.json").exists()


@pytest.mark.parametrize("tamper", [
    lambda plan: plan.update(binding={}),
    lambda plan: plan.update(credentialsQualified=1),
    lambda plan: plan.update(inspectionSha256="0" * 64),
    lambda plan: plan["nativePlan"].update(candidateInputs={}),
    lambda plan: plan["nativePlan"]["secrets"][0]["patch"][0].update(value="wrong-uid"),
    lambda plan: plan["nativePlan"]["secrets"][0]["patch"][3].update(op="add"),
    lambda plan: plan["nativePlan"]["secrets"][0]["patch"][3].update(path="/metadata/labels/injected"),
])
def test_private_plan_binding_or_scope_drift_is_refused_even_with_matching_export_hash(recovery_flow, tamper):
    item = recovery_flow
    activate(item)
    item.tamper_plan = tamper
    with pytest.raises(bootstrap.BootstrapError):
        recovery.recover(item.args)
    assert not item.patch_calls
    assert (item.args.operation_dir / "qualified-plan.json").exists()


@pytest.mark.parametrize("elapsed,wall_delta", [(301, 301), (301, 0), (1, -1)])
def test_export_delay_or_clock_change_cannot_extend_native_plan_lifetime(recovery_flow, elapsed, wall_delta):
    item = recovery_flow
    activate(item)
    def delay(item):
        item.clock.monotonic += elapsed
        item.clock.wall += wall_delta
    item.after_qualification = delay
    with pytest.raises(bootstrap.BootstrapError):
        recovery.recover(item.args)
    assert not item.patch_calls and (item.args.operation_dir / "native-qualified-evidence.tar").exists()


@pytest.mark.parametrize("name,mode", [("stage/candidate/openbao_service_token", 0o644), ("stage/response-000.json", 0o644)])
def test_candidate_or_evidence_mode_drift_retains_opaque_archive_and_refuses_use(recovery_flow, name, mode):
    item = recovery_flow
    item.tamper_stage = lambda remote: remote.update({name: (remote[name][0], mode)})
    with pytest.raises(bootstrap.BootstrapError):
        recovery.recover(item.args)
    assert (item.args.operation_dir / "native-stage-evidence.tar").exists()
    assert not item.patch_calls and not item.deletions


def test_missing_stage_response_cannot_be_qualified(recovery_flow):
    item = recovery_flow
    item.tamper_stage = lambda remote: remote.pop("stage/response-119.json")
    with pytest.raises(bootstrap.BootstrapError):
        recovery.recover(item.args)
    assert item.qualification_calls == 0 and not item.patch_calls
    assert (item.args.operation_dir / "native-stage-evidence.tar").exists()


@pytest.mark.parametrize("name", ["stage/request-000.json", "stage/response-001.json", "stage/response-119.json"])
def test_changed_non_token_journal_bytes_refuse_before_qualification(recovery_flow, name):
    item = recovery_flow
    item.tamper_stage = lambda remote: remote.update({name: (b'{"changed":true}\n', 0o600)})
    with pytest.raises(bootstrap.BootstrapError):
        recovery.recover(item.args)
    assert item.qualification_calls == 0 and not item.patch_calls
    assert (item.args.operation_dir / "native-stage-evidence.tar").exists()


@pytest.mark.parametrize("name", ["qualification/request-000.json", "qualification/response-000.json",
                                  "qualification/response-050.json"])
def test_changed_qualification_journal_refuses_before_any_secret_patch(recovery_flow, name):
    item = recovery_flow
    activate(item)
    item.after_qualification = lambda current: current.remote.update({name: (b'{"changed":true}\n', 0o600)})
    with pytest.raises(bootstrap.BootstrapError, match="native qualified plan binding differs"):
        recovery.recover(item.args)
    assert item.stage_calls == item.qualification_calls == 1 and not item.patch_calls
    assert (item.args.operation_dir / "native-qualified-evidence.tar").exists()
    assert (item.args.operation_dir / "qualified-plan.json").exists()
    assert not (item.args.operation_dir / "recovery-complete.json").exists()


def test_retained_state_drift_before_stage_refuses_issuance(recovery_flow):
    item = recovery_flow
    item.drift = "retained-current"
    with pytest.raises(bootstrap.BootstrapError):
        recovery.recover(item.args)
    assert item.stage_calls == item.qualification_calls == 0 and not item.patch_calls


def test_operation_is_fresh_and_cannot_be_replayed(recovery_flow):
    item = recovery_flow
    recovery.recover(item.args)
    with pytest.raises(bootstrap.BootstrapError, match="already exists"):
        recovery.recover(item.args)
    assert item.stage_calls == item.qualification_calls == 1


def test_explicit_mode_is_required_and_mutually_exclusive(recovery_flow):
    item = recovery_flow
    for first, second in ((False, False), (True, True), (1, False)):
        item.args.stage_only, item.args.activate_existing_secrets = first, second
        with pytest.raises(bootstrap.BootstrapError, match="explicit recovery mode"):
            recovery.recover(item.args)
    assert not item.creates and not item.args.operation_dir.exists()


def test_archive_rejects_symlink_and_unknown_private_file(recovery_flow):
    item = recovery_flow
    with pytest.raises(bootstrap.BootstrapError):
        recovery.evidence_members(archive({"root-token": (ROOT_TOKEN, 0o600)}), item.snapshot)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as output:
        entry = tarfile.TarInfo("stage/inputs/openbao_service_token")
        entry.type, entry.linkname, entry.mode = tarfile.SYMTYPE, inspection.REMOTE_ROOT, 0o600
        output.addfile(entry)
    with pytest.raises(bootstrap.BootstrapError):
        recovery.evidence_members(stream.getvalue(), item.snapshot)
