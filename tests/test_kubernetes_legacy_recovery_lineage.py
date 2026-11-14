"""Private predecessor transport and authenticated historical source custody.

Real native chain/preimage rejection lives in the Rust planner tests. These
tests exercise the adapter around that boundary, including no-write refusal.
"""
from __future__ import annotations

from copy import copy, deepcopy
import io
import json
from pathlib import Path
import sys
import tarfile
from types import SimpleNamespace
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from test_recover_kubernetes_legacy_credentials import recovery_flow, activate, state_snapshot
from test_inspect_kubernetes_legacy_credentials import flow
import bootstrap_kubernetes_openbao as bootstrap
import inspect_kubernetes_legacy_credentials as inspection
import kubernetes_legacy_recovery_lineage as lineage
import recover_kubernetes_legacy_credentials as recovery


def bundle(assets: Path, *, malicious: bool = False) -> tuple[dict, dict]:
    assets.mkdir(mode=0o700)
    names = ("scripts/recover_kubernetes_legacy_credentials.py", "scripts/inspect_kubernetes_legacy_credentials.py",
             "scripts/kubernetes_legacy_recovery_sources.py")
    source = ("SOURCE_FILES = " + repr(names) + "\n").encode()
    if malicious:
        source = b"SOURCE_FILES = __import__('os').system('false')\n"
    contents = {names[0]: b"# authenticated historical adapter\n", names[1]: b"# authenticated historical inspector\n",
                names[2]: source}
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, raw in contents.items():
            archive.writestr("selfhost-prepared/" + name, raw)
    raw = output.getvalue()
    (assets / "prepared-selfhost-bundle.zip").write_bytes(raw)
    inventory = bootstrap.encoded({"artifacts": [{"name": "prepared-selfhost-bundle.zip", "sha256": recovery.sha256(raw)}]})
    (assets / "installer-inventory.json").write_bytes(inventory)
    return {"inventorySha256": recovery.sha256(inventory)}, {name: recovery.sha256(raw) for name, raw in contents.items()}


@pytest.fixture
def completed(recovery_flow, monkeypatch):
    item = recovery_flow
    identity, sources = bundle(item.args.recovery_assets)
    item.recovery["release"].update(identity)
    monkeypatch.setattr(inspection.sources, "authenticate", lambda assets, identity: sources.copy())
    monkeypatch.setattr(inspection.sources, "recheck", lambda expected: inspection.same(expected, sources, "source drift"))
    activate(item)
    recovery.recover(item.args)
    item.prior = item.args.operation_dir
    item.before = state_snapshot(item)
    item.next = copy(item.args)
    item.next.operation_dir = item.prior.with_name("successor")
    item.next.previous_recovery_dir = [item.prior]
    item.next.previous_recovery_assets = [item.args.recovery_assets]
    return item


def selected(item):
    bootstrap.private_directory(item.next.operation_dir)
    return lineage.selected(item.next, item.original, item.snapshot, item.bound)


def test_completed_predecessor_reauthenticates_its_signed_release_and_retains_original(completed):
    item = completed
    reads, writes = item.auth_calls, len(item.patch_calls)
    predecessor = selected(item)
    assert item.auth_calls == reads + 1
    assert predecessor.snapshot == item.candidate
    assert predecessor.snapshot != item.snapshot
    assert len(item.patch_calls) == writes
    assert state_snapshot(item) == item.before
    predecessor.check()
    assert (predecessor.root / "original" / "openbao_bootstrap_token").read_bytes() == item.snapshot["openbao_bootstrap_token"][0]
    assert not (item.args.state_dir / "renewal-adoption.json").exists()


@pytest.mark.parametrize("tamper", ["candidate", "plan", "export", "operator", "source-map", "incomplete", "missing-response"])
def test_changed_or_incomplete_predecessor_is_refused_before_any_cluster_write(completed, tamper):
    item = completed
    if tamper == "candidate":
        path = item.prior / "candidate/auth_tls_kms_token"
        path.write_bytes(b"private changed candidate")
    elif tamper == "plan":
        (item.prior / "qualified-plan.json").write_bytes(b"{}")
    elif tamper == "export":
        (item.prior / "native-qualified-evidence.tar").write_bytes(b"invalid archive")
    elif tamper == "operator":
        (item.prior / "marty-deploy").write_bytes(b"different operator")
    elif tamper == "source-map":
        path = item.prior / "source-authenticated.json"
        value = json.loads(path.read_bytes())
        value["files"].pop(next(iter(value["files"])))
        path.write_bytes(bootstrap.encoded(value))
    elif tamper == "incomplete":
        bootstrap.write_new(item.prior / "recovery-stopped.json", b"{}")
    else:
        (item.prior / "activation/response-17.json").unlink()
    writes, pods = len(item.patch_calls), len(item.creates)
    with pytest.raises((bootstrap.BootstrapError, ValueError, OSError, KeyError, tarfile.TarError)):
        selected(item)
    assert (len(item.patch_calls), len(item.creates)) == (writes, pods)


def test_predecessor_artifact_authentication_failure_precedes_live_secret_observation(completed, monkeypatch):
    item = completed
    prepare = bootstrap.prepare
    def rejected(**kwargs):
        if kwargs["output"].name.startswith("predecessor-"):
            raise bootstrap.BootstrapError("synthetic signed predecessor refusal")
        return prepare(**kwargs)
    monkeypatch.setattr(bootstrap, "prepare", rejected)
    observations = item.events.count("legacy Secret observation")
    pods = len(item.creates)
    with pytest.raises(bootstrap.BootstrapError, match="signed predecessor"):
        selected(item)
    assert item.events.count("legacy Secret observation") == observations
    assert len(item.creates) == pods


def test_native_predecessor_admission_is_bounded_and_its_refusal_cannot_create_a_producer(completed, monkeypatch):
    item = completed
    predecessor = selected(item)
    calls = []
    def refused(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"private native refusal")
    monkeypatch.setattr(lineage.subprocess, "run", refused)
    observed = {"apiVersion": "v1", "kind": "SecretList", "items": [item.secrets[name] for name in item.names]}
    pods = len(item.creates)
    with pytest.raises(bootstrap.BootstrapError, match="native owner refused"):
        predecessor.admit(item.next.operation_dir / "marty-deploy", {"rootTokenFile": "unread"}, observed, bootstrap.encoded(observed))
    assert calls[0][0][-2:] == ["operator", "kubernetes-legacy-recovery-predecessors"]
    request = json.loads(calls[0][1]["input"])
    assert request["current"] == str(predecessor.current)
    assert request["predecessors"] == str(predecessor.root)
    assert calls[0][1]["timeout"] == 120
    assert len(item.creates) == pods


def test_live_preimage_recheck_preserves_metadata_only_changes_but_refuses_any_data_or_uid_change(completed):
    item = completed
    predecessor = selected(item)
    observed = {"items": [deepcopy(item.secrets[name]) for name in item.names]}
    predecessor.observed = deepcopy(observed)
    observed["items"][0]["metadata"]["resourceVersion"] = "new-metadata-version"
    predecessor.same_publication(observed)
    observed["items"][0]["data"]["foreign.empty"] = "Y2hhbmdlZA=="
    with pytest.raises(bootstrap.BootstrapError, match="live predecessor publication changed"):
        predecessor.same_publication(observed)


@pytest.mark.parametrize("path", ["activation/response-12.json", "candidate/auth_tls_kms_token", "source-authenticated.json"])
def test_predecessor_inputs_remain_bound_after_admission(completed, path):
    item = completed
    predecessor = selected(item)
    target = item.prior / path
    target.write_bytes(target.read_bytes() + b"\nchanged")
    with pytest.raises(bootstrap.BootstrapError):
        predecessor.check()


def test_historical_source_declaration_is_data_never_executed(tmp_path, monkeypatch):
    identity, _ = bundle(tmp_path / "malicious", malicious=True)
    called = []
    monkeypatch.setattr(lineage.ast, "literal_eval", lambda value: called.append(value) or (_ for _ in ()).throw(ValueError("not literal")))
    with pytest.raises(ValueError, match="not literal"):
        lineage.historical_sources(tmp_path / "malicious", identity, b"{}")
    assert len(called) == 1


@pytest.mark.parametrize("marker", ["renewal-adoption.json", "renewal-adoption-pending.json"])
def test_ordinary_renewal_or_pending_adoption_is_not_replaced_by_root_recovery(recovery_flow, marker):
    item = recovery_flow
    bootstrap.write_new(item.args.state_dir / marker, b"{}")
    with pytest.raises(bootstrap.BootstrapError, match="ordinary renewal or reconciliation"):
        recovery.recover(item.args)
    assert item.auth_calls == 0 and not item.creates and item.stage_calls == 0


def test_ordered_predecessor_arguments_must_pair_and_cannot_repeat(tmp_path):
    for directories, assets in [([tmp_path], []), ([tmp_path, tmp_path], [tmp_path, tmp_path]),
                                 ([tmp_path / str(index) for index in range(9)], [tmp_path] * 9)]:
        args = SimpleNamespace(previous_recovery_dir=directories, previous_recovery_assets=assets)
        with pytest.raises(bootstrap.BootstrapError, match="one authenticated assets directory"):
            lineage.selected(args, {}, {}, {})


@pytest.mark.parametrize("late_drift", [False, True])
def test_successor_orchestration_uses_completed_inputs_and_rechecks_before_issuance(completed, monkeypatch, late_drift):
    item = completed
    original_snapshot = deepcopy(item.snapshot)
    prior_candidate = deepcopy(item.candidate)
    item.args = item.next
    item.snapshot = prior_candidate
    item.expected_auth_calls = 3
    item.replacement_prefix = b"PRIVATE_SECOND_REPLACEMENT_"
    item.patch_version_base = 4000
    item.auth_calls = item.stage_calls = item.qualification_calls = item.target_calls = item.native_calls = 0
    item.events, item.creates, item.uploads, item.requests, item.deletions = [], [], [], [], []
    item.patch_calls, item.patch_timeouts, item.remote, item.imports, item.export_calls = [], [], {}, {}, []
    base_process = recovery.subprocess.run

    def process(command, **kwargs):
        if command[-2:] != ["operator", "kubernetes-legacy-recovery-predecessors"]:
            return base_process(command, **kwargs)
        request = json.loads(kwargs["input"])
        assert Path(request["current"]).is_relative_to(item.args.operation_dir / "predecessors")
        assert recovery.private.current_snapshot(Path(request["current"])) == prior_candidate
        assert recovery.private.current_snapshot(Path(request["predecessors"]) / "original") == original_snapshot
        manifest = json.loads((Path(request["predecessors"]) / "manifest.json").read_bytes())
        item.lineage_summary = {"schema": lineage.SCHEMA, "binding": item.bound,
            "originalInputBindings": recovery.input_bindings(original_snapshot),
            "steps": [{**manifest["steps"][0], "privatePlanSha256": json.loads(
                (item.prior / "recovery-complete.json").read_bytes())["privatePlanSha256"],
                "candidateInputs": recovery.input_bindings(prior_candidate)}]}
        return SimpleNamespace(returncode=0, stdout=bootstrap.encoded(item.lineage_summary), stderr=b"")

    base_transport = bootstrap.Transport
    class Transport(base_transport):
        def execute(self, pod, command, *, data=None, **kwargs):
            result = super().execute(pod, command, data=data, **kwargs)
            if command[:3] == [inspection.REMOTE_OPERATOR, "operator", "kubernetes-legacy-recovery-inspect"]:
                assert json.loads(data)["predecessors"] == lineage.REMOTE
                item.report["predecessorChain"] = item.lineage_summary
                item.remote["inspection.json"] = bootstrap.encoded(item.report), 0o600
                if late_drift:
                    item.secrets[item.names[0]]["data"]["foreign.empty"] = "Y2hhbmdlZA=="
            return result

    monkeypatch.setattr(recovery.subprocess, "run", process)
    monkeypatch.setattr(bootstrap, "Transport", Transport)
    if late_drift:
        with pytest.raises(bootstrap.BootstrapError, match="live predecessor publication changed"):
            recovery.recover(item.args)
        assert item.stage_calls == 0 and not item.patch_calls
        assert not (item.args.operation_dir / "recovery-complete.json").exists()
    else:
        recovery.recover(item.args)
        result = json.loads((item.args.operation_dir / "recovery-complete.json").read_bytes())
        assert result["predecessorChain"] == item.lineage_summary
        assert result["verifiedSecretCount"] == len(item.patch_calls) == 34
        assert item.events.count("legacy Secret observation") == 102
        assert item.events[:item.events.index("legacy producer creation")].count("legacy Secret observation") == 34
        assert item.imports[inspection.REMOTE_CURRENT] == prior_candidate
        assert lineage.REMOTE in item.imports
    assert state_snapshot(item) == item.before
