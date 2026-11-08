"""Exercise local selection durability and interrupted-activation admission.

These are real private filesystem operations; cluster/credential proof belongs
to the activation adapter and native verifier rather than this metadata owner.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import bootstrap_kubernetes_openbao as bootstrap
import kubernetes_application_state as selection


pytestmark = pytest.mark.skipif(os.name != "posix", reason="private POSIX selection contract")


def write(path, value):
    raw = value if isinstance(value, bytes) else bootstrap.encoded(value)
    path.write_bytes(raw)
    path.chmod(0o600)


def private_directory(path):
    path.mkdir(mode=0o700)
    return path


@pytest.fixture
def state(tmp_path):
    root = private_directory(tmp_path / "bootstrap")
    current = private_directory(root / "credentials")
    operation = private_directory(tmp_path / "activation")
    candidate = private_directory(operation / "candidate")
    write(current / "retained", b"PRIVATE_PREVIOUS_GENERATION_CANARY")
    write(candidate / "retained", b"PRIVATE_NEXT_GENERATION_CANARY")
    binding = {"namespace": "marty-test", "namespaceUid": "c647e5d2-85d7-409b-8729-94b8f8cf29ab",
        "openbaoClusterId": "9347f7a0-aae1-4ecf-9e77-165626c051c2",
        "workloadProject": "marty-selfhost-disposable-k8s-0123456789ab"}
    runtime = {"runtimeSourceSha": "1" * 40, "chartSourceSha": "2" * 40,
        "tag": "v1.2.3-nightly.20261108.123", "buildRunId": 123, "buildRunAttempt": 1,
        "inventorySha256": "3" * 64, "imageLockSha256": "4" * 64, "operatorSha256": "5" * 64}
    write(root / "marty-images.json", {"release": runtime})
    return SimpleNamespace(root=root, current=current, operation=operation, candidate=candidate,
                           binding=binding, runtime=runtime, activation_id="a" * 32)


def proof(state, current):
    return {"schema": selection.VERIFIED_SCHEMA, "binding": state.binding,
        "activationId": state.activation_id, "operationDirectory": str(state.operation),
        "candidateDirectory": str(state.candidate), "previousDirectory": str(current),
        "runtime": state.runtime, "secret": {"name": "marty-secrets", "uid": "secret-uid", "resourceVersion": "201"},
        "deployments": [{"name": name, "uid": name + "-uid", "generation": 3, "revision": 2,
                         "podUids": [name + "-pod-uid"]}
                        for name in ["flow", "gateway", "issuance-native", "notification", "signing-keys"]],
        "status": "secret-and-rollouts-verified", "credentialDeliveryVerified": True,
        "credentialConsumptionVerified": False}


def begin(state, held):
    previous = held.current(state.binding)
    held.begin(state.binding, state.operation, state.candidate, state.activation_id, expected=previous)
    return previous


def publish(state, held):
    previous = begin(state, held)
    write(state.operation / selection.VERIFIED, proof(state, previous.directory))
    held.publish(state.binding, state.operation, expected=previous)
    return previous


def activate(state):
    with selection.locked(state.root) as held:
        previous = publish(state, held)
        held.complete(state.binding, state.operation)
        held.finish(state.binding, state.operation)
        return previous, held.current(state.binding)


def test_bootstrap_fallback_is_private_readonly_and_requires_an_active_lock(state):
    names = set(state.root.iterdir())
    with selection.locked(state.root) as held:
        selected = held.current(state.binding)
        assert selected.directory == state.current and selected.activation_id is None
        assert selected.selector is selected.identity is None
        assert held.pending(state.binding) is None
        held.require_current(state.binding, expected=selected)
    assert set(state.root.iterdir()) == names
    with pytest.raises(bootstrap.BootstrapError):
        held.current(state.binding)


def test_directory_lock_refuses_another_local_operation_and_releases_on_error(state):
    with pytest.raises(RuntimeError, match="fixture failure"):
        with selection.locked(state.root):
            with pytest.raises(bootstrap.BootstrapError, match="another Kubernetes application operation"):
                with selection.locked(state.root):
                    pytest.fail("second writer acquired the lock")
            raise RuntimeError("fixture failure")
    with selection.locked(state.root) as held:
        assert held.current(state.binding).directory == state.current


def test_pending_intent_survives_process_boundary_and_admits_only_same_attempt(state):
    with selection.locked(state.root) as held:
        original = begin(state, held)
        first = (state.root / selection.PENDING).read_bytes()
        with pytest.raises(bootstrap.BootstrapError, match="activation is pending"):
            held.current(state.binding)
    with selection.locked(state.root) as held:
        assert held.current(state.binding, pending_operation=state.operation) == original
        held.begin(state.binding, state.operation, state.candidate, state.activation_id, expected=original)
        assert (state.root / selection.PENDING).read_bytes() == first
        with pytest.raises(bootstrap.BootstrapError, match="activation is pending"):
            held.current(state.binding, pending_operation=state.operation.parent / "other")
        with pytest.raises(bootstrap.BootstrapError, match="activation is pending"):
            held.begin(state.binding, state.operation, state.candidate, "b" * 32, expected=original)
    assert not (state.root / selection.SELECTOR).exists()
    assert (state.current / "retained").read_bytes() == b"PRIVATE_PREVIOUS_GENERATION_CANARY"


def test_selector_requires_verified_evidence_and_pending_stays_until_completion(state):
    with selection.locked(state.root) as held:
        previous = begin(state, held)
        with pytest.raises(bootstrap.BootstrapError):
            held.publish(state.binding, state.operation, expected=previous)
        assert not (state.root / selection.SELECTOR).exists()
        write(state.operation / selection.VERIFIED, proof(state, previous.directory))
        held.publish(state.binding, state.operation, expected=previous)
        with pytest.raises(bootstrap.BootstrapError, match="activation is pending"):
            held.current(state.binding)
        with pytest.raises(bootstrap.BootstrapError):
            held.finish(state.binding, state.operation)
        assert (state.root / selection.PENDING).exists()
        held.complete(state.binding, state.operation)
        held.finish(state.binding, state.operation)
        current = held.current(state.binding)
        assert current.directory == state.candidate and current.activation_id == state.activation_id
    assert not (state.root / selection.PENDING).exists()
    assert (state.current / "retained").read_bytes() == b"PRIVATE_PREVIOUS_GENERATION_CANARY"
    for path in [state.root / selection.SELECTOR, state.operation / selection.VERIFIED,
                 state.operation / selection.COMPLETE]:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert b"PRIVATE_" not in path.read_bytes()


def test_resume_after_selection_is_idempotent_and_remembers_original_generation(state):
    with selection.locked(state.root) as held:
        original = publish(state, held)
    published_inode = (state.root / selection.SELECTOR).stat().st_ino
    with selection.locked(state.root) as held:
        recovered = held.current(state.binding, pending_operation=state.operation)
        assert recovered == original and recovered.directory != state.candidate
        held.publish(state.binding, state.operation, expected=recovered)
        assert (state.root / selection.SELECTOR).stat().st_ino == published_inode
        held.complete(state.binding, state.operation)
        completion_inode = (state.operation / selection.COMPLETE).stat().st_ino
        held.complete(state.binding, state.operation)
        assert (state.operation / selection.COMPLETE).stat().st_ino == completion_inode
        held.finish(state.binding, state.operation)


def test_later_activation_advances_existing_selector_and_preserves_both_prior_generations(state):
    _, first = activate(state)
    operation = private_directory(state.operation.parent / "second-activation")
    candidate = private_directory(operation / "candidate")
    write(candidate / "retained", b"PRIVATE_THIRD_GENERATION_CANARY")
    successor = SimpleNamespace(**{**vars(state), "operation": operation, "candidate": candidate,
                                   "activation_id": "b" * 32})
    previous, current = activate(successor)
    assert previous == first
    assert current.directory == candidate and current.activation_id == "b" * 32
    assert (state.current / "retained").read_bytes() == b"PRIVATE_PREVIOUS_GENERATION_CANARY"
    assert (state.candidate / "retained").read_bytes() == b"PRIVATE_NEXT_GENERATION_CANARY"


def test_pending_cleanup_failure_can_finish_same_already_completed_selection(state, monkeypatch):
    with selection.locked(state.root) as held:
        original = publish(state, held)
        held.complete(state.binding, state.operation)
        original_unlink = selection.os.unlink
        with monkeypatch.context() as patch:
            def fail_cleanup(path, *args, **kwargs):
                if path == selection.PENDING:
                    raise OSError("PRIVATE_CLEANUP_FAILURE_CANARY")
                return original_unlink(path, *args, **kwargs)
            patch.setattr(selection.os, "unlink", fail_cleanup)
            with pytest.raises(bootstrap.BootstrapError):
                held.finish(state.binding, state.operation)
        assert (state.root / selection.PENDING).exists()
    with selection.locked(state.root) as held:
        assert held.current(state.binding, pending_operation=state.operation) == original
        held.publish(state.binding, state.operation, expected=original)
        held.complete(state.binding, state.operation)
        held.finish(state.binding, state.operation)
        assert held.current(state.binding).directory == state.candidate


@pytest.mark.parametrize("prefix_length", [0, 1, 127, -1])
def test_completion_recovers_only_exact_prefix_and_retains_private_interrupted_bytes(state, prefix_length):
    with selection.locked(state.root) as held:
        previous = publish(state, held)
        expected = {**proof(state, previous.directory), "schema": selection.COMPLETE_SCHEMA,
                    "status": "application-generation-selected"}
        raw = bootstrap.encoded(expected)
        prefix = raw[:prefix_length]
        write(state.operation / selection.COMPLETE, prefix)
        assert held.complete(state.binding, state.operation) == expected
        retained = list(state.operation.glob("application-activation-complete-interrupted-*.partial"))
        assert len(retained) == 1 and retained[0].read_bytes() == prefix
        assert stat.S_IMODE(retained[0].stat().st_mode) == 0o600
        assert (state.operation / selection.COMPLETE).read_bytes() == raw
        held.finish(state.binding, state.operation)


@pytest.mark.parametrize("invalid", [b"not a receipt", b'{"PRIVATE_FOREIGN_CANARY":true}', b"{}\n"])
def test_foreign_completion_is_preserved_and_never_repaired(state, invalid):
    with selection.locked(state.root) as held:
        publish(state, held)
        write(state.operation / selection.COMPLETE, invalid)
        with pytest.raises(bootstrap.BootstrapError) as error:
            held.complete(state.binding, state.operation)
        assert "PRIVATE_" not in str(error.value)
        assert (state.operation / selection.COMPLETE).read_bytes() == invalid
        assert (state.root / selection.PENDING).exists()
        assert not list(state.operation.glob("application-activation-complete-interrupted-*.partial"))


@pytest.mark.parametrize("failure", ["before-rename", "after-rename-fsync"])
def test_failed_selector_publication_retains_pending_and_same_attempt_can_reconcile(state, monkeypatch, failure):
    with selection.locked(state.root) as held:
        previous = begin(state, held)
        write(state.operation / selection.VERIFIED, proof(state, previous.directory))
        with monkeypatch.context() as patch:
            if failure == "before-rename":
                def fail_replace(*args, **kwargs):
                    raise OSError("PRIVATE_FILESYSTEM_FAILURE_CANARY")
                patch.setattr(selection.os, "replace", fail_replace)
            else:
                original_fsync = selection.os.fsync
                def fail_fsync(descriptor):
                    if descriptor == held.descriptor and (state.root / selection.SELECTOR).exists():
                        raise OSError("PRIVATE_FILESYSTEM_FAILURE_CANARY")
                    return original_fsync(descriptor)
                patch.setattr(selection.os, "fsync", fail_fsync)
            with pytest.raises(bootstrap.BootstrapError) as error:
                held.publish(state.binding, state.operation, expected=previous)
            assert "PRIVATE_" not in str(error.value)
        assert (state.root / selection.PENDING).exists()
        with pytest.raises(bootstrap.BootstrapError, match="activation is pending"):
            held.current(state.binding)
    with selection.locked(state.root) as held:
        recovered = held.current(state.binding, pending_operation=state.operation)
        assert recovered == previous
        held.publish(state.binding, state.operation, expected=recovered)
        held.complete(state.binding, state.operation)
        held.finish(state.binding, state.operation)
        assert held.current(state.binding).directory == state.candidate


def test_intent_durability_error_leaves_a_bound_resumable_attempt(state, monkeypatch):
    with selection.locked(state.root) as held:
        previous = held.current(state.binding)
        original_fsync = selection.os.fsync
        with monkeypatch.context() as patch:
            def fail_directory_sync(descriptor):
                if descriptor == held.descriptor:
                    raise OSError("PRIVATE_INTENT_SYNC_CANARY")
                return original_fsync(descriptor)
            patch.setattr(selection.os, "fsync", fail_directory_sync)
            with pytest.raises(bootstrap.BootstrapError):
                held.begin(state.binding, state.operation, state.candidate, state.activation_id, expected=previous)
    with selection.locked(state.root) as held:
        assert held.current(state.binding, pending_operation=state.operation) == previous
        held.begin(state.binding, state.operation, state.candidate, state.activation_id, expected=previous)
        assert not (state.root / selection.SELECTOR).exists()


@pytest.mark.parametrize("tamper", ["secret", "binding", "runtime", "candidate", "previous", "nonce",
                                  "empty-pods", "duplicate-pods", "generation-bool", "zero-revision",
                                  "duplicate-deployment", "missing-delivery", "claimed-consumption", "extra"])
def test_unbound_or_incomplete_verification_never_selects_a_generation(state, tamper):
    with selection.locked(state.root) as held:
        previous = begin(state, held)
        value = proof(state, previous.directory)
        if tamper == "secret":
            value["secret"]["name"] = "other-secret"
        elif tamper == "binding":
            value["binding"] = {**state.binding, "namespace": "other-namespace"}
        elif tamper == "runtime":
            value["runtime"] = {**state.runtime, "runtimeSourceSha": "9" * 40}
        elif tamper == "candidate":
            value["candidateDirectory"] = str(state.current)
        elif tamper == "previous":
            value["previousDirectory"] = str(state.candidate)
        elif tamper == "nonce":
            value["activationId"] = "b" * 32
        elif tamper == "empty-pods":
            value["deployments"][0]["podUids"] = []
        elif tamper == "duplicate-pods":
            value["deployments"][0]["podUids"] *= 2
        elif tamper == "generation-bool":
            value["deployments"][0]["generation"] = True
        elif tamper == "zero-revision":
            value["deployments"][0]["revision"] = 0
        elif tamper == "duplicate-deployment":
            value["deployments"].append(value["deployments"][0])
        elif tamper == "claimed-consumption":
            value["credentialConsumptionVerified"] = True
        elif tamper == "missing-delivery":
            value["credentialDeliveryVerified"] = False
        else:
            value["PRIVATE_UNEXPECTED_CANARY"] = True
        write(state.operation / selection.VERIFIED, value)
        with pytest.raises(bootstrap.BootstrapError) as error:
            held.publish(state.binding, state.operation, expected=previous)
        assert "PRIVATE_" not in str(error.value)
        assert not (state.root / selection.SELECTOR).exists()
        assert (state.root / selection.PENDING).exists()


@pytest.mark.parametrize("target", ["selector", "proof", "completion"])
@pytest.mark.parametrize("tamper", ["symlink", "hardlink", "mode", "duplicate-json", "unknown-schema"])
def test_selected_state_refuses_unsafe_or_corrupt_metadata_without_bootstrap_fallback(state, target, tamper):
    activate(state)
    path = {"selector": state.root / selection.SELECTOR, "proof": state.operation / selection.VERIFIED,
            "completion": state.operation / selection.COMPLETE}[target]
    original = path.read_bytes()
    if tamper in {"symlink", "hardlink"}:
        retained = path.with_suffix(".retained")
        path.rename(retained)
        if tamper == "symlink":
            path.symlink_to(retained)
        else:
            os.link(retained, path)
    elif tamper == "mode":
        path.chmod(0o644)
    elif tamper == "duplicate-json":
        write(path, b'{"schema":"one","schema":"two"}')
    else:
        value = json.loads(original)
        value["schema"] = "unknown/v1"
        write(path, value)
    with selection.locked(state.root) as held:
        with pytest.raises(bootstrap.BootstrapError):
            held.current(state.binding)
    assert (state.current / "retained").read_bytes() == b"PRIVATE_PREVIOUS_GENERATION_CANARY"


@pytest.mark.parametrize("raw", [b"", b"{}", b'{"binding":{},"binding":{}}', b"x" * (selection.MAX_RECORD + 1)])
def test_invalid_pending_state_blocks_new_operations(state, raw):
    write(state.root / selection.PENDING, raw)
    with selection.locked(state.root) as held:
        with pytest.raises(bootstrap.BootstrapError):
            held.current(state.binding)
        with pytest.raises(bootstrap.BootstrapError):
            held.pending(state.binding, state.operation)


def test_replaced_generation_directory_or_retained_root_is_not_accepted(state):
    activate(state)
    state.candidate.rename(state.operation / "retained-candidate")
    private_directory(state.candidate)
    with selection.locked(state.root) as held:
        with pytest.raises(bootstrap.BootstrapError):
            held.current(state.binding)
        state.root.rename(state.root.with_name("displaced-bootstrap"))
        private_directory(state.root)
        private_directory(state.root / "credentials")
        with pytest.raises(bootstrap.BootstrapError):
            held.current(state.binding)


def test_existing_selector_inode_replacement_refuses_same_bytes_on_later_activation(state):
    activate(state)
    successor = private_directory(state.operation.parent / "successor")
    successor_candidate = private_directory(successor / "candidate")
    with selection.locked(state.root) as held:
        previous = held.current(state.binding)
        held.begin(state.binding, successor, successor_candidate, "b" * 32, expected=previous)
        intent = held.pending(state.binding, successor)
        replacement = state.root / "replacement-selector.json"
        write(replacement, (state.root / selection.SELECTOR).read_bytes())
        os.replace(replacement, state.root / selection.SELECTOR)
        with pytest.raises(bootstrap.BootstrapError):
            held.current(state.binding, pending_operation=successor)
        assert held.pending(state.binding, successor) == intent
        assert (state.root / selection.SELECTOR).read_bytes() == previous.selector


@pytest.mark.parametrize("mode", [0o755, 0o770, 0o777])
def test_nonprivate_root_refuses_before_state_access(state, mode):
    state.root.chmod(mode)
    with pytest.raises(bootstrap.BootstrapError):
        with selection.locked(state.root):
            pytest.fail("nonprivate state was admitted")


def test_operation_cannot_replace_or_nest_in_selected_private_inputs(state):
    with selection.locked(state.root) as held:
        previous = held.current(state.binding)
        for operation in [state.root, state.current, state.current / "nested"]:
            with pytest.raises(bootstrap.BootstrapError):
                held.begin(state.binding, operation, operation / "candidate", state.activation_id, expected=previous)
        assert not (state.root / selection.PENDING).exists()


def test_private_record_refuses_a_different_effective_owner(state, monkeypatch):
    parent = selection.directory_fd(state.root)
    try:
        effective = os.geteuid()
        monkeypatch.setattr(selection.os, "geteuid", lambda: effective + 1)
        with pytest.raises(bootstrap.BootstrapError):
            selection.read_file_at(parent, "marty-images.json")
    finally:
        os.close(parent)
