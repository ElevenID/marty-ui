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


@pytest.mark.parametrize("boundary", ["begin", "proof", "pending"])
def test_selection_rejects_operations_inside_enrolled_renewal_identity(state, boundary):
    identity = private_directory(state.root / "renewal-identity")
    for name in ("renewal-role-id", "renewal-secret-id", "renewal-leaf-policies.json"):
        write(identity / name, b"PRIVATE_RETAINED_RENEWAL_CANARY")
    unsafe = identity / "unsafe-operation"
    with selection.locked(state.root) as held:
        selected = held.current(state.binding)
        if boundary == "begin":
            with pytest.raises(bootstrap.BootstrapError):
                held.begin(state.binding, unsafe, unsafe / "candidate", state.activation_id,
                           expected=selected)
            assert not unsafe.exists() and not (state.root / selection.PENDING).exists()
        else:
            if boundary == "pending":
                begin(state, held)
                pending = json.loads((state.root / selection.PENDING).read_bytes())
            state.operation.rename(unsafe)
            state.operation, state.candidate = unsafe, unsafe / "candidate"
            if boundary == "proof":
                write(unsafe / selection.VERIFIED, proof(state, state.current))
                with pytest.raises(bootstrap.BootstrapError):
                    held.proof(unsafe, state.binding)
            else:
                pending["operationDirectory"] = str(unsafe)
                pending["candidateDirectory"] = str(state.candidate)
                write(state.root / selection.PENDING, pending)
                with pytest.raises(bootstrap.BootstrapError):
                    held.pending(state.binding)
        assert not (state.root / selection.SELECTOR).exists()
        for path in identity.iterdir():
            if path.is_file():
                assert path.read_bytes() == b"PRIVATE_RETAINED_RENEWAL_CANARY"


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


@pytest.fixture
def renewal_state(state):
    catalog = json.loads((bootstrap.ROOT / "deploy-config/catalog/kubernetes-secrets.json").read_bytes())
    write(state.root / "bootstrap-complete.json", {"credentialPublication": {
        "schema": bootstrap.PUBLICATION_SCHEMA, "catalog": catalog}})
    inputs = {name.upper() for name in set(bootstrap.SELFHOST_TLS_FILES) | bootstrap.KEYCLOAK_FILES
              if name != "workload_identity_ca_cert"}
    state.renewal_names = sorted(entry["name"] for entry in catalog["secrets"]
        if any(field.get("env") in inputs for field in entry["fields"].values()))
    assert len(state.renewal_names) == 33
    return state


def renewal_proof(state, current):
    value = proof(state, current)
    value.pop("secret")
    return {**value, "schema": selection.RENEWAL_VERIFIED_SCHEMA,
            "status": "secrets-and-rollouts-verified",
            "secrets": [{"name": name, "uid": name + "-uid", "resourceVersion": str(201 + index)}
                        for index, name in enumerate(state.renewal_names)]}


def successor(state, name, marker):
    operation = private_directory(state.operation.parent / name)
    candidate = private_directory(operation / "candidate")
    write(candidate / "retained", b"PRIVATE_SUCCESSOR_GENERATION_CANARY")
    return SimpleNamespace(**{**vars(state), "operation": operation, "candidate": candidate,
                              "activation_id": marker * 32})


def publish_renewal(state, held):
    previous = held.current(state.binding)
    held.begin(state.binding, state.operation, state.candidate, state.activation_id,
               expected=previous, domain="renewal")
    write(state.operation / selection.RENEWAL_VERIFIED, renewal_proof(state, previous.directory))
    held.publish(state.binding, state.operation, expected=previous, domain="renewal")
    return previous


def activate_renewal(state):
    with selection.locked(state.root) as held:
        previous = publish_renewal(state, held)
        completion = held.complete(state.binding, state.operation, domain="renewal")
        assert completion["status"] == "renewal-generation-selected"
        held.finish(state.binding, state.operation, domain="renewal")
        return previous, held.current(state.binding)


def test_renewal_selects_the_shared_generation_without_inventing_an_ordinary_marker(renewal_state):
    state = renewal_state
    previous, current = activate_renewal(state)
    assert previous.activation_id is previous.renewal_activation_id is None
    assert current.activation_id is None
    assert current.renewal_activation_id == current.generation_activation_id == state.activation_id
    assert current.directory == state.candidate
    assert (state.current / "retained").read_bytes() == b"PRIVATE_PREVIOUS_GENERATION_CANARY"
    with selection.locked(state.root) as held:
        assert held.current(state.binding, domain="renewal") == current
        assert len(held.renewal_secret_names()) == 33
    selected = json.loads((state.root / selection.SELECTOR).read_bytes())
    assert selected["schema"] == selection.GENERATION_SELECTOR_SCHEMA
    assert selected["applicationActivationId"] is None
    assert stat.S_IMODE((state.operation / selection.RETAINED_INTENT).stat().st_mode) == 0o600
    assert not (state.root / selection.PENDING).exists()


def test_alternating_application_and_renewal_history_preserves_both_markers(renewal_state):
    state = renewal_state
    _, first = activate(state)
    assert json.loads(first.selector)["schema"] == selection.SELECTOR_SCHEMA
    renewal = successor(state, "renewal-second", "b")
    previous, second = activate_renewal(renewal)
    assert previous == first
    assert (second.activation_id, second.renewal_activation_id, second.generation_activation_id) == (
        "a" * 32, "b" * 32, "b" * 32)
    application = successor(state, "application-third", "c")
    previous, third = activate(application)
    assert previous == second
    assert (third.activation_id, third.renewal_activation_id, third.generation_activation_id) == (
        "c" * 32, "b" * 32, "c" * 32)
    renewal_again = successor(state, "renewal-fourth", "d")
    previous, fourth = activate_renewal(renewal_again)
    assert previous == third
    assert (fourth.activation_id, fourth.renewal_activation_id, fourth.generation_activation_id) == (
        "c" * 32, "d" * 32, "d" * 32)
    for retained in (state, renewal, application, renewal_again):
        assert (retained.candidate / "retained").exists()
    assert not (state.root / selection.PENDING).exists()


@pytest.mark.parametrize("owner", ["application", "renewal"])
@pytest.mark.parametrize("method", ["pending", "current", "begin", "publish", "complete", "finish"])
def test_pending_attempt_cannot_be_reused_by_the_other_domain(renewal_state, owner, method):
    state = renewal_state
    other = "renewal" if owner == "application" else "application"
    with selection.locked(state.root) as held:
        previous = held.current(state.binding)
        held.begin(state.binding, state.operation, state.candidate, state.activation_id,
                   expected=previous, domain=owner)
        for domain in ("application", "renewal"):
            with pytest.raises(bootstrap.BootstrapError, match="activation is pending"):
                held.current(state.binding, domain=domain)
        before = (state.root / selection.PENDING).read_bytes()
        with pytest.raises(bootstrap.BootstrapError):
            if method == "current":
                held.current(state.binding, pending_operation=state.operation, domain=other)
            elif method == "begin":
                held.begin(state.binding, state.operation, state.candidate, state.activation_id,
                           expected=previous, domain=other)
            elif method == "publish":
                held.publish(state.binding, state.operation, expected=previous, domain=other)
            else:
                getattr(held, method)(state.binding, state.operation, domain=other)
        assert (state.root / selection.PENDING).read_bytes() == before
        assert not (state.root / selection.SELECTOR).exists()


@pytest.mark.parametrize("domain", ["application", "renewal"])
def test_prior_foreign_receipt_refuses_cross_domain_operation_reuse(renewal_state, domain):
    state = renewal_state
    foreign = selection.RENEWAL_VERIFIED if domain == "application" else selection.VERIFIED
    write(state.operation / foreign, {"private": "FOREIGN_DOMAIN_RECEIPT_CANARY"})
    with selection.locked(state.root) as held:
        previous = held.current(state.binding)
        with pytest.raises(bootstrap.BootstrapError):
            held.begin(state.binding, state.operation, state.candidate, state.activation_id,
                       expected=previous, domain=domain)
    assert not (state.root / selection.PENDING).exists()
    assert json.loads((state.operation / foreign).read_bytes())["private"] == "FOREIGN_DOMAIN_RECEIPT_CANARY"


@pytest.mark.parametrize("first_domain", ["application", "renewal"])
def test_latest_marker_cannot_be_reused_for_another_activation_domain(renewal_state, first_domain):
    state = renewal_state
    (activate if first_domain == "application" else activate_renewal)(state)
    next_state = successor(state, "next-marker-reuse", "a")
    other = "renewal" if first_domain == "application" else "application"
    with selection.locked(state.root) as held:
        previous = held.current(state.binding)
        with pytest.raises(bootstrap.BootstrapError):
            held.begin(state.binding, next_state.operation, next_state.candidate, next_state.activation_id,
                       expected=previous, domain=other)
    assert not (state.root / selection.PENDING).exists()


@pytest.mark.parametrize("tamper", ["missing-secret", "extra-secret", "duplicate-name", "duplicate-uid",
    "foreign-name", "empty-version", "wrong-schema", "wrong-status", "ordinary-secret", "empty-deployments",
    "empty-pods", "missing-delivery", "claimed-consumption", "wrong-predecessor", "wrong-activation"])
def test_renewal_requires_every_catalog_secret_and_complete_rollout_evidence(renewal_state, tamper):
    state = renewal_state
    with selection.locked(state.root) as held:
        previous = held.current(state.binding)
        held.begin(state.binding, state.operation, state.candidate, state.activation_id,
                   expected=previous, domain="renewal")
        value = renewal_proof(state, previous.directory)
        if tamper == "missing-secret":
            value["secrets"].pop()
        elif tamper == "extra-secret":
            value["secrets"].append({"name": "foreign", "uid": "foreign-uid", "resourceVersion": "200"})
        elif tamper == "duplicate-name":
            value["secrets"][1]["name"] = value["secrets"][0]["name"]
        elif tamper == "duplicate-uid":
            value["secrets"][1]["uid"] = value["secrets"][0]["uid"]
        elif tamper == "foreign-name":
            value["secrets"][0]["name"] = "marty-secrets"
        elif tamper == "empty-version":
            value["secrets"][0]["resourceVersion"] = ""
        elif tamper == "wrong-schema":
            value["schema"] = selection.VERIFIED_SCHEMA
        elif tamper == "wrong-status":
            value["status"] = "secret-and-rollouts-verified"
        elif tamper == "ordinary-secret":
            value["secret"] = value.pop("secrets")[0]
        elif tamper == "empty-deployments":
            value["deployments"] = []
        elif tamper == "empty-pods":
            value["deployments"][0]["podUids"] = []
        elif tamper == "missing-delivery":
            value["credentialDeliveryVerified"] = False
        elif tamper == "claimed-consumption":
            value["credentialConsumptionVerified"] = True
        elif tamper == "wrong-predecessor":
            value["previousDirectory"] = str(state.candidate)
        else:
            value["activationId"] = "b" * 32
        write(state.operation / selection.RENEWAL_VERIFIED, value)
        with pytest.raises(bootstrap.BootstrapError):
            held.publish(state.binding, state.operation, expected=previous, domain="renewal")
        assert not (state.root / selection.SELECTOR).exists()
        assert (state.root / selection.PENDING).exists()


@pytest.mark.parametrize("tamper", ["schema", "missing-input", "duplicate-secret"])
def test_renewal_refuses_incomplete_retained_publication_inventory(renewal_state, tamper):
    state = renewal_state
    publication = json.loads((state.root / "bootstrap-complete.json").read_bytes())
    contract = publication["credentialPublication"]
    if tamper == "schema":
        contract["schema"] = "unknown/v1"
    elif tamper == "missing-input":
        target = next(entry for entry in contract["catalog"]["secrets"] if entry["name"] == "keycloak-kms")
        target["fields"].pop("master-cookie.token")
    else:
        contract["catalog"]["secrets"].append(contract["catalog"]["secrets"][1])
    write(state.root / "bootstrap-complete.json", publication)
    with selection.locked(state.root) as held:
        previous = held.current(state.binding)
        held.begin(state.binding, state.operation, state.candidate, state.activation_id,
                   expected=previous, domain="renewal")
        write(state.operation / selection.RENEWAL_VERIFIED, renewal_proof(state, previous.directory))
        with pytest.raises(bootstrap.BootstrapError):
            held.publish(state.binding, state.operation, expected=previous, domain="renewal")
        assert not (state.root / selection.SELECTOR).exists()


@pytest.mark.parametrize("field", ["applicationActivationId", "renewalActivationId"])
def test_selector_cannot_forge_a_preserved_domain_marker(renewal_state, field):
    state = renewal_state
    activate(state)
    renewal = successor(state, "renewal-second", "b")
    activate_renewal(renewal)
    path = state.root / selection.SELECTOR
    value = json.loads(path.read_bytes())
    value[field] = "f" * 32
    write(path, value)
    with selection.locked(state.root) as held:
        with pytest.raises(bootstrap.BootstrapError):
            held.current(state.binding)


def test_application_selector_cannot_downgrade_and_forget_a_prior_renewal(renewal_state):
    state = renewal_state
    activate_renewal(state)
    application = successor(state, "application-second", "b")
    activate(application)
    path = state.root / selection.SELECTOR
    value = json.loads(path.read_bytes())
    for key in ("domain", "applicationActivationId", "renewalActivationId", "intentIdentity"):
        value.pop(key)
    value["schema"] = selection.SELECTOR_SCHEMA
    write(path, value)
    with selection.locked(state.root) as held:
        with pytest.raises(bootstrap.BootstrapError):
            held.current(state.binding)


@pytest.mark.parametrize("target", ["retained-intent", "earlier-proof", "earlier-generation"])
def test_completed_selection_revalidates_predecessor_custody(renewal_state, target):
    state = renewal_state
    activate(state)
    renewal = successor(state, "renewal-second", "b")
    activate_renewal(renewal)
    application = successor(state, "application-third", "c")
    activate(application)
    if target == "earlier-generation":
        state.candidate.rename(state.candidate.with_name("preserved-candidate"))
        private_directory(state.candidate)
    else:
        path = (renewal.operation / selection.RETAINED_INTENT if target == "retained-intent"
                else state.operation / selection.VERIFIED)
        replacement = path.with_suffix(".replacement")
        write(replacement, path.read_bytes())
        os.replace(replacement, path)
    with selection.locked(state.root) as held:
        with pytest.raises(bootstrap.BootstrapError):
            held.current(state.binding)


@pytest.mark.parametrize("failure", ["before-rename", "after-rename-fsync"])
def test_interrupted_renewal_selection_reconciles_with_both_domain_markers(renewal_state, monkeypatch, failure):
    state = renewal_state
    _, first = activate(state)
    renewal = successor(state, "renewal-second", "b")
    with selection.locked(state.root) as held:
        held.begin(state.binding, renewal.operation, renewal.candidate, renewal.activation_id,
                   expected=first, domain="renewal")
        write(renewal.operation / selection.RENEWAL_VERIFIED, renewal_proof(renewal, first.directory))
        with monkeypatch.context() as patch:
            if failure == "before-rename":
                def fail_replace(*args, **kwargs):
                    raise OSError("PRIVATE_RENAME_CANARY")
                patch.setattr(selection.os, "replace", fail_replace)
            else:
                original = selection.os.fsync
                def fail(descriptor):
                    value = json.loads((state.root / selection.SELECTOR).read_bytes())
                    if descriptor == held.descriptor and value.get("domain") == "renewal":
                        raise OSError("PRIVATE_SYNC_CANARY")
                    return original(descriptor)
                patch.setattr(selection.os, "fsync", fail)
            with pytest.raises(bootstrap.BootstrapError):
                held.publish(state.binding, renewal.operation, expected=first, domain="renewal")
        with pytest.raises(bootstrap.BootstrapError, match="activation is pending"):
            held.current(state.binding)
    with selection.locked(state.root) as held:
        recovered = held.current(state.binding, pending_operation=renewal.operation, domain="renewal")
        assert recovered == first
        held.publish(state.binding, renewal.operation, expected=recovered, domain="renewal")
        held.complete(state.binding, renewal.operation, domain="renewal")
        held.finish(state.binding, renewal.operation, domain="renewal")
        final = held.current(state.binding)
        assert (final.activation_id, final.renewal_activation_id) == ("a" * 32, "b" * 32)


def test_retained_intent_is_resynced_before_a_failed_begin_can_resume(renewal_state, monkeypatch):
    state = renewal_state
    with selection.locked(state.root) as held:
        previous = held.current(state.binding)
        original = selection.os.fsync
        operation_identity = selection.owned_directory(state.operation)
        with monkeypatch.context() as patch:
            def fail(descriptor):
                if selection.directory_identity(os.fstat(descriptor)) == operation_identity:
                    raise OSError("PRIVATE_RETAINED_INTENT_SYNC_CANARY")
                return original(descriptor)
            patch.setattr(selection.os, "fsync", fail)
            with pytest.raises(bootstrap.BootstrapError):
                held.begin(state.binding, state.operation, state.candidate, state.activation_id,
                           expected=previous, domain="renewal")
        assert not (state.root / selection.PENDING).exists()
        retained_inode = (state.operation / selection.RETAINED_INTENT).stat().st_ino
        resynced = []
        with monkeypatch.context() as patch:
            def observe(descriptor):
                if os.fstat(descriptor).st_ino == retained_inode:
                    assert not (state.root / selection.PENDING).exists()
                    resynced.append(True)
                return original(descriptor)
            patch.setattr(selection.os, "fsync", observe)
            held.begin(state.binding, state.operation, state.candidate, state.activation_id,
                       expected=previous, domain="renewal")
        assert resynced == [True]
        assert held.current(state.binding, pending_operation=state.operation, domain="renewal") == previous


@pytest.mark.parametrize("prefix", [0, 127])
def test_renewal_completion_retains_an_exact_interrupted_prefix(renewal_state, prefix):
    state = renewal_state
    with selection.locked(state.root) as held:
        previous = publish_renewal(state, held)
        value = {**renewal_proof(state, previous.directory), "schema": selection.RENEWAL_COMPLETE_SCHEMA,
                 "status": "renewal-generation-selected"}
        raw = bootstrap.encoded(value)
        write(state.operation / selection.RENEWAL_COMPLETE, raw[:prefix])
        assert held.complete(state.binding, state.operation, domain="renewal") == value
        retained = list(state.operation.glob("renewal-activation-complete-interrupted-*.partial"))
        assert len(retained) == 1 and retained[0].read_bytes() == raw[:prefix]
        held.finish(state.binding, state.operation, domain="renewal")
        assert held.current(state.binding).renewal_activation_id == state.activation_id


def test_renewal_completion_sync_failure_keeps_pending_and_recovers_same_receipt(renewal_state, monkeypatch):
    state = renewal_state
    with selection.locked(state.root) as held:
        publish_renewal(state, held)
        original = selection.os.fsync
        operation_identity = selection.owned_directory(state.operation)
        with monkeypatch.context() as patch:
            def fail(descriptor):
                if (selection.directory_identity(os.fstat(descriptor)) == operation_identity
                        and (state.operation / selection.RENEWAL_COMPLETE).exists()):
                    raise OSError("PRIVATE_COMPLETION_SYNC_CANARY")
                return original(descriptor)
            patch.setattr(selection.os, "fsync", fail)
            with pytest.raises(bootstrap.BootstrapError):
                held.complete(state.binding, state.operation, domain="renewal")
        assert (state.root / selection.PENDING).exists()
        inode = (state.operation / selection.RENEWAL_COMPLETE).stat().st_ino
        held.complete(state.binding, state.operation, domain="renewal")
        assert (state.operation / selection.RENEWAL_COMPLETE).stat().st_ino == inode
        held.finish(state.binding, state.operation, domain="renewal")
        assert held.current(state.binding).renewal_activation_id == state.activation_id


@pytest.mark.parametrize("domain", ["application", "renewal"])
@pytest.mark.parametrize("boundary", ["before-unlink", "directory-sync", "current-validation"])
def test_finish_deadline_expiry_preserves_exact_pending_and_same_attempt_recovery(
        renewal_state, monkeypatch, domain, boundary):
    state = renewal_state
    clock = [0]

    def check_deadline():
        bootstrap.require(clock[0] < 900, "activation deadline expired")

    with selection.locked(state.root) as held:
        previous = (publish_renewal if domain == "renewal" else publish)(state, held)
        held.complete(state.binding, state.operation, domain=domain)
        pending = (state.root / selection.PENDING).read_bytes()
        selector = selection.private_record(state.root / selection.SELECTOR)
        completion_path = state.operation / (selection.RENEWAL_COMPLETE if domain == "renewal" else selection.COMPLETE)
        completion = selection.private_record(completion_path)
        with monkeypatch.context() as patch:
            if boundary == "before-unlink":
                clock[0] = 901
            elif boundary == "directory-sync":
                original_fsync = selection.os.fsync

                def delayed_sync(descriptor):
                    original_fsync(descriptor)
                    if descriptor == held.descriptor and not (state.root / selection.PENDING).exists():
                        clock[0] = 901

                patch.setattr(selection.os, "fsync", delayed_sync)
            else:
                original_current = held.current

                def delayed_validation(*args, **kwargs):
                    result = original_current(*args, **kwargs)
                    if not (state.root / selection.PENDING).exists():
                        clock[0] = 901
                    return result

                patch.setattr(held, "current", delayed_validation)
            with pytest.raises(bootstrap.BootstrapError, match="activation deadline expired"):
                held.finish(state.binding, state.operation, domain=domain, check_deadline=check_deadline)
        assert (state.root / selection.PENDING).read_bytes() == pending
        assert stat.S_IMODE((state.root / selection.PENDING).stat().st_mode) == 0o600
        assert selection.private_record(state.root / selection.SELECTOR) == selector
        assert selection.private_record(completion_path) == completion
        with pytest.raises(bootstrap.BootstrapError, match="activation is pending"):
            held.current(state.binding)
    with selection.locked(state.root) as held:
        assert held.current(state.binding, pending_operation=state.operation, domain=domain) == previous
        held.publish(state.binding, state.operation, expected=previous, domain=domain)
        held.complete(state.binding, state.operation, domain=domain)
        clock[0] = 0
        held.finish(state.binding, state.operation, domain=domain, check_deadline=check_deadline)
        assert not (state.root / selection.PENDING).exists()
        assert held.current(state.binding).directory == state.candidate


@pytest.mark.parametrize("domain", ["application", "renewal"])
def test_finish_failed_unlink_sync_restores_pending_without_reverting_selected_generation(
        renewal_state, monkeypatch, domain):
    state = renewal_state
    with selection.locked(state.root) as held:
        previous = (publish_renewal if domain == "renewal" else publish)(state, held)
        held.complete(state.binding, state.operation, domain=domain)
        pending = (state.root / selection.PENDING).read_bytes()
        selector = selection.private_record(state.root / selection.SELECTOR)
        original_fsync = selection.os.fsync
        with monkeypatch.context() as patch:
            def fail_unlink_sync(descriptor):
                if descriptor == held.descriptor and not (state.root / selection.PENDING).exists():
                    raise OSError("PRIVATE_PENDING_SYNC_CANARY")
                return original_fsync(descriptor)

            patch.setattr(selection.os, "fsync", fail_unlink_sync)
            with pytest.raises(bootstrap.BootstrapError) as error:
                held.finish(state.binding, state.operation, domain=domain)
        assert "PRIVATE_" not in str(error.value)
        assert (state.root / selection.PENDING).read_bytes() == pending
        assert selection.private_record(state.root / selection.SELECTOR) == selector
        assert held.current(state.binding, pending_operation=state.operation, domain=domain) == previous
        held.finish(state.binding, state.operation, domain=domain)
        assert held.current(state.binding).directory == state.candidate
