"""Root-held nonce-to-signed-grant rendezvous ordering tests."""
import json
import os
from pathlib import Path
import sys

import pytest

if sys.platform != "linux" or os.geteuid() != 0:
    pytest.skip("VM signed exchange requires Linux root", allow_module_level=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_vm_exchange as exchange
from installer_candidate_controller import ControllerLease
import installer_release as release


@pytest.fixture
def arranged(tmp_path, monkeypatch):
    registry = tmp_path / "registry"
    registry.mkdir(mode=0o700)
    fixture = json.loads((Path(__file__).resolve().parents[1]
                          / "rust/crates/deployment-catalog/tests/fixtures/installer-candidate-records.json")
                         .read_text())
    grant = release.decode(fixture["authorization"].encode())
    expected = {key: grant[key] for key in release.CONTEXT_FIELDS}
    target = dict(guest_id="11111111-1111-4111-8111-111111111111",
                  disk_id="e" * 64, engine_id="test-engine-12345678",
                  installation_id="22222222-2222-4222-8222-222222222222")
    verified = dict(intent_sha256="a" * 64, receipt_sha256="b" * 64,
                    target=target, ssh=dict(host="127.0.0.1", port=2222,
                                            user="installer", control_dir="/root/control",
                                            controller_key_sha256="c" * 64,
                                            known_hosts_sha256="d" * 64))
    calls = []
    def verify(lease, _registry, **_kwargs):
        assert lease.parent is not None
        calls.append("verify")
        return verified
    monkeypatch.setattr(exchange, "verify_consumed_intent", verify)
    args = dict(client=object(), registry=registry,
                authorization=tmp_path / "candidate-authorization.json",
                assets=tmp_path / "assets", expected=expected,
                gh=tmp_path / "gh", cosign=tmp_path / "cosign",
                descriptor=tmp_path / "controller-transport.json",
                upload_output=tmp_path / "upload.json",
                grant_output=tmp_path / "grant", controller_user_id=101,
                clock=lambda: 100000)
    return args, verified, calls


def test_exchange_releases_lease_for_transport_and_reverifies(arranged):
    args, verified, calls = arranged
    def upload(**kwargs):
        calls.append("upload")
        with ControllerLease(args["registry"]):
            pass
        assert kwargs["ledger"] == args["registry"] / (args["expected"]["nonce"] + ".json")
        return dict(receipt_sha256=verified["receipt_sha256"],
                    context_sha256=release.candidate_context_sha256(args["expected"]))
    def receive(**kwargs):
        calls.append("receive")
        with ControllerLease(args["registry"]):
            pass
        assert release.decode(kwargs["context_file"].read_bytes()) == args["expected"]
        assert release.decode(kwargs["target_file"].read_bytes()) == verified["target"]
        return dict(receipt_sha256=verified["receipt_sha256"],
                    context_sha256=release.candidate_context_sha256(args["expected"]),
                    target_sha256=release.digest(release.encode(verified["target"])))
    result = exchange.exchange(**args, upload=upload, receive=receive)
    assert calls == ["verify", "upload", "receive", "verify"]
    assert result["guest_dispatched"] is False and result["acceptance"] is False
    assert result["intent_sha256"] == verified["intent_sha256"]


def test_uncertain_upload_stops_without_retrieval_or_retry(arranged):
    args, _, calls = arranged
    def upload(**_kwargs):
        calls.append("upload")
        (args["registry"] / "uncertain-upload-intent").write_text("retained")
        raise OSError("synthetic lost GitHub response")
    def receive(**_kwargs):
        pytest.fail("retrieved grant after uncertain upload")
    with pytest.raises(OSError, match="lost GitHub response"):
        exchange.exchange(**args, upload=upload, receive=receive)
    assert calls == ["verify", "upload"]
    assert (args["registry"] / "uncertain-upload-intent").read_text() == "retained"
    with pytest.raises(FileExistsError):
        exchange.exchange(**args, upload=upload, receive=receive)
    assert calls == ["verify", "upload", "verify"]


def test_mismatched_signed_grant_refuses_completion(arranged):
    args, verified, calls = arranged
    def upload(**_kwargs):
        calls.append("upload")
        return dict(receipt_sha256=verified["receipt_sha256"],
                    context_sha256=release.candidate_context_sha256(args["expected"]))
    def receive(**_kwargs):
        calls.append("receive")
        return dict(receipt_sha256="c" * 64,
                    context_sha256=release.candidate_context_sha256(args["expected"]),
                    target_sha256=release.digest(release.encode(verified["target"])))
    with pytest.raises(ValueError, match="signed execution grant differs"):
        exchange.exchange(**args, upload=upload, receive=receive)
    assert calls == ["verify", "upload", "receive"]


@pytest.mark.parametrize("incomplete,observer_failure,replace_output", [
    (False, False, False), (True, False, False),
    (False, True, False), (True, True, False),
    (False, False, True)])
def test_post_grant_same_vm_dispatch_keeps_lease(arranged, monkeypatch,
                                                  incomplete, observer_failure,
                                                  replace_output):
    args, verified, calls = arranged
    registry = args["registry"]
    control = registry / "control"
    control.mkdir(mode=0o700)
    key, known_hosts = control / "controller_ed25519", control / "known_hosts"
    key.write_bytes(b"synthetic private key")
    known_hosts.write_bytes(b"synthetic pinned host")
    key.chmod(0o600)
    known_hosts.chmod(0o600)
    verified["ssh"]["control_dir"] = str(control)
    verified["ssh"]["controller_key_sha256"] = release.digest(key.read_bytes())
    verified["ssh"]["known_hosts_sha256"] = release.digest(known_hosts.read_bytes())
    verified["receipt_sha256"] = release.digest(b"receipt")
    host_raw = release.encode({"synthetic": "previously admitted host"})
    fresh = dict(target=verified["target"], ssh=verified["ssh"],
                 authorization_sha256=release.digest(b"authorization"),
                 inventory_sha256=release.digest(b"inventory"),
                 initial_guest_readiness_sha256=release.digest(b"initial VM"),
                 host_observation_sha256=release.digest(host_raw),
                 probe_finished_at=100000)
    vm_id = verified["target"]["guest_id"]
    observation_id = "33333333-3333-4333-8333-333333333333"
    def preflight(lease, _registry, _runtime, **kwargs):
        calls.append("fresh")
        exchange._write(lease.parent,
                        vm_id + "." + kwargs["observation_id"] + ".host-preflight.json",
                        fresh)
        exchange._write(lease.parent,
                        vm_id + "." + kwargs["observation_id"] + ".host-observation.json",
                        release.decode(host_raw))
        return fresh
    monkeypatch.setattr(exchange, "preflight", preflight)
    monkeypatch.setattr(exchange.dispatch, "verify", lambda **_kwargs:
                        (b"authorization", b"receipt", b"inventory", {}))
    monkeypatch.setattr(exchange.dispatch, "verified_harness_script",
                        lambda *_args: "synthetic signed TLS probe")
    monkeypatch.setattr(exchange.dispatch, "verified_bootstrap",
                        lambda *_args: "synthetic signed bootstrap")
    def invoke(**kwargs):
        calls.append("invoke")
        assert kwargs["lease"].parent is not None
        assert kwargs["host"] == "127.0.0.1"
        assert kwargs["key"] == key
        assert kwargs["approved_ssh"]["key_sha256"] == release.digest(key.read_bytes())
        assert (registry / (args["expected"]["nonce"] +
                           ".vm-dispatch-approval.json")).is_file()
        kwargs["admission_gate"]("setup")
        kwargs["admission_gate"]("invoke")
        if incomplete:
            raise ValueError("native startup recorded; acceptance incomplete")
        return dict(installation_ready=False, acceptance_report=False)
    signed = dict(schema="elevenid.installer-vm-signed-exchange/v1",
                  nonce=args["expected"]["nonce"],
                  intent_sha256=verified["intent_sha256"],
                  receipt_sha256=verified["receipt_sha256"],
                  target=verified["target"], ssh=verified["ssh"],
                  guest_dispatched=False, acceptance=False)
    def process_observer(_registry, _runtime, *, vm_id, process_check_id,
                         lease):
        calls.append("process")
        if observer_failure:
            raise OSError("post-dispatch VM observation failed")
        record = dict(schema=exchange.live_vm.PROCESS_CHECK_SCHEMA,
                      vm_id=vm_id, observation_id=process_check_id,
                      initial_guest_readiness_sha256=fresh[
                          "initial_guest_readiness_sha256"])
        exchange._write(lease.parent,
                        vm_id + ".process-check-" + process_check_id + ".json",
                        record)
        return record
    def observe_installed(**kwargs):
        calls.append("installed")
        assert kwargs["checkpoint"]["acceptance"] is False
        assert kwargs["checkpoint"]["dispatch"] == (
            "failed_or_incomplete" if incomplete else "returned_zero_unqualified")
        if replace_output:
            kwargs["output"].rename(kwargs["output"].with_name(
                kwargs["output"].name + ".held"))
            kwargs["output"].mkdir(mode=0o700)
        kwargs["unchanged"]()
        kwargs["writer"](exchange.acceptance.NAME,
                         release.encode(kwargs["checkpoint"]))
        return kwargs["checkpoint"]
    with ControllerLease(registry) as lease:
        exchange._write(lease.parent, args["expected"]["nonce"] + ".context.json",
                        args["expected"])
        exchange._write(lease.parent, args["expected"]["nonce"] + ".target.json",
                        verified["target"])
    common = dict(registry=registry, runtime_parent=registry,
                  vm_id=vm_id, installation_id=verified["target"]["installation_id"],
                  observation_id=observation_id,
                  final_observation_id="44444444-4444-4444-8444-444444444444",
                  exchange_result=signed, authorization=args["authorization"],
                  assets=args["assets"], expected=args["expected"], gh=args["gh"],
                  cosign=args["cosign"], grants=registry / "signed-grant",
                  ssh=Path("/usr/bin/ssh"), scp=Path("/usr/bin/scp"),
                  clock=args["clock"])
    if observer_failure:
        with pytest.raises(OSError, match="VM observation failed"):
            exchange.dispatch_once(**common, invoke=invoke,
                                   process_observer=process_observer,
                                   observe_installed=observe_installed)
    elif replace_output:
        with pytest.raises(ValueError, match="registry replaced"):
            exchange.dispatch_once(**common, invoke=invoke,
                                   process_observer=process_observer,
                                   observe_installed=observe_installed)
    elif incomplete:
        with pytest.raises(ValueError, match="acceptance incomplete"):
            exchange.dispatch_once(**common, invoke=invoke,
                                   process_observer=process_observer,
                                   observe_installed=observe_installed)
    else:
        result = exchange.dispatch_once(**common, invoke=invoke,
                                        process_observer=process_observer,
                                        observe_installed=observe_installed)
        assert result["installation_ready"] is False
    assert calls[:7] == ["verify", "fresh", "verify", "invoke", "fresh",
                        "fresh", "process"]
    assert calls.count("invoke") == 1
    assert calls.count("installed") == (0 if observer_failure else 1)
    post_path = registry / (args["expected"]["nonce"] +
                            ".vm-post-dispatch.json")
    if observer_failure:
        assert not post_path.exists()
    else:
        post = release.decode(post_path.read_bytes())
        assert post["command_returned_zero"] is (not incomplete)
        assert post["installation_ready"] is False
        assert post["acceptance"] is False
        output = registry / (args["expected"]["nonce"] +
                             ".installed-observations")
        if replace_output:
            assert not (output / exchange.acceptance.NAME).exists()
            assert (output.with_name(output.name + ".held") /
                    "vm-binding.json").is_file()
        else:
            assert (output / exchange.acceptance.NAME).is_file()
    before_retry = len(calls)
    with pytest.raises(FileExistsError):
        exchange.dispatch_once(**common, invoke=invoke,
                               process_observer=process_observer,
                               observe_installed=observe_installed)
    assert calls[before_retry:] == ["verify", "fresh"]
    assert calls.count("invoke") == 1
