"""Cap-only reconciliation never replays a producer or rewrites failed receipts."""

from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_windows_failed_current_inspection import failed_current
from test_windows_recovery_phase_receipts import receipts
import selfhost_windows_recovery_leaf_caps as caps
import selfhost_windows_staging_recovery as staging
import selfhost_windows_renewal_native as native
import selfhost_windows_selection as selection


def partial_from_complete(raw):
    keep = {
        phase + "." + event + ".json"
        for phase in ("authority", "prepare", "tls")
        for event in ("started", "completed")
    } | {
        "keycloak.started.json",
        "prepare.helper.json",
        "tls.created.json",
        "tls.helper.json",
    }
    return {name: value if name in keep else b"" for name, value in raw.items()}


def helper(config, cycle, reconciled=False):
    phase = "cap-reconcile" if reconciled else "keycloak"
    return {
        "id": ("f" if reconciled else "d") * 64,
        "name": config["project"] + "-renew-" + phase + "-" + cycle,
        "image": config["native"]["helper_image"],
        "inspection_sha256": ("a" if reconciled else "b") * 64,
    }


def cap_receipts(original, config, cycle, guard, data):
    intent = {
        "schema": "marty.windows-staged-leaf-cap-reconciliation/v1",
        "guard_sha256": guard,
        "original_receipt_sha256": original,
        "failed_helper": helper(config, cycle),
        "binary_sha256": config["native"]["binary_sha256"],
        "data_sha256": data,
        "credential_admission": False,
        "producer_replay": False,
    }
    raw = {
        caps.PREFIX + "intent.json": selection.packed(intent),
        caps.PREFIX + "helper.json": selection.packed(helper(config, cycle, True)),
    }
    for phase in caps.PHASES:
        for event in ("started", "completed"):
            raw[caps.PREFIX + phase + "." + event + ".json"] = selection.packed(
                {"phase": phase, "event": event, "metadata": {}}
            )
    return raw


def test_only_exact_failed_keycloak_boundary_is_eligible():
    original = partial_from_complete(receipts())
    hashes, helpers = caps.partial_receipts(
        original, "marty-production-synthetic", "a" * 32, "helper", "services"
    )
    assert len(hashes) == 18 and len(helpers) == 3
    for name in original:
        changed = dict(original)
        changed[name] = (
            b""
            if original[name]
            else selection.packed(
                {"phase": "export", "event": "started", "metadata": {}}
            )
        )
        with pytest.raises((ValueError, KeyError)):
            caps.partial_receipts(
                changed, "marty-production-synthetic", "a" * 32, "helper", "services"
            )


def item(config, cycle, reconciled=False):
    proof = helper(config, cycle, reconciled)
    return {
        "Id": proof["id"],
        "Name": "/" + proof["name"],
        "RestartCount": 0,
        "Config": {
            "Image": proof["image"],
            "Labels": {"marty.windows.renewal": cycle},
            "Entrypoint": ["python"],
            "Cmd": ["-c", caps.CAP_WORKER if reconciled else native.PRODUCER_ASSEMBLE],
        },
        "State": {
            "Status": "exited",
            "Running": False,
            "ExitCode": 0 if reconciled else 1,
            "OOMKilled": False,
            "Error": "",
        },
        "HostConfig": {
            "NetworkMode": config["native"]["network"],
            "LogConfig": {"Type": "none"},
            "ReadonlyRootfs": True,
            "RestartPolicy": {"Name": "no"},
            "Privileged": False,
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "SecurityOpt": ["no-new-privileges"],
            "Memory": 512 * 1024 * 1024,
            "NanoCpus": 1000000000,
        },
        "Mounts": [
            {
                "Destination": "/control",
                "Type": "volume",
                "Name": config["native"]["control_volume"],
                "RW": True,
            },
            *[
                {
                    "Destination": dest,
                    "Type": "bind",
                    "Source": config["native"][key],
                    "RW": False,
                }
                for dest, key in [
                    ("/operator/tool", "binary"),
                    ("/input/ca.crt", "ca_file"),
                ]
            ],
        ],
    }


def config():
    return {
        "project": "marty-production-synthetic",
        "native": {
            "helper_image": "helper",
            "network": "private_default",
            "control_volume": "private-control",
            "binary": "C:/private/tool",
            "ca_file": "C:/private/ca.crt",
            "binary_sha256": "1" * 64,
        },
    }


@pytest.mark.parametrize("reconciled", [False, True])
@pytest.mark.parametrize(
    "fault",
    [
        "running",
        "exit",
        "oom",
        "command",
        "image",
        "network",
        "log",
        "writable",
        "restart",
        "privileged",
        "caps",
        "volume",
        "bind",
        "extra",
        "census",
    ],
)
def test_wrong_helper_identity_or_active_transport_refuses(reconciled, fault):
    cfg = config()
    cycle = "a" * 32
    value = item(cfg, cycle, reconciled)
    if fault == "running":
        value["State"]["Running"] = True
    elif fault == "exit":
        value["State"]["ExitCode"] = 7
    elif fault == "oom":
        value["State"]["OOMKilled"] = True
    elif fault == "command":
        value["Config"]["Cmd"] = ["-c", "PRIVATE_SENTINEL"]
    elif fault == "image":
        value["Config"]["Image"] = "other"
    elif fault == "network":
        value["HostConfig"]["NetworkMode"] = "host"
    elif fault == "log":
        value["HostConfig"]["LogConfig"]["Type"] = "json-file"
    elif fault == "writable":
        value["HostConfig"]["ReadonlyRootfs"] = False
    elif fault == "restart":
        value["RestartCount"] = 1
    elif fault == "privileged":
        value["HostConfig"]["Privileged"] = True
    elif fault == "caps":
        value["HostConfig"]["CapAdd"] = ["SYS_ADMIN"]
    elif fault == "volume":
        value["Mounts"][0]["Name"] = "foreign"
    elif fault == "bind":
        value["Mounts"][1]["RW"] = True
    elif fault == "extra":
        value["Mounts"].append({"Destination": "/foreign"})
    else:
        with pytest.raises(ValueError):
            caps.checked_helpers(
                [item(cfg, cycle), value], {}, cfg, cycle, complete=False
            )
        return
    with pytest.raises((ValueError, KeyError)):
        caps.helper_proof(value, cfg, cycle, reconciled=reconciled)


def test_helper_census_binds_both_retained_records_and_no_other_cycle_process():
    cfg = config()
    cycle = "a" * 32
    before = item(cfg, cycle)
    after = item(cfg, cycle, True)
    assert set(
        caps.checked_helpers([before, after], {}, cfg, cycle, complete=True)
    ) == {"failed", "reconciled"}
    assert set(caps.checked_helpers([before], {}, cfg, cycle, complete=False)) == {
        "failed"
    }
    with pytest.raises(ValueError):
        caps.checked_helpers([before, after], {}, cfg, cycle, complete=False)
    retired = {"tls.helper.json": {"id": before["Id"], "name": "retired"}}
    with pytest.raises(ValueError):
        caps.checked_helpers([before, after], retired, cfg, cycle, complete=True)


@contextmanager
def failed_assembler(monkeypatch):
    import test_selfhost_windows_selection as fixtures

    original_model = fixtures.model

    def full_inventory(directory):
        model = original_model(directory)
        # The boundary fixture normally contains token inputs only. Include
        # the public-certificate slots to exercise the real 39-change contract.
        for index in range(40 - len(model["secrets"])):
            name = "synthetic_public_certificate_" + str(index)
            model["secrets"][name] = {"file": str(directory / name)}
            model["services"]["gateway"]["secrets"].append(
                {"source": name, "target": "/run/secrets/" + name}
            )
        return model

    monkeypatch.setattr(fixtures, "model", full_inventory)
    with failed_current(monkeypatch) as (root, path, cfg, failed, events):
        output = root / ("windows-renewal-" + "e" * 32)
        output.mkdir()
        data = {}
        monkeypatch.setattr(native, "require_recovery_capability", lambda *args: None)

        def produce(staged, current, logical, cycle, image, checkpoint):
            data.update(config=staged, current=current, cycle=cycle)
            events.append("original-producer")
            for phase in ("prepare", "tls"):
                checkpoint(phase, "started", {})
                metadata = {
                    "id": ("b" if phase == "prepare" else "c") * 64,
                    "name": cfg["project"] + "-renew-" + phase + "-" + cycle,
                    "image": image
                    if phase == "tls"
                    else staged["native"]["helper_image"],
                }
                if phase == "tls":
                    checkpoint(phase, "created", metadata)
                checkpoint(phase, "helper", metadata)
                checkpoint(phase, "completed", {})
            checkpoint("keycloak", "started", {})
            raise ValueError("PUBLIC_FAILED_ASSEMBLER")

        monkeypatch.setattr(native, "produce_recovery_generation", produce)
        with pytest.raises(ValueError):
            staging.stage_recovery_generation(path, output, "marty-selfhost-synthetic")

        def helpers(items, old, staged, cycle, *, complete):
            result = {"failed": helper(staged, cycle)}
            if complete:
                result["reconciled"] = helper(staged, cycle, True)
            return result

        monkeypatch.setattr(caps, "checked_helpers", helpers)
        before = {p.name: p.read_bytes() for p in output.iterdir()}
        yield path, cfg, output, events, data, before


@pytest.mark.parametrize("fault", [None, "helper", "export", "candidate"])
def test_reconciliation_is_once_only_and_preserves_all_failed_receipts(
    monkeypatch, fault
):
    with failed_assembler(monkeypatch) as (path, cfg, root, events, data, before):

        def mint(staged, current, cycle):
            assert (root / (caps.PREFIX + "intent.json")).stat().st_size > 0
            events.append("cap-helper")
            if fault == "helper":
                raise ValueError("PRIVATE_SENTINEL")
            return helper(staged, cycle, True)

        def export(staged, mirror):
            if fault == "export":
                raise ValueError("PRIVATE_SENTINEL")
            return {
                n: b"PUBLIC_BOUNDED_" + n.encode() if value else b""
                for n, value in data["current"].items()
            }

        def prove(*args):
            events.append("candidate-proof")
            if fault == "candidate":
                raise ValueError("PRIVATE_SENTINEL")

        monkeypatch.setattr(caps, "run_cap_helper", mint)
        monkeypatch.setattr(native, "export_generation", export)
        monkeypatch.setattr(native, "preflight_recovery", prove)
        if fault:
            with pytest.raises(ValueError):
                caps.reconcile(path, root)
        else:
            result = caps.reconcile(path, root)
            assert result["guards_retained"] and not result["credential_admission"]
            proof = staging.publish_recovery_candidate(path, root)
            assert (
                set(proof["receipt_sha256"])
                == staging.RECOVERY_RECEIPTS | caps.CAP_RECEIPTS
            )
        assert before == {name: (root / name).read_bytes() for name in before}
        assert not (root / "activation").exists()
        assert selection.renewal.recovery_guard(cfg).exists()
        assert selection.renewal.renewal_staging_guard(cfg).exists()
        with pytest.raises(ValueError):
            caps.reconcile(path, root)
        assert events.count("original-producer") == events.count("cap-helper") == 1


def test_worker_source_is_valid_and_does_not_include_activation_or_revocation():
    compile(caps.CAP_WORKER, "cap-worker", "exec")
    assert "explicit_max_ttl" in caps.CAP_WORKER
    assert "generation-unbounded-retained" in caps.CAP_WORKER
    assert "keycloak-provision" not in caps.CAP_WORKER
    assert "auth/token/revoke" not in caps.CAP_WORKER


def test_rebound_cap_evidence_and_partial_alternatives_are_refused():
    cfg = config()
    cycle = "a" * 32
    old = {"x": "1" * 64}
    guard = "2" * 64
    data = "3" * 64
    raw = cap_receipts(old, cfg, cycle, guard, data)
    helpers = {"failed": helper(cfg, cycle), "reconciled": helper(cfg, cycle, True)}
    assert (
        len(caps.completed_receipts(raw, old, helpers, cfg, cycle, guard, data)) == 10
    )
    for name in raw:
        changed = dict(raw)
        changed[name] = b""
        with pytest.raises((ValueError, KeyError)):
            caps.completed_receipts(changed, old, helpers, cfg, cycle, guard, data)
    changed = deepcopy(helpers)
    changed["failed"]["id"] = "7" * 64
    with pytest.raises(ValueError):
        caps.completed_receipts(raw, old, changed, cfg, cycle, guard, data)
    assert caps.receipt_names(staging.RECOVERY_RECEIPTS | caps.CAP_RECEIPTS)
    assert not caps.receipt_names(
        staging.RECOVERY_RECEIPTS | {caps.PREFIX + "intent.json"}
    )
