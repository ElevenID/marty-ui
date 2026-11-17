"""A stopped recovery helper's public CA read never exempts other storage."""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
import os
from subprocess import CompletedProcess
from pathlib import Path
import sys

import pytest

sys.path[:0] = [
    str(Path(__file__).resolve().parents[1] / "scripts"),
    str(Path(__file__).parent),
]
import selfhost_windows_renewal as renewal
import selfhost_windows_selection as selection
import selfhost_windows_recovery_leaf_caps as caps
from test_windows_recovery_leaf_caps import config, item
from test_windows_recovery_leaf_caps import failed_assembler
from test_selfhost_windows_inputs import private_fixture


def identities(monkeypatch):
    def identity(path):
        key = str(path).replace("\\", "/")
        parent = ("volume", "root")
        node = ("volume", key)
        return Path(key), node, {node, parent} if key != "C:/owned" else {node}

    # Distinct explicit NTFS object identities with a real ancestor relation.
    def actual(path):
        key = str(path).replace("\\", "/")
        if key == "C:/owned":
            return Path(key), ("volume", "root"), {("volume", "root")}
        return identity(path)

    monkeypatch.setattr(renewal, "windows_identity", actual)


def storage_items():
    owned = {
        "Id": "a" * 64,
        "Config": {
            "Labels": {"com.docker.compose.project": "marty-production-synthetic"}
        },
        "Mounts": [
            {"Type": "bind", "Source": "C:/owned", "Destination": "/bao", "RW": True}
        ],
    }
    reader = {
        "Id": "b" * 64,
        "Config": {"Labels": {}},
        "Mounts": [
            {
                "Type": "bind",
                "Source": "C:/owned/tls/ca.crt",
                "Destination": "/input/ca.crt",
                "RW": False,
            }
        ],
    }
    return owned, reader


def test_exact_ro_ca_reader_keeps_namespace_witness(monkeypatch):
    identities(monkeypatch)
    owned, reader = storage_items()
    with pytest.raises(ValueError):
        renewal.disjoint_storage([owned, reader], "marty-production-synthetic", {})
    proof = renewal.disjoint_storage(
        [owned, reader],
        "marty-production-synthetic",
        {},
        retained_ca_readers={reader["Id"]: "C:/owned/tls/ca.crt"},
    )
    assert {row[0].replace("\\", "/") for row in proof} == {
        "C:/owned",
        "C:/owned/tls/ca.crt",
    }


@pytest.mark.parametrize(
    "fault",
    ["rw", "destination", "source", "id", "missing-id", "other-mount", "other-reader"],
)
def test_reader_cannot_hide_other_overlap_or_mount_drift(monkeypatch, fault):
    identities(monkeypatch)
    owned, reader = storage_items()
    supplied = {reader["Id"]: "C:/owned/tls/ca.crt"}
    items = [owned, reader]
    if fault == "rw":
        reader["Mounts"][0]["RW"] = True
    elif fault == "destination":
        reader["Mounts"][0]["Destination"] = "/elsewhere"
    elif fault == "source":
        reader["Mounts"][0]["Source"] = "C:/owned/other.crt"
    elif fault == "id":
        reader["Id"] = "c" * 64
    elif fault == "missing-id":
        del reader["Id"]
    elif fault == "other-mount":
        reader["Mounts"].append(
            {
                "Type": "bind",
                "Source": "C:/owned/data",
                "Destination": "/control",
                "RW": True,
            }
        )
    else:
        other = deepcopy(reader)
        other["Id"] = "c" * 64
        items.append(other)
    with pytest.raises(ValueError):
        renewal.disjoint_storage(
            items, "marty-production-synthetic", {}, retained_ca_readers=supplied
        )


@contextmanager
def guarded_reader():
    if os.name != "nt":
        pytest.skip("Actual held private NTFS inputs")
    with private_fixture() as (parent, _):
        cfg = config()
        cfg["current_secrets"] = str(parent / "current")
        cfg["native"].update(
            network=cfg["project"] + "_default",
            control_volume=cfg["project"] + "-renewal-control",
        )
        cycle = "a" * 32
        root = parent / ("windows-renewal-" + cycle)
        root.mkdir()
        staged = deepcopy(cfg)
        staged["native"].update(
            renewed="/control/windows-renewal-" + cycle + "/generation",
            token_file="/control/recovery-session-" + cycle + "/token",
        )
        raw = selection.packed(staged)
        (root / "config.private.json").write_bytes(raw)
        guard = {
            "schema": "marty.windows-expired-renewal-staging/v1",
            "root": str(root),
            "config_sha256": selection.digest(raw),
        }
        with ExitStack() as stack:
            yield cfg, root, staged, guard, stack, cycle


def test_guard_bound_callback_rechecks_helper_and_allows_successor_path():
    with guarded_reader() as (cfg, root, staged, guard, stack, cycle):
        staged["native"]["binary"] = "C:/private/admitted-successor"
        raw = selection.packed(staged)
        (root / "config.private.json").write_bytes(raw)
        guard["config_sha256"] = selection.digest(raw)
        callback = caps.retained_ca_readers(cfg, root, selection.packed(guard), stack)
        failed = item(staged, cycle)
        assert callback([failed]) == {failed["Id"]: cfg["native"]["ca_file"]}
        complete = item(staged, cycle, True)
        assert len(callback([failed, complete])) == 2
        changed = deepcopy(failed)
        changed["State"]["Running"] = True
        with pytest.raises(ValueError):
            callback([changed, complete])


def test_docker_mount_array_order_does_not_change_helper_identity():
    import itertools

    cfg = config()
    cycle = "a" * 32
    original = item(cfg, cycle)
    expected = caps.helper_proof(original, cfg, cycle, reconciled=False)
    for mounts in itertools.permutations(original["Mounts"]):
        changed = deepcopy(original)
        changed["Mounts"] = list(mounts)
        assert caps.helper_proof(changed, cfg, cycle, reconciled=False) == expected
    changed = deepcopy(original)
    changed["Mounts"][0]["PUBLIC_UNKNOWN_METADATA"] = "changed"
    assert caps.helper_proof(changed, cfg, cycle, reconciled=False) != expected


@pytest.mark.parametrize(
    "fault",
    [
        "hash",
        "root",
        "ca",
        "network",
        "control",
        "helper-image",
        "missing",
        "recreated",
    ],
)
def test_unbound_or_changed_helper_refuses(fault):
    with guarded_reader() as (cfg, root, staged, guard, stack, cycle):
        if fault == "hash":
            guard["config_sha256"] = "0" * 64
        elif fault == "root":
            guard["root"] = str(root.parent / "other")
        elif fault in ("ca", "network", "control", "helper-image"):
            key = {
                "ca": "ca_file",
                "network": "network",
                "control": "control_volume",
                "helper-image": "helper_image",
            }[fault]
            staged["native"][key] = "other"
            raw = selection.packed(staged)
            (root / "config.private.json").write_bytes(raw)
            guard["config_sha256"] = selection.digest(raw)
        if fault in ("missing", "recreated"):
            callback = caps.retained_ca_readers(
                cfg, root, selection.packed(guard), stack
            )
            failed = item(staged, cycle)
            callback([failed])
            if fault == "missing":
                with pytest.raises(ValueError):
                    callback([])
            else:
                changed = deepcopy(failed)
                changed["Id"] = "e" * 64
                with pytest.raises(ValueError):
                    callback([changed])
        else:
            with pytest.raises(ValueError):
                caps.retained_ca_readers(cfg, root, selection.packed(guard), stack)


def test_context_revalidates_callback_on_same_closing_census(monkeypatch):
    identities(monkeypatch)
    _, reader = storage_items()
    reader.update(
        Image="sha256:" + "a" * 64,
        Created="fixed",
        RestartCount=0,
        State={"Status": "exited", "ExitCode": 1, "StartedAt": "fixed"},
        HostConfig={},
    )
    calls = []
    seen = []

    class Docker:
        def containers(self):
            value = [deepcopy(reader)]
            calls.append(value)
            if len(calls) == 2:
                value[0]["Mounts"][0]["RW"] = True
            return value

        def volumes(self):
            return {}

        def native_witnesses(self, *args):
            return {}

    def callback(items):
        seen.append(items)
        assert items[0]["Mounts"][0]["RW"] is False
        return {reader["Id"]: "C:/owned/tls/ca.crt"}

    context = renewal.ForeignContext(
        Docker(),
        "marty-production-synthetic",
        set(),
        [reader],
        {},
        "helper",
        retained_ca_readers=callback,
    )
    monkeypatch.setattr(context, "_candidate", lambda *args, **kwargs: {})
    # Keep snapshot stable to exercise the fresh closing helper check itself.
    monkeypatch.setattr(
        renewal, "context_snapshot", lambda items: {"fixed": {"project": "foreign"}}
    )
    with pytest.raises(renewal.UnsafeRenewalContext):
        context.check()
    assert len(seen) == 2 and seen[0] is calls[0] and seen[1] is calls[1]


@pytest.mark.parametrize(
    "fault", [None, "remove", "terminal-write", "guard-replacement", "new-participant"]
)
def test_unused_retirement_preserves_receipts_and_blocks_partial_outcomes(
    monkeypatch, fault
):
    import selfhost_windows_staging_recovery as staging
    import selfhost_windows_inputs as inputs

    checked = caps.checked_helpers
    with failed_assembler(monkeypatch) as (path, cfg, root, events, data, before):
        staged = data["config"]
        cycle = data["cycle"]
        docker = renewal.Docker(cfg["docker_host"], cfg["engine_id"])
        rows = docker.containers()
        rows.append(item(staged, cycle))
        observed = selection._inspect(cfg, "old", {}, None)
        monkeypatch.setattr(docker, "containers", lambda: deepcopy(rows))
        monkeypatch.setattr(
            observed["context"], "check", lambda **kwargs: deepcopy(rows)
        )
        monkeypatch.setattr(caps, "checked_helpers", checked)
        # Runtime path spellings are synthetic here; real NTFS file/guard
        # custody and removal/archival sequencing are exercised below.
        monkeypatch.setattr(renewal, "windows_mount_path_equal", lambda a, b: a == b)
        removed = []

        def remove(args, **kwargs):
            assert args == [*docker.prefix, "rm", "d" * 64]
            metadata = root.parent / (
                "." + cfg["project"] + ".unused-stage-retirement-" + cycle
            )
            assert (metadata / "intent.json").is_file()
            assert (metadata / "failed.inspection.private.json").is_file()
            if fault == "remove":
                return CompletedProcess(args, 1, b"", b"PUBLIC_REFUSAL")
            rows[:] = [row for row in rows if row["Id"] != "d" * 64]
            removed.append(args[-1])
            if fault == "new-participant":
                unknown = deepcopy(item(staged, cycle))
                unknown["Id"] = "9" * 64
                unknown["Name"] = "/PUBLIC_UNEXPECTED_HELPER"
                rows.append(unknown)
            return CompletedProcess(args, 0, (args[-1] + "\n").encode(), b"")

        monkeypatch.setattr(renewal, "run_owned_mutation", remove)
        if fault == "terminal-write":

            def fail_terminal(*args):
                raise ValueError("PUBLIC_TERMINAL_WRITE_FAILURE")

            monkeypatch.setattr(caps, "_retirement_done", fail_terminal)
        if fault == "guard-replacement":
            original = inputs._held_private_input

            @contextmanager
            def replace_guard(target, *args, **kwargs):
                if kwargs.get("_rename_to") is not None:
                    replacement = Path(target).parent / "PUBLIC_REPLACEMENT"
                    replacement.write_bytes(Path(target).read_bytes())
                    os.replace(replacement, target)
                with original(target, *args, **kwargs) as raw:
                    yield raw

            monkeypatch.setattr(inputs, "_held_private_input", replace_guard)
        guard = renewal.recovery_guard(cfg)
        original_guard = guard.read_bytes()
        original_failure = renewal.renewal_staging_guard(cfg).read_bytes()
        if fault:
            with pytest.raises((ValueError, OSError)):
                caps.retire_unused_stage(path, root)
        else:
            result = caps.retire_unused_stage(path, root)
            assert result["guard_archived"] and result["failed_current_guard_retained"]
            assert not result["credential_admission"] and not guard.exists()
            archive = guard.parent / (
                "." + cfg["project"] + ".recovery-unused-retired-" + cycle + ".json"
            )
            assert archive.read_bytes() == original_guard
            caps.require_closed_retirements(cfg)
        assert before == {name: (root / name).read_bytes() for name in before}
        assert renewal.renewal_staging_guard(cfg).read_bytes() == original_failure
        assert not list(Path(staged["renewed_secrets"]).iterdir())
        assert events.count("original-producer") == 1
        assert removed == ([] if fault == "remove" else ["d" * 64])
        if fault:
            with pytest.raises(ValueError):
                caps.require_closed_retirements(cfg)
            with pytest.raises(ValueError), selection._session(path):
                pass
            fresh = root.parent / ("windows-renewal-" + "f" * 32)
            fresh.mkdir()
            with pytest.raises(ValueError):
                staging.stage_recovery_generation(
                    path, fresh, "marty-selfhost-synthetic"
                )
            assert events.count("original-producer") == 1
