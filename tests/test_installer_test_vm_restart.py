"""Synthetic, non-VM tests for the one-shot installer test VM restart path."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import uuid

if sys.platform != "linux":
    raise unittest.SkipTest("Linux VM controller tests")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_test_vm_restart as restart

VM = "70573b98-a002-468c-a932-f27c1ca20440"
NONCE = "23157141-54e9-4744-8c80-a2321e850dec"


class Records(unittest.TestCase):
    def test_installer_only_memory_changes_only_qemu_m_and_preserves_first_launch(self):
        runtime = Path("/runtime") / VM
        original = restart.launcher._arguments(runtime, VM, 22024)
        selected = restart._restart_args(runtime, VM, 22024, original, 2048)
        index = original.index("-m") + 1
        self.assertEqual(restart.launcher.MEMORY_MIB, 4096)
        self.assertEqual(original[index], "4096")
        self.assertEqual(selected[index], "2048")
        self.assertEqual([i for i, (old, new) in enumerate(zip(original, selected))
                          if old != new], [index])
        self.assertEqual(restart.launcher._arguments(runtime, VM, 22024), original)
        self.assertEqual(restart._restart_args(runtime, VM, 22024, original, 4096),
                         original)
        for unsupported in (True, 1024, 8192, "2048"):
            with self.assertRaisesRegex(ValueError, "memory profile unsupported"):
                restart._restart_args(runtime, VM, 22024, original, unsupported)
        with self.assertRaisesRegex(ValueError, "historical memory policy"):
            restart._restart_args(runtime, VM, 22024, [*original, "-m", "1024"], 2048)

    def test_installer_only_headroom_thresholds_and_guest_memtotal(self):
        def record(kib):
            return f"MemAvailable: {kib} kB\n".encode()
        self.assertEqual(restart._headroom_from_meminfo(record(4194304), 2048),
                         4194304)
        with self.assertRaisesRegex(ValueError, "installer-only host memory"):
            restart._headroom_from_meminfo(record(4194303), 2048)
        self.assertEqual(restart._headroom_from_meminfo(record(6291456), 4096),
                         6291456)
        with self.assertRaisesRegex(ValueError, "installer-only host memory"):
            restart._headroom_from_meminfo(record(6291455), 4096)
        with self.assertRaisesRegex(ValueError, "memory profile unsupported"):
            restart._headroom_from_meminfo(record(4194304), False)
        self.assertEqual(restart._guest_mem_total("MemTotal: 2010000 kB", 2048),
                         2010000)
        with self.assertRaisesRegex(ValueError, "guest memory differs"):
            restart._guest_mem_total("MemTotal: 1000000 kB", 2048)

    def test_poweroff_binds_original_pid_and_result(self):
        launch = {"pid": 862, "start_ticks": "73433773", "observed_at": 100}
        intent = {"acceptance": False, "disk_retained": True, "pid": 862,
                  "reason": "bootstrap-only", "requested_at": 110,
                  "start_ticks": "73433773", "vm_id": VM}
        result = {"acceptance": False, "disk_retained": True, "observed_at": 111,
                  "original_pid": 862, "original_process_absent": True,
                  "original_start_ticks": "73433773", "request_error_type": None,
                  "vm_id": VM}
        original = [restart.release.encode(intent), restart.release.encode(result)]

        def read(_fd, name):
            return (original[0], intent) if name.endswith("poweroff-intent.json") else (original[1], result)

        with mock.patch.object(restart, "_read_record", side_effect=read):
            self.assertEqual(restart._poweroff(1, VM, {"launch_receipt": launch}),
                             tuple(original))
            for key, value in (("original_process_absent", False),
                               ("original_pid", 999), ("request_error_type", "SSH"),
                               ("disk_retained", False)):
                previous = result[key]
                result[key] = value
                with self.assertRaises(ValueError):
                    restart._poweroff(1, VM, {"launch_receipt": launch})
                result[key] = previous

    def test_missing_or_unknown_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                restart._no_prior_attempt(fd, VM)
                (Path(directory) / (VM + ".restart-intent.json")).write_text("partial")
                with self.assertRaisesRegex(ValueError, "already recorded"):
                    restart._no_prior_attempt(fd, VM)
            finally:
                os.close(fd)

    def test_dangling_monitor_name_blocks_before_port_check(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            (runtime / "disk.qcow2").write_bytes(b"disk")
            (runtime / "qmp.sock").symlink_to("missing-socket")
            with self.assertRaisesRegex(ValueError, "monitor endpoint"):
                restart._no_live_owner(12345, 99999999, "123", str(uuid.uuid4()),
                                       runtime, 22024)

    def test_status_census_reads_all_four_uids(self):
        self.assertEqual(restart._status_uids(
            b"Name:\tactor\nUid:\t0\t0\t994\t0\n"), (0, 0, 994, 0))
        with self.assertRaisesRegex(ValueError, "UID inventory"):
            restart._status_uids(b"Uid:\t0\t0\t994\n")
        with self.assertRaisesRegex(ValueError, "status inventory"):
            restart._status_uids(b"Uid:\t0\t0\t994\t0\n" + b"x" * 65536)
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc / "status").write_bytes(b"Uid:\t0\t0\t994\t0\n")
            self.assertTrue(restart._actor_is_uid(proc, 994))
            self.assertFalse(restart._actor_is_uid(proc, 995))

    def test_original_pid_reuse_is_distinguished_by_start_and_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            (runtime / "disk.qcow2").write_bytes(b"disk")
            current_start = restart._process_start(Path("/proc") / str(os.getpid()))
            boot = str(uuid.uuid4())
            with mock.patch.object(restart.launcher, "_boot_id", return_value=boot):
                self.assertTrue(restart._original_still_live(os.getpid(), current_start, boot))
                self.assertFalse(restart._original_still_live(
                    os.getpid(), str(int(current_start) + 1), boot))
                self.assertFalse(restart._original_still_live(
                    os.getpid(), current_start, str(uuid.uuid4())))

    def test_real_self_descriptor_census_keeps_enumerator_open(self):
        with tempfile.TemporaryDirectory() as directory:
            disk = Path(directory) / "disk.qcow2"
            disk.write_bytes(b"synthetic-disk")
            proc = Path("/proc") / str(os.getpid())
            with disk.open("rb") as held:
                restart._scan_descriptors(proc, disk.stat())
                self.assertEqual(os.fstat(held.fileno()).st_ino, disk.stat().st_ino)
            with disk.open("r+b") as held:
                with self.assertRaisesRegex(ValueError, "live process holder"):
                    restart._scan_descriptors(proc, disk.stat())
                self.assertEqual(os.fstat(held.fileno()).st_ino, disk.stat().st_ino)

    def test_mutable_disk_digest_is_stable_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.qcow2"
            path.write_bytes(b"mutable-test-disk")
            with path.open("rb") as file:
                self.assertEqual(restart._mutable_digest(file.fileno())[:2],
                                 (17, restart.hashlib.sha256(b"mutable-test-disk").hexdigest()))
            path.write_bytes(b"")
            with path.open("rb") as file:
                with self.assertRaisesRegex(ValueError, "bounds"):
                    restart._mutable_digest(file.fileno())

    def test_disk_metadata_open_refuses_fifo_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            path = parent / "disk.qcow2"
            os.mkfifo(path, 0o600)
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                info = path.lstat()
                with self.assertRaisesRegex(ValueError, "held metadata"):
                    restart._disk_fd(fd, os.getuid(), os.getgid(), info.st_dev, info.st_ino)
                path.unlink()
                path.symlink_to("missing")
                info = path.lstat()
                with self.assertRaisesRegex(ValueError, "held metadata"):
                    restart._disk_fd(fd, os.getuid(), os.getgid(), info.st_dev, info.st_ino)
            finally:
                os.close(fd)

    def test_record_chain_refusal_precedes_mutation(self):
        with mock.patch.object(restart, "_read_record", side_effect=ValueError("record changed")), \
             mock.patch.object(restart, "_write") as write:
            with self.assertRaisesRegex(ValueError, "record changed"):
                restart._record_set(1, VM)
            write.assert_not_called()

    def test_historical_guest_engine_and_chain_are_exact(self):
        history = {"creation_intent": b"created", "launch_receipt": b"launched"}
        record = {"vm_id": VM, "phase": "guest-ready", "qualified": False,
                  "dispatch_authorized": False,
                  "record_sha256": {name + "_sha256": restart.release.digest(raw)
                                    for name, raw in history.items()},
                  "guest": {"docker_engine_id": "engine-705",
                            "guest_uid": 1000, "guest_user": "installer"}}
        def read(_fd, _name):
            return restart.release.encode(record), record
        with mock.patch.object(restart, "_read_record", side_effect=read):
            self.assertEqual(restart._historical_guest(1, VM, history)[1], "engine-705")
            record["record_sha256"]["launch_receipt_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "historical guest"):
                restart._historical_guest(1, VM, history)

    def test_mutable_image_rejects_external_data_file(self):
        disk = Path("/fixture/disk.qcow2")
        base = "/fixture/base.img"
        observed = {"filename": str(disk), "format": "qcow2",
                    "backing-filename": base, "full-backing-filename": base,
                    "backing-filename-format": "qcow2", "virtual-size": 32 * 1024**3,
                    "format-specific": {"data": {"data-file": "/other/secret"}}}
        with mock.patch.object(restart, "_header_backing"), \
             mock.patch.object(restart, "_qemu_info_unprivileged",
                               side_effect=lambda *_a, **_k: restart.release.encode(observed)):
            with self.assertRaisesRegex(ValueError, "backing differs"):
                restart._mutable_image_info(disk, 1, 994, 987, base, 32 * 1024**3)
            observed["format-specific"] = {}
            restart._mutable_image_info(disk, 1, 994, 987, base, 32 * 1024**3)
            observed["backing-filename"] = "/other/base"
            with self.assertRaisesRegex(ValueError, "backing differs"):
                restart._mutable_image_info(disk, 1, 994, 987, base, 32 * 1024**3)
            observed["backing-filename"] = base
            observed["virtual-size"] = 16 * 1024**3
            with self.assertRaisesRegex(ValueError, "backing differs"):
                restart._mutable_image_info(disk, 1, 994, 987, base, 32 * 1024**3)

    def test_header_rejects_external_feature_and_changed_backing_before_parser(self):
        base = b"/fixture/signed-base.img"
        header = bytearray(65536)
        header[:4] = b"QFI\xfb"
        header[4:8] = (3).to_bytes(4, "big")
        header[8:16] = (528).to_bytes(8, "big")
        header[16:20] = len(base).to_bytes(4, "big")
        header[20:24] = (16).to_bytes(4, "big")
        header[24:32] = (32 * 1024**3).to_bytes(8, "big")
        header[100:104] = (112).to_bytes(4, "big")
        header[112:116] = (0xe2792aca).to_bytes(4, "big")
        header[116:120] = (5).to_bytes(4, "big")
        header[120:125] = b"qcow2"
        header[528:528 + len(base)] = base
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "disk.qcow2"
            def check() -> None:
                path.write_bytes(header)
                with path.open("rb") as held:
                    restart._header_backing(held.fileno(), base.decode(), 32 * 1024**3)
            check()
            header[72:80] = (4).to_bytes(8, "big")
            with self.assertRaisesRegex(ValueError, "header differs"):
                check()
            header[72:80] = (0).to_bytes(8, "big")
            header[112:116] = (0x44415441).to_bytes(4, "big")
            with self.assertRaisesRegex(ValueError, "external data file"):
                check()
            header[112:116] = (0xe2792aca).to_bytes(4, "big")
            header[528] = ord("X")
            with self.assertRaisesRegex(ValueError, "backing name"):
                check()

    def test_qemu_info_runs_as_dedicated_uid_with_fixed_format(self):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"{}")
        os.close(write_fd)
        class Process:
            pid = 12345
            stdout = os.fdopen(read_fd, "rb")
            def poll(self):
                return 0
            def wait(self, timeout):
                return 0
        with mock.patch.object(restart.launcher, "_trusted_tool", return_value="a" * 64), \
             mock.patch.object(restart.subprocess, "Popen", return_value=Process()) as spawn:
            self.assertEqual(restart._qemu_info_unprivileged(
                Path("/runtime/disk.qcow2"), 994, 987), b"{}")
        argv = spawn.call_args.args[0]
        options = spawn.call_args.kwargs
        self.assertEqual(argv[:6], [str(restart.launcher.SETPRIV), "--reuid", "994",
                                    "--regid", "987", "--clear-groups"])
        for required in ("--bounding-set=-all", "--inh-caps=-all",
                         "--ambient-caps=-all", "--no-new-privs"):
            self.assertIn(required, argv)
        self.assertEqual(argv[-5:], ["info", "-f", "qcow2", "--output=json",
                                      "/runtime/disk.qcow2"])
        self.assertTrue(options["close_fds"] and options["start_new_session"])
        self.assertEqual(options["cwd"], "/")

    def test_pre_spawn_rejects_changed_disk_and_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            registry = base / "registry"
            runtime_parent = base / "runtime"
            runtime_dir = runtime_parent / VM
            registry.mkdir(mode=0o700)
            control = registry / (VM + ".control")
            control.mkdir(mode=0o700)
            runtime_parent.mkdir(mode=0o755)
            runtime_dir.mkdir(mode=0o700)
            disk = runtime_dir / "disk.qcow2"
            disk.write_bytes(b"booted-overlay")
            disk.chmod(0o600)
            info = disk.stat()
            with disk.open("rb") as held:
                observed = restart._mutable_digest(held.fileno())
            intent = {"runtime_dir_device": runtime_dir.stat().st_dev,
                      "runtime_dir_inode": runtime_dir.stat().st_ino,
                      "control_dir_device": control.stat().st_dev,
                      "control_dir_inode": control.stat().st_ino,
                      "disk_device": info.st_dev, "disk_inode": info.st_ino,
                      "mutable_disk_bytes": observed[0], "mutable_disk_sha256": observed[1],
                      "mutable_disk_mtime_ns": observed[2],
                      "mutable_disk_ctime_ns": observed[3],
                      "poweroff_intent_sha256": restart.release.digest(b"record"),
                      "poweroff_result_sha256": restart.release.digest(b"record"),
                      "historical_guest_readiness_sha256": restart.release.digest(b"record")}
            raw = restart.release.encode(intent)
            context = {"raw": {}, "records": {"runtime_receipt": {
                "runtime_uid": os.getuid(), "runtime_gid": os.getgid()},
                "seed_receipt": {}, "creation_receipt": {"virtual_gib": 32},
                "creation_intent": {
                    "image": {"image_path": "/fixture/base.img"}}}}
            class Lease:
                parent = os.open(registry, os.O_RDONLY | os.O_DIRECTORY)
            try:
                def read(_fd, name):
                    return (raw, intent) if name.endswith("restart-intent.json") else (b"record", {})
                with mock.patch.object(restart, "_read_record", side_effect=read), \
                     mock.patch.object(restart.launcher, "_seed_media"), \
                     mock.patch.object(restart, "_mutable_image_info"), \
                     mock.patch.object(restart, "_source_and_control"):
                    self.assertEqual(restart._recheck_before_spawn(
                        Path("/source"), registry, runtime_parent, VM, Lease(), intent, context), raw)
                    disk.write_bytes(b"changed-overlay")
                    with self.assertRaisesRegex(ValueError, "mutable disk changed"):
                        restart._recheck_before_spawn(
                            Path("/source"), registry, runtime_parent, VM, Lease(), intent, context)
                    disk.write_bytes(b"booted-overlay")
                    changed = dict(intent, disk_inode=info.st_ino + 1)
                    with self.assertRaisesRegex(ValueError, "restart intent changed"):
                        restart._recheck_before_spawn(
                            Path("/source"), registry, runtime_parent, VM, Lease(), changed, context)
            finally:
                os.close(Lease.parent)

    def test_preflight_writes_only_after_stable_owned_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            registry = base / "registry"
            runtime_parent = base / "runtime"
            runtime_dir = runtime_parent / VM
            control_dir = registry / (VM + ".control")
            registry.mkdir(mode=0o700)
            runtime_parent.mkdir(mode=0o755)
            runtime_dir.mkdir(mode=0o700)
            control_dir.mkdir(mode=0o700)
            disk = runtime_dir / "disk.qcow2"
            disk.write_bytes(b"booted-overlay")
            disk.chmod(0o600)
            info = disk.stat()
            runtime = {"runtime_uid": os.getuid(), "runtime_gid": os.getgid(),
                       "runtime_account": "account", "runtime_dir_device": runtime_dir.stat().st_dev,
                       "runtime_dir_inode": runtime_dir.stat().st_ino,
                       "disk_device": info.st_dev, "disk_inode": info.st_ino}
            seed = {"ssh_port": 22024, "control_dir_device": control_dir.stat().st_dev,
                    "control_dir_inode": control_dir.stat().st_ino}
            args = restart.launcher._arguments(runtime_dir, VM, 22024)
            records = {"runtime_receipt": runtime, "seed_receipt": seed,
                       "creation_receipt": {"virtual_gib": 32},
                       "creation_intent": {"image": {"image_path": "/fixture/base.img"}},
                       "launch_intent": {"runtime_dir": str(runtime_dir),
                                         "control_dir": str(control_dir), "args": args,
                                         "qemu_sha256": "a" * 64, "kvm_gid": 993},
                       "launch_pid": {"pid": 862, "start_ticks": "123",
                                      "controller_boot_id": str(uuid.uuid4())}}
            class Lease:
                parent = os.open(registry, os.O_RDONLY | os.O_DIRECTORY)
                owner_pid = os.getpid()
            wrote = []
            def write(_fd, _name, record):
                wrote.append(record)
                return restart.release.encode(record)
            def read(_fd, name):
                return (b"history", {}) if name.endswith("guest-readiness.json") else (b"power", {})
            try:
                with mock.patch.object(restart, "_record_set", return_value=({}, records)), \
                     mock.patch.object(restart, "_poweroff", return_value=(b"power", b"power")), \
                     mock.patch.object(restart, "_historical_guest",
                                       return_value=(b"history", "engine", 1000)), \
                     mock.patch.object(restart, "_identity", return_value="account"), \
                     mock.patch.object(restart, "_source_and_control"), \
                     mock.patch.object(restart, "_no_live_owner"), \
                     mock.patch.object(restart, "_mutable_image_info"), \
                     mock.patch.object(restart.launcher, "_seed_media"), \
                     mock.patch.object(restart, "_installer_headroom", return_value=5 * 1024**2), \
                     mock.patch.object(restart.launcher, "_trusted_tool", return_value="a" * 64), \
                     mock.patch.object(restart.launcher, "_kvm_group", return_value=993), \
                     mock.patch.object(restart.launcher, "_boot_id", return_value=str(uuid.uuid4())), \
                     mock.patch.object(restart, "_read_record", side_effect=read), \
                     mock.patch.object(restart, "_write", side_effect=write):
                    intent, _ = restart._prepare_restart(Path("/source"), registry,
                                                          runtime_parent, VM, NONCE, 2048, Lease())
                    self.assertEqual(intent["mutable_disk_sha256"],
                                     restart.hashlib.sha256(b"booted-overlay").hexdigest())
                    memory_index = intent["args"].index("-m") + 1
                    self.assertEqual(intent["args"][memory_index], "2048")
                    self.assertEqual(intent["guest_memory_mib"], 2048)
                    self.assertEqual(intent["controller_reserve_mib"], 2048)
                    self.assertEqual(intent["purpose"], "installer_only_trial")
                    self.assertEqual(intent["host_mem_available_kib_at_preflight"],
                                     5 * 1024**2)
                    self.assertEqual(len(wrote), 0)
                    wrote.clear()
                    disk.write_bytes(b"changed-overlay")
                    with mock.patch.object(restart, "_mutable_digest",
                                           side_effect=ValueError("disk changed")):
                        with self.assertRaisesRegex(ValueError, "disk changed"):
                            restart._prepare_restart(Path("/source"), registry,
                                                      runtime_parent, VM, NONCE, 2048, Lease())
                    self.assertEqual(wrote, [])
                    runtime["runtime_dir_inode"] += 1
                    with self.assertRaisesRegex(ValueError, "runtime directory differs"):
                        restart._prepare_restart(Path("/source"), registry,
                                                  runtime_parent, VM, NONCE, 2048, Lease())
                    self.assertEqual(wrote, [])
                    runtime["runtime_dir_inode"] -= 1
                    with mock.patch.object(restart, "_no_live_owner",
                                           side_effect=ValueError("active VM")):
                        with self.assertRaisesRegex(ValueError, "active VM"):
                            restart._prepare_restart(Path("/source"), registry,
                                                      runtime_parent, VM, NONCE, 2048, Lease())
                    with mock.patch.object(restart, "_poweroff",
                                           side_effect=ValueError("poweroff missing")):
                        with self.assertRaisesRegex(ValueError, "poweroff missing"):
                            restart._prepare_restart(Path("/source"), registry,
                                                      runtime_parent, VM, NONCE, 2048, Lease())
                    with mock.patch.object(restart, "_record_set",
                                           side_effect=ValueError("historical chain changed")):
                        with self.assertRaisesRegex(ValueError, "historical chain changed"):
                            restart._prepare_restart(Path("/source"), registry,
                                                      runtime_parent, VM, NONCE, 2048, Lease())
                    with mock.patch.object(restart, "_installer_headroom",
                                           side_effect=ValueError("memory headroom insufficient")):
                        with self.assertRaisesRegex(ValueError, "memory headroom"):
                            restart._prepare_restart(Path("/source"), registry,
                                                      runtime_parent, VM, NONCE, 2048, Lease())
                    self.assertEqual(wrote, [])
            finally:
                os.close(Lease.parent)

    def test_restart_refusal_precedes_spawn(self):
        class Lease:
            parent = 5
            def __init__(self, registry):
                self.registry = registry
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return None

        with mock.patch.object(restart.os, "geteuid", return_value=0), \
             mock.patch.object(restart, "ControllerLease", Lease), \
             mock.patch.object(restart.launcher, "_trusted_tool", return_value="a" * 64), \
             mock.patch.object(restart.launcher, "_kvm_group", return_value=993), \
             mock.patch.object(restart, "_prepare_restart", side_effect=ValueError("custody")), \
             mock.patch.object(restart.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(ValueError, "custody"):
                restart.restart(Path("/source"), Path("/registry"), Path("/runtime"),
                                vm_id=VM, attempt_nonce=NONCE)
            spawn.assert_not_called()

    def test_inspect_repeats_preflight_without_record_or_spawn(self):
        class Lease:
            parent = 5
            def __init__(self, registry):
                self.registry = registry
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return None
        with mock.patch.object(restart.os, "geteuid", return_value=0), \
             mock.patch.object(restart, "ControllerLease", Lease), \
             mock.patch.object(restart, "_prepare_restart", return_value=({}, {})) as prepare, \
             mock.patch.object(restart, "_write") as write, \
             mock.patch.object(restart.subprocess, "Popen") as spawn:
            result = restart.inspect(Path("/signed-image"), Path("/registry"),
                                     Path("/runtime"), vm_id=VM, attempt_nonce=NONCE)
            self.assertTrue(result["read_only"])
            self.assertFalse(result["qualified"] or result["dispatch_authorized"])
            self.assertEqual(prepare.call_count, 1)
            write.assert_not_called()
            spawn.assert_not_called()

    def test_headroom_refusal_precedes_restart_intent_and_spawn(self):
        class Lease:
            parent = 5
            def __init__(self, registry):
                self.registry = registry
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return None
        with mock.patch.object(restart.os, "geteuid", return_value=0), \
             mock.patch.object(restart, "ControllerLease", Lease), \
             mock.patch.object(restart.launcher, "_trusted_tool", return_value="a" * 64), \
             mock.patch.object(restart.launcher, "_kvm_group", return_value=993), \
             mock.patch.object(restart, "_prepare_restart", return_value=({}, {})), \
             mock.patch.object(restart, "_installer_headroom",
                               side_effect=ValueError("VM installer-only host memory headroom insufficient")), \
             mock.patch.object(restart, "_write") as write, \
             mock.patch.object(restart.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(ValueError, "memory headroom"):
                restart.restart(Path("/source"), Path("/registry"), Path("/runtime"),
                                vm_id=VM, attempt_nonce=NONCE, guest_memory_mib=2048)
            write.assert_not_called()
            spawn.assert_not_called()

    def test_restart_writes_exact_attempt_chain_with_mock_process(self):
        class Lease:
            parent = 5
            def __init__(self, registry):
                self.registry = registry
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return None

        class Process:
            pid = 12345
            def poll(self):
                return None

        runtime = {"runtime_uid": 994, "runtime_gid": 987}
        intent = {"schema": restart.SCHEMA, "phase": "intent", "vm_id": VM,
                  "attempt_nonce": NONCE, "ssh_port": 22024,
                  "qemu_sha256": "a" * 64, "args": ["/usr/bin/qemu-system-x86_64"],
                  "disk_device": 1, "disk_inode": 2, "controller_boot_id": str(uuid.uuid4()),
                  "qualified": False, "dispatch_authorized": False,
                  "application_deployment_authorized": False}
        context = {"runtime_dir": Path("/runtime") / VM,
                   "records": {"runtime_receipt": runtime,
                               "launch_pid": {"pid": 862, "start_ticks": "123",
                                              "controller_boot_id": str(uuid.uuid4())}}}
        live = {"pid": 12345, "start_ticks": "123", "disk_fd": 7}
        written = {}
        def write(_fd, name, record):
            written[name] = record
            return b"intent" if name.endswith("restart-intent.json") else restart.release.encode(record)
        with mock.patch.object(restart.os, "geteuid", return_value=0), \
             mock.patch.object(restart, "ControllerLease", Lease), \
             mock.patch.object(restart.launcher, "_trusted_tool", return_value="a" * 64), \
             mock.patch.object(restart.launcher, "_kvm_group", return_value=993), \
             mock.patch.object(restart, "_prepare_restart", return_value=(intent, context)), \
             mock.patch.object(restart, "_installer_headroom", return_value=5 * 1024**2), \
             mock.patch.object(restart, "_recheck_before_spawn", return_value=b"intent"), \
             mock.patch.object(restart, "_same_path"), \
             mock.patch.object(restart, "_no_live_owner"), \
             mock.patch.object(restart.subprocess, "Popen", return_value=Process()) as spawn, \
             mock.patch.object(restart.launcher, "_start_ticks", return_value="123"), \
             mock.patch.object(restart, "_read_record", return_value=(b"intent", intent)), \
             mock.patch.object(restart, "_write", side_effect=write), \
             mock.patch.object(restart.os, "readlink", return_value=str(restart.launcher.QEMU)), \
             mock.patch.object(restart.launcher, "_live", return_value=live):
            result = restart.restart(Path("/source"), Path("/registry"), Path("/runtime"),
                                     vm_id=VM, attempt_nonce=NONCE)
        self.assertEqual(spawn.call_count, 1)
        self.assertEqual(result["pid"], 12345)
        self.assertEqual(result["intent_sha256"], restart.release.digest(b"intent"))
        self.assertFalse(result["qualified"] or result["dispatch_authorized"]
                         or result["application_deployment_authorized"])
        self.assertEqual(written[VM + ".restart-pid.json"]["attempt_nonce"], NONCE)
        self.assertEqual(written[VM + ".restart-receipt.json"]["start_ticks"], "123")


if __name__ == "__main__":
    unittest.main()
