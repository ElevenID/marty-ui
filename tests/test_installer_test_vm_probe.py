"""Synthetic tests for the dormant installer-only VM probe controller."""
from __future__ import annotations

import os
import json
import shutil
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

if sys.platform != "linux":
    raise unittest.SkipTest("Linux VM controller tests")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_test_vm_probe as probe

VM = "70573b98-a002-468c-a932-f27c1ca20440"
PROBE = "df5c63a6-3fb9-439e-8829-8df69d6b7bc0"
SOURCE = "47ac8d24107bea47cebcb9aa0665825dcfd438de"
TAG = "v1.1.263-nightly.20261026.40392505279"


class Probe(unittest.TestCase):
    def test_published_assets_require_exact_verified_receipts_and_signed_subjects(self):
        with tempfile.TemporaryDirectory() as directory:
            assets = Path(directory) / "published"
            assets.mkdir(mode=0o700)
            base = {"schema": probe.acquisition.SCHEMA,
                    "scope": "controller-acquisition-only", "source_sha": SOURCE,
                    "release_tag": TAG, "build_run_id": 40392909103,
                    "build_run_attempt": 1, "release_id": 123,
                    "release_observation_sha256": "", "started_at": 100,
                    "guest_acquisition": False, "acceptance": False}
            observed = {"release_id": 123}
            base["release_observation_sha256"] = probe.release.digest(
                probe.release.encode(observed))
            inventory_raw = b"synthetic-inventory"
            verified = dict(base, inventory_sha256=probe.release.digest(inventory_raw),
                            verified_at=101,
                            artifact_count=len(probe.published.expected_assets()))
            records = {"intent": base, "release": observed, "verified": verified}
            def canonical(path, _maximum):
                name = next(part for part in records if path.name.endswith(part + ".json"))
                record = records[name]
                return probe.release.encode(record), record
            def private_file(path, _maximum, executable=False):
                if executable:
                    return probe.dispatch.TOOLS[path.name]
                return ("a" * 64, 42)
            with mock.patch.object(probe, "_canonical", side_effect=canonical), \
                 mock.patch.object(probe.published, "observe", return_value=observed), \
                 mock.patch.object(probe.published, "verify_downloads"), \
                 mock.patch.object(probe.release, "verify_inventory_assets",
                                   return_value={"artifacts": [{"name": probe.OPERATOR,
                                                                    "sha256": "a" * 64,
                                                                    "size": 42}]}), \
                 mock.patch.object(probe.bootstrap, "private_file",
                                   return_value=inventory_raw), \
                 mock.patch.object(probe.dispatch, "private_file",
                                   side_effect=private_file), \
                 mock.patch.object(probe.provenance, "verify_subject") as signed:
                result = probe._verified_assets(assets, Path("/tools/gh"),
                                                Path("/tools/cosign"),
                                                mock.Mock(request=lambda *_a: {}))
                self.assertEqual(result["binary_sha256"], "a" * 64)
                self.assertEqual(signed.call_count, 2)
                verified["inventory_sha256"] = "b" * 64
                with self.assertRaisesRegex(ValueError, "inventory changed"):
                    probe._verified_assets(assets, Path("/tools/gh"),
                                           Path("/tools/cosign"),
                                           mock.Mock(request=lambda *_a: {}))

    def test_closed_guest_directory_name_rejects_injection(self):
        self.assertEqual(probe._guest_dir(PROBE),
                         "/home/installer/.marty-installer-only-probe-" + PROBE)
        for invalid in ("../tmp", PROBE + ";touch /tmp/unsafe", PROBE.upper(),
                        "00000000-0000-0000-0000-000000000000"):
            with self.assertRaises(ValueError):
                probe._guest_dir(invalid)

    def test_guest_directory_stamp_refuses_other_owner_mode_and_kind(self):
        binding = {"guest_uid": 1000}
        with mock.patch.object(probe, "_ssh", return_value=b"10:20:1000:700:directory:2\n"):
            self.assertEqual(probe._guest_stamp(binding, probe._guest_dir(PROBE)),
                             (10, 20, 1000, 700, "directory", 2))
        for bad in (b"10:20:0:700:directory:2\n",
                    b"10:20:1000:755:directory:2\n",
                    b"10:20:1000:700:symbolic link:2\n",
                    b"10:20:1000:700:directory:3\n"):
            with mock.patch.object(probe, "_ssh", return_value=bad):
                with self.assertRaises(ValueError):
                    probe._guest_stamp(binding, probe._guest_dir(PROBE))

    def test_guest_home_stamp_binds_owner_mode_and_inode(self):
        with mock.patch.object(probe, "_ssh", return_value=b"10:11:1000:700:directory:4\n"):
            self.assertEqual(probe._guest_home_stamp({"guest_uid": 1000}),
                             (10, 11, 1000, 700, "directory"))
        for raw in (b"10:11:0:700:directory:4\n",
                    b"10:11:1000:755:directory:4\n",
                    b"10:11:1000:700:symbolic link:4\n"):
            with mock.patch.object(probe, "_ssh", return_value=raw):
                with self.assertRaises(ValueError):
                    probe._guest_home_stamp({"guest_uid": 1000})

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir(mode=0o700)
            def real_stamp(_binding, _script, **_kwargs):
                item = home.stat()
                return (f"{item.st_dev}:{item.st_ino}:{item.st_uid}:"
                        f"{item.st_mode & 0o777:o}:directory:{item.st_nlink}\n").encode()
            with mock.patch.object(probe, "_ssh", side_effect=real_stamp):
                before_links = home.stat().st_nlink
                before = probe._guest_home_stamp({"guest_uid": os.getuid()})
                (home / "new-owned-probe").mkdir(mode=0o700)
                self.assertEqual(home.stat().st_nlink, before_links + 1)
                self.assertEqual(probe._guest_home_stamp({"guest_uid": os.getuid()}),
                                 before)

    def test_transport_uses_exact_directory_and_digest_before_probe_commands(self):
        directory = probe._guest_dir(PROBE)
        target = directory + "/marty-deploy"
        expected = {"binary_bytes": 42, "binary_sha256": "a" * 64}
        replies = [b"", b"10:20:1000:700:directory:2\n",
                   b"10:20:1000:700:directory:2\n", b"",
                   b"10:20:1000:700:directory:2\n"]
        with mock.patch.object(probe, "_ssh", side_effect=replies) as ssh, \
             mock.patch.object(probe, "_pinned", return_value=["-F", "/dev/null"]), \
             mock.patch.object(probe, "_guest_home_stamp", return_value=(10, 11, 1000, 700, "directory")), \
             mock.patch.object(probe, "_guest_operator",
                               return_value=(10, 21, 1000, 700, 1, 42)), \
             mock.patch.object(probe, "command", return_value=b"") as scp:
            result = probe._transport({"guest_uid": 1000, "port": 22024,
                                       "home_stamp": (10, 11, 1000, 700, "directory")},
                                      Path("/private/operator"), expected, PROBE)
        self.assertEqual(result["directory_stamp"],
                         (10, 20, 1000, 700, "directory", 2))
        self.assertEqual(ssh.call_args_list[0].args[1],
                         "umask 077; /usr/bin/mkdir -m 700 -- " + directory)
        self.assertEqual(scp.call_args.args[0][-2:],
                         ["/private/operator", "installer@127.0.0.1:" + target])
        self.assertEqual(scp.call_args.kwargs["env"], probe.restart.launcher.ENV)
        self.assertEqual(ssh.call_count, 5)

        with mock.patch.object(probe, "_ssh", side_effect=replies), \
             mock.patch.object(probe, "_pinned", return_value=[]), \
             mock.patch.object(probe, "_guest_home_stamp", return_value=(10, 11, 1000, 700, "directory")), \
             mock.patch.object(probe, "_guest_operator",
                               side_effect=ValueError("operator digest differs")), \
             mock.patch.object(probe, "command", return_value=b""):
            with self.assertRaisesRegex(ValueError, "operator digest differs"):
                probe._transport({"guest_uid": 1000, "port": 22024,
                                  "home_stamp": (10, 11, 1000, 700, "directory")},
                                 Path("/private/operator"), expected, PROBE)

    def test_held_guest_operator_digest_and_inode_are_required(self):
        binding = {"guest_uid": 1000}
        expected = {"binary_bytes": 42, "binary_sha256": "a" * 64}
        with mock.patch.object(probe, "_ssh",
                               return_value=("10:21:1000:700:1:42:" + "a" * 64 + "\n").encode()) as ssh:
            self.assertEqual(probe._guest_operator(binding, "/fixture/operator", expected),
                             (10, 21, 1000, 700, 1, 42))
        script = ssh.call_args.args[1]
        self.assertIn("os.O_PATH|os.O_NOFOLLOW", script)
        self.assertIn("/proc/self/fd/%d", script)
        self.assertIn("os.stat(p,follow_symlinks=False)", script)
        with mock.patch.object(probe, "_ssh",
                               return_value=("10:21:1000:700:1:42:" + "b" * 64 + "\n").encode()):
            with self.assertRaisesRegex(ValueError, "guest operator differs"):
                probe._guest_operator(binding, "/fixture/operator", expected)

    def test_guest_operator_observation_script_reopens_exact_synthetic_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "operator"
            target.write_bytes(b"synthetic-public-operator")
            target.chmod(0o700)
            expected = {"binary_bytes": target.stat().st_size,
                        "binary_sha256": probe.hashlib.sha256(target.read_bytes()).hexdigest()}
            def local(_binding, script, **_kwargs):
                run = subprocess.run(shlex.split(script), capture_output=True,
                                     check=False, timeout=5)
                if run.returncode != 0:
                    raise ValueError("bounded guest observation refused")
                return run.stdout
            with mock.patch.object(probe, "_ssh", side_effect=local):
                observed = probe._guest_operator({"guest_uid": os.getuid()},
                                                  str(target), expected)
                self.assertEqual(observed[1], target.stat().st_ino)
                target.chmod(0o600)
                with self.assertRaisesRegex(ValueError, "bounded guest observation refused"):
                    probe._guest_operator({"guest_uid": os.getuid()},
                                          str(target), expected)

            # Grow the named regular file just after the initial fstat in a
            # test-only copy of the guest observer. The exact-byte reader must
            # stop at the authenticated size and reject the extra EOF byte.
            target.write_bytes(b"a" * (1024 * 1024))
            target.chmod(0o700)
            expected = {"binary_bytes": target.stat().st_size,
                        "binary_sha256": probe.hashlib.sha256(target.read_bytes()).hexdigest()}
            def concurrent_growth(_binding, script, **_kwargs):
                argv = shlex.split(script)
                marker = "left=size;h=hashlib.sha256()"
                self.assertIn(marker, argv[4])
                argv[4] = argv[4].replace(marker,
                    "os.truncate(p,size+1);" + marker)
                run = subprocess.run(argv, capture_output=True, timeout=5)
                self.assertNotEqual(run.returncode, 0)
                raise ValueError("bounded guest observation refused")
            with mock.patch.object(probe, "_ssh", side_effect=concurrent_growth):
                with self.assertRaisesRegex(ValueError, "bounded guest observation refused"):
                    probe._guest_operator({"guest_uid": os.getuid()},
                                          str(target), expected)
            self.assertEqual(target.stat().st_size, expected["binary_bytes"] + 1)

    def test_sealed_guest_exec_keeps_verified_bytes_and_clean_fixed_argv(self):
        if shutil.which("cc") is None:
            self.skipTest("C compiler unavailable for synthetic executable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "operator.c"
            source.write_text(
                '#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n'
                'int main(int n,char**v){'
                'if(n!=2||getenv("LEAK_ME")||strcmp(getenv("HOME"),"/nonexistent"))return 3;'
                'if(!strcmp(v[1],"--build-identity")){puts("' + SOURCE + ':' + TAG + '");return 0;}'
                'if(!strcmp(v[1],"--help")){puts("usage: marty-deploy.py synthetic");return 0;}'
                'return 4;}\n', encoding="ascii")
            original = root / "operator"
            subprocess.run([shutil.which("cc"), "-o", str(original), str(source)],
                           check=True, capture_output=True, timeout=15)
            original.chmod(0o700)
            digest = probe.hashlib.sha256(original.read_bytes()).hexdigest()
            identity = SOURCE + ":" + TAG
            def run(code, path=original, flag="--build-identity", size=None):
                selected_size = path.stat().st_size if size is None else size
                return subprocess.run([sys.executable, "-E", "-I", "-B", "-c", code,
                                       str(path), digest, str(selected_size), str(os.getuid()),
                                       flag, identity], cwd="/", capture_output=True,
                                      env={"HOME": "/", "PATH": "/usr/bin:/bin", "LANG": "C",
                                           "LEAK_ME": "must-not-reach-child"}, timeout=10)
            clean = run(probe.GUEST_SEALED_EXEC)
            self.assertEqual(clean.returncode, 0, clean.stderr)
            self.assertEqual(json.loads(clean.stdout)["flag"], "--build-identity")
            help_result = run(probe.GUEST_SEALED_EXEC, flag="--help")
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            forbidden = run(probe.GUEST_SEALED_EXEC, flag="install")
            self.assertNotEqual(forbidden.returncode, 0)
            self.assertNotIn(b"marty-deploy.py synthetic", forbidden.stdout)

            # Inject a competing path swap at the exact seal/exec boundary in
            # a test-only copy of the constant program. The executed bytes
            # still come from the sealed FD, not the later named path.
            replacement = root / "replacement"
            replacement.write_bytes(b"untrusted replacement")
            replacement.chmod(0o700)
            marker = "    child=subprocess.Popen("
            swapped_code = probe.GUEST_SEALED_EXEC.replace(
                marker, "    os.replace(" + repr(str(replacement)) + ",path)\n" + marker)
            self.assertNotEqual(swapped_code, probe.GUEST_SEALED_EXEC)
            swapped = run(swapped_code)
            self.assertEqual(swapped.returncode, 0, swapped.stderr)
            self.assertEqual(json.loads(swapped.stdout)["operator_sha256"], digest)
            self.assertNotEqual(probe.hashlib.sha256(original.read_bytes()).hexdigest(), digest)

            # Restore the compiled trusted ELF from a separately retained
            # immutable fixture for the in-place mutation case.
            original.unlink()
            subprocess.run([shutil.which("cc"), "-o", str(original), str(source)],
                           check=True, capture_output=True, timeout=15)
            original.chmod(0o700)
            changed_code = probe.GUEST_SEALED_EXEC.replace(
                marker, "    os.truncate(path,0)\n" + marker)
            changed = run(changed_code)
            self.assertEqual(changed.returncode, 0, changed.stderr)
            self.assertEqual(original.stat().st_size, 0)
            oversized = root / "oversized"
            with oversized.open("wb") as stream:
                stream.truncate(67108865)
            oversized.chmod(0o700)
            refused = run(probe.GUEST_SEALED_EXEC, path=oversized,
                          size=67108865)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(refused.stdout, b"")

    def test_controller_accepts_only_fixed_sealed_execution_receipt(self):
        target = probe._guest_dir(PROBE) + "/marty-deploy"
        expected = {"binary_sha256": "a" * 64, "binary_bytes": 42,
                    "source_sha": SOURCE, "release_tag": TAG,
                    "build_run_id": 40392909103, "build_run_attempt": 1}
        result = {"flag": "--help", "operator_sha256": "a" * 64,
                  "operator_device": 10, "operator_inode": 21,
                  "output_sha256": "b" * 64, "output_bytes": 100,
                  "matched": True}
        with mock.patch.object(probe, "_ssh", return_value=probe.release.encode(result)) as ssh:
            accepted = probe._execute_sealed({"guest_uid": 1000}, target,
                                             expected, (10, 21, 1000, 700, 1, 42), "--help")
            self.assertEqual(accepted, result)
            script = ssh.call_args.args[1]
            self.assertIn("/usr/bin/env -i", script)
            self.assertIn("/usr/bin/python3 -E -I -B -c", script)
            self.assertNotIn(target + " --help", script)
            result["operator_inode"] = 22
            ssh.return_value = probe.release.encode(result)
            with self.assertRaisesRegex(ValueError, "sealed execution differs"):
                probe._execute_sealed({"guest_uid": 1000}, target,
                                      expected, (10, 21, 1000, 700, 1, 42), "--help")
        with self.assertRaisesRegex(ValueError, "command unsupported"):
            probe._execute_sealed({"guest_uid": 1000}, target,
                                  expected, (10, 21, 1000, 700, 1, 42), "install")

    def test_durable_intent_precedes_guest_action_and_is_one_shot(self):
        expected = {"binary": Path("/fixture/marty-deploy-linux-amd64"),
                    "binary_sha256": "a" * 64, "binary_bytes": 42,
                    "source_sha": SOURCE, "release_tag": TAG,
                    "build_run_id": 40392909103, "build_run_attempt": 1,
                    "inventory_sha256": "b" * 64,
                    "acquisition_sha256": "c" * 64}
        binding = {"readiness_sha256": "d" * 64, "pid": 1135,
                   "start_ticks": "91460346", "boot_id": "e" * 36,
                   "disk_device": 2128, "disk_inode": 33597607,
                   "engine_id": "engine-705", "guest_uid": 1000,
                   "port": 22024, "key_sha256": "f" * 64,
                   "known_hosts_sha256": "1" * 64,
                   "control_dir": Path("/fixture/control")}
        with tempfile.TemporaryDirectory() as tmp:
            registry = Path(tmp)
            class Lease:
                def __init__(self, _registry):
                    self.parent = os.open(registry, os.O_RDONLY | os.O_DIRECTORY)
                def __enter__(self):
                    return self
                def __exit__(self, *_args):
                    os.close(self.parent)
            def transfer(_binding, _binary, _expected, _probe_id):
                intent = registry / (VM + ".installer-only-probe-intent.json")
                self.assertTrue(intent.is_file())
                self.assertEqual(intent.stat().st_mode & 0o777, 0o600)
                raise ValueError("synthetic transfer refused")
            def write(parent, name, record):
                raw = probe.release.encode(record)
                fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                             0o600, dir_fd=parent)
                try:
                    os.write(fd, raw)
                    os.fsync(fd)
                    os.fsync(parent)
                finally:
                    os.close(fd)
                return raw
            def read(parent, name):
                fd = os.open(name, os.O_RDONLY, dir_fd=parent)
                try:
                    raw = os.read(fd, 65537)
                finally:
                    os.close(fd)
                return raw, probe.release.decode(raw)
            with mock.patch.object(probe.os, "geteuid", return_value=0), \
                 mock.patch.object(probe, "ControllerLease", Lease), \
                 mock.patch.object(probe, "_verified_assets", return_value=expected), \
                 mock.patch.object(probe, "_bound_vm", return_value=binding), \
                 mock.patch.object(probe.dispatch, "private_file",
                                   return_value=("a" * 64, 42)), \
                 mock.patch.object(probe, "_write", side_effect=write), \
                 mock.patch.object(probe, "_read_record", side_effect=read), \
                 mock.patch.object(probe, "_transport", side_effect=transfer) as moved:
                with self.assertRaisesRegex(ValueError, "synthetic transfer refused"):
                    probe.probe(source=Path("/source"), registry=registry,
                                runtime_parent=Path("/runtime"), vm_id=VM,
                                probe_id=PROBE, assets=Path("/assets"),
                                gh=Path("/gh"), cosign=Path("/cosign"), client=None)
                self.assertFalse((registry / (VM + ".installer-only-probe-result.json")).exists())
                with self.assertRaisesRegex(ValueError, "already attempted"):
                    probe.probe(source=Path("/source"), registry=registry,
                                runtime_parent=Path("/runtime"), vm_id=VM,
                                probe_id=PROBE, assets=Path("/assets"),
                                gh=Path("/gh"), cosign=Path("/cosign"), client=None)
                self.assertEqual(moved.call_count, 1)

    def test_source_or_live_refusal_precedes_intent(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = Path(tmp)
            class Lease:
                def __init__(self, _registry):
                    self.parent = os.open(registry, os.O_RDONLY | os.O_DIRECTORY)
                def __enter__(self):
                    return self
                def __exit__(self, *_args):
                    os.close(self.parent)
            with mock.patch.object(probe.os, "geteuid", return_value=0), \
                 mock.patch.object(probe, "ControllerLease", Lease), \
                 mock.patch.object(probe, "_verified_assets",
                                   side_effect=ValueError("published asset refused")), \
                 mock.patch.object(probe, "_transport") as transfer:
                with self.assertRaisesRegex(ValueError, "published asset refused"):
                    probe.probe(source=Path("/source"), registry=registry,
                                runtime_parent=Path("/runtime"), vm_id=VM,
                                probe_id=PROBE, assets=Path("/assets"),
                                gh=Path("/gh"), cosign=Path("/cosign"), client=None)
                transfer.assert_not_called()
                self.assertEqual(list(registry.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
