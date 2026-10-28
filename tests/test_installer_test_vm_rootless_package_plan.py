"""Synthetic read-only package and local policy plan checks, without a VM."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import pwd
import shlex
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

if sys.platform != "linux":
    raise unittest.SkipTest("Linux controller tests")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_test_vm_rootless_package_plan as subject

VM = "70573b98-a002-468c-a932-f27c1ca20440"
OBS = "59d6d704-7060-4397-ab90-00ba0742e498"


class PackagePlan(unittest.TestCase):
    def test_closed_queries_and_sanitized_parsers(self):
        self.assertEqual(shlex.split(subject._local_command())[:5],
                         ["/usr/bin/python3", "-E", "-I", "-B", "-c"])
        self.assertEqual(shlex.split(subject._local_command())[5],
                         subject.LOCAL_SCRIPT)
        for package in subject.PACKAGES:
            commands = subject._commands(package)
            self.assertEqual(len(commands), 3)
            self.assertTrue(all(command.endswith(package) for command in commands))
            self.assertIn("/usr/bin/dpkg-query -L -- " + package,
                          subject._file_list_command(package))
        for bad in ("docker.io; id", "other", "../uidmap"):
            with self.assertRaises(ValueError):
                subject._commands(bad)
            with self.assertRaises(ValueError):
                subject._file_list_command(bad)
        self.assertEqual(subject._package_status(b"install ok installed\n1.2.3-1\n"),
                         {"status": "installed", "installed_version": "1.2.3-1"})
        policy = (b"uidmap:\n  Installed: (none)\n  Candidate: 1:4.2-1ubuntu1\n"
                  b"  Version table:\n     1:4.2-1ubuntu1 500\n"
                  b"        500 http://example.invalid/ubuntu noble/main amd64 Packages\n"
                  b"        release v=24.04,o=Ubuntu,a=noble,n=noble,l=Ubuntu\n")
        parsed = subject._policy(policy, "uidmap")
        self.assertEqual(parsed["candidate_version"], "1:4.2-1ubuntu1")
        self.assertTrue(parsed["ubuntu_origin_metadata_observed"])
        self.assertNotIn("example.invalid", str(parsed))
        self.assertEqual(subject._policy(policy, "rootlesskit")["status"], "unknown")
        depends = subject._depends(b"rootlesskit\n  Depends: uidmap\n  Depends: libc6\n",
                                   "rootlesskit")
        self.assertEqual(depends["closed_package_dependencies"], ["uidmap"])
        self.assertEqual(depends["other_dependency_lines"], 1)
        self.assertEqual(subject._file_list(b"/usr/bin/rootlesskit\n"),
                         {"status": "file_list_observed",
                          "approved_paths_observed": ["/usr/bin/rootlesskit"]})
        self.assertEqual(subject._file_list(b"/private/secret\n"),
                         {"status": "file_list_observed", "approved_paths_observed": []})
        self.assertEqual(subject._file_list(b"relative/path\n")["status"], "unknown")

    def test_actual_local_script_uses_fixed_files_and_sanitizes_foreign_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = {
                "/etc/passwd": b"installer:x:1000:1001::/home/installer:/bin/bash\nforeign:x:2000:2000::/:/bin/false\n",
                "/etc/group": b"installer:x:1001:\ndocker:x:998:installer\nforeign:x:2000:\n",
                "/etc/subuid": b"installer:100000:65536\nforeign:165536:65536\n",
                "/etc/subgid": b"installer:100000:65536\nforeign:165536:65536\n",
                "/etc/apt/sources.list.d/ubuntu.sources":
                    b"Types: deb\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n",
                "/proc/sys/kernel/apparmor_restrict_unprivileged_userns": b"1\n",
            }
            mapped = {}
            for index, (path, content) in enumerate(source.items()):
                destination = base / str(index)
                destination.write_bytes(content)
                mapped[path] = destination
            actual_open, actual_read, actual_fstat, actual_stat = (
                os.open, os.read, os.fstat, os.stat)
            descriptors = {}
            def owned(item, path=None):
                return SimpleNamespace(**{name: (0 if name == "st_uid" else
                    4096 if name == "st_size" and path.startswith("/proc/sys/") else
                    getattr(item, name)) for name in ("st_dev", "st_ino", "st_uid",
                    "st_gid", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")})
            def opening(path, flags, *args, **kwargs):
                fd = actual_open(mapped.get(path, path), flags, *args, **kwargs)
                descriptors[fd] = (descriptors.get(int(path.rsplit("/", 1)[1]))
                    if path.startswith("/proc/self/fd/") else path)
                return fd
            output = io.StringIO()
            with mock.patch.object(os, "getuid", return_value=1000), \
                 mock.patch.object(pwd, "getpwuid", return_value=SimpleNamespace(pw_name="installer")), \
                 mock.patch.object(os, "open", side_effect=opening), \
                 mock.patch.object(os, "read", side_effect=lambda fd, count:
                                   actual_read(fd, min(count, 3))), \
                 mock.patch.object(os, "fstat", side_effect=lambda fd:
                                   owned(actual_fstat(fd), descriptors.get(fd))), \
                 mock.patch.object(os, "stat", side_effect=lambda path, **kw:
                                   owned(actual_stat(mapped.get(path, path), **kw), path)), \
                 contextlib.redirect_stdout(output):
                exec(subject.LOCAL_SCRIPT, {"__name__": "__main__"})
            value = json.loads(output.getvalue())
            self.assertEqual(value["account"]["name_in_local_files"], False)
            self.assertEqual(value["account"]["local_uid_gid_candidate"], 2001)
            self.assertEqual(value["subuid"]["local_candidate_start"], 231072)
            self.assertEqual(value["subgid"]["local_candidate_start"], 231072)
            self.assertEqual(value["apparmor_unprivileged_userns_restrict"], 1)
            self.assertTrue(value["ubuntu_signed_by_declaration_observed"])
            self.assertNotIn("foreign", output.getvalue())
            self.assertEqual(subject._local_policy(output.getvalue().encode()), value)

    def test_same_vm_required_and_private_result_is_one_shot(self):
        with tempfile.TemporaryDirectory() as temporary:
            registry = Path(temporary)
            binding = {"readiness_sha256": "a" * 64, "pid": 1135,
                       "start_ticks": "91460346", "engine_id": "engine-705"}
            local = {"schema": subject.GUEST_SCHEMA,
                     "account": {"status": "local_files_observed",
                                 "name_in_local_files": False,
                                 "local_uid_gid_candidate": 2001},
                     "subuid": {"status": "local_file_candidate",
                                "local_candidate_start": 231072,
                                "local_ranges_checked": 2},
                     "subgid": {"status": "local_file_candidate",
                                "local_candidate_start": 231072,
                                "local_ranges_checked": 2},
                     "apparmor_unprivileged_userns_restrict": 1,
                     "ubuntu_signed_by_declaration_observed": True,
                     "external_nss_checked": False,
                     "keyring_admitted": False}
            class Lease:
                def __init__(self, _registry):
                    self.parent = os.open(registry, os.O_RDONLY | os.O_DIRECTORY)
                def __enter__(self):return self
                def __exit__(self, *_):os.close(self.parent)
            def write(parent, name, value):
                fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600,
                             dir_fd=parent)
                try:
                    os.write(fd, subject.release.encode(value))
                    os.fsync(fd);os.fsync(parent)
                finally:os.close(fd)
            kwargs = dict(source=Path("/source"), registry=registry,
                          runtime_parent=Path("/runtime"), vm_id=VM,
                          observation_id=OBS)
            with mock.patch.object(subject.os, "geteuid", return_value=0), \
                 mock.patch.object(subject, "ControllerLease", Lease), \
                 mock.patch.object(subject.probe, "_bound_vm", return_value=binding) as bound, \
                 mock.patch.object(subject, "_read_query", return_value=None) as queries, \
                 mock.patch.object(subject.probe, "_ssh",
                                   return_value=subject.release.encode(local)), \
                 mock.patch.object(subject, "_write", side_effect=write):
                result = subject.observe(**kwargs)
                self.assertEqual(bound.call_count, 2)
                self.assertEqual(queries.call_count, len(subject.PACKAGES) * 3)
                self.assertFalse(result["package_actions_authorized"])
                self.assertFalse(result["rootless_ready"])
                self.assertFalse(result["plan_complete"])
                self.assertEqual(result["proposed_supplementary_groups"], [])
                self.assertFalse(result["proposed_sudo_grants"])
                self.assertFalse(result["proposed_docker_group_membership"])
                with self.assertRaisesRegex(ValueError, "already observed"):
                    subject.observe(**kwargs)
            (registry / (VM + subject.RESULT_SUFFIX)).unlink()
            with mock.patch.object(subject.os, "geteuid", return_value=0), \
                 mock.patch.object(subject, "ControllerLease", Lease), \
                 mock.patch.object(subject.probe, "_bound_vm",
                                   side_effect=[binding, dict(binding, engine_id="changed")]), \
                 mock.patch.object(subject, "_read_query", return_value=None), \
                 mock.patch.object(subject.probe, "_ssh",
                                   return_value=subject.release.encode(local)), \
                 mock.patch.object(subject, "_write", side_effect=write) as writing:
                with self.assertRaisesRegex(ValueError, "live binding changed"):
                    subject.observe(**kwargs)
                writing.assert_not_called()


if __name__ == "__main__":
    unittest.main()
