"""Focused source-only successor controls; no Docker or API execution."""
from copy import deepcopy
import importlib
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
adapter = importlib.import_module("scoped_signing_successor")
shared = importlib.import_module("scoped_native_runtime")


class SuccessorControls(unittest.TestCase):
    def test_actual_candidate_bytes_are_rechecked_not_just_receipt_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "marty-signing-keys"
            candidate.write_bytes(b"synthetic-elf")
            reference = shared.ref(candidate)
            self.assertEqual(adapter.verify_candidate_output(reference), candidate)
            candidate.write_bytes(b"foreign-bytes")
            with self.assertRaisesRegex(ValueError, "BOUND_FILE_CHANGED"):
                adapter.verify_candidate_output(reference)

    def test_live_render_has_original_project_directory_without_changing_freeze_argv(self):
        arguments = ["docker", "compose", "--project-name", "elevenid-beta", "-f", "frozen/base.yml"]
        original = arguments.copy()
        rendered = adapter.live_compose_arguments(arguments, "C:/original/project")
        self.assertEqual(rendered[4:6], ["--project-directory", "C:/original/project"])
        self.assertEqual(arguments, original)
        self.assertNotIn("--project-directory", arguments)

    def test_effective_env_inherits_image_and_applies_overrides_and_removals(self):
        self.assertEqual(adapter.effective_environment(["PATH=/image/bin", "A=old", "REMOVE=yes"],
                         {"A": "new", "REMOVE": None}), {"PATH": "/image/bin", "A": "new"})
        self.assertNotEqual(adapter.environment(["PATH=/image/bin", "A=new", "FOREIGN=extra"]),
                            adapter.effective_environment(["PATH=/image/bin"], {"A": "new"}))

    def test_environment_duplicates_refused_even_if_same_value(self):
        with self.assertRaisesRegex(ValueError, "DUPLICATE_ENVIRONMENT_KEY"):
            adapter.environment(["A=one", "A=one"])

    def fixture(self):
        endpoint = {"NetworkID": "network", "EndpointID": "endpoint", "IPAddress": "172.18.0.2",
                    "Gateway": "172.18.0.1", "IPPrefixLen": 16, "Aliases": ["signing-keys"],
                    "IPAMConfig": None, "Links": None, "DriverOpts": None, "GwPriority": 0,
                    "DNSNames": ["signing-keys", "a" * 12]}
        old = {"Id": "a" * 64, "Config": {"Env": ["A=1"], "Labels": {}}, "HostConfig": {
            "Dns": None, "DnsOptions": None, "DnsSearch": None, "OomKillDisable": False},
            "Mounts": [{"Type": "bind", "Source": "C:/owned/old", "Destination": "/candidate"}],
            "NetworkSettings": {"Networks": {"beta": endpoint}}}
        actual = deepcopy(old)
        actual["Id"] = "b" * 64
        actual["Config"]["Labels"] = {"com.docker.compose.project.environment_file": "frozen.env",
                                         "com.docker.compose.depends_on": ""}
        new_endpoint = actual["NetworkSettings"]["Networks"]["beta"]
        new_endpoint.update(NetworkID="", EndpointID="", IPAddress="", Gateway="", IPPrefixLen=0,
                            DNSNames=["signing-keys", "b" * 12])
        calls = []
        core = SimpleNamespace(AUTO_LABELS={"original"}, _successor_original_created=lambda *args: calls.append(args))
        def verify():
            adapter.normalized_created(old, actual, "signing-keys", "C:/owned/new", "hash", ["file"], "5.4.0",
                core=core, adapter=shared, network_read=lambda name: [{"Id": "network"}],
                command=["docker", "compose", "--env-file", "frozen.env", "up", "--no-deps"])
        return old, actual, core, calls, verify

    def test_only_proven_unattached_endpoint_defaults_are_normalized(self):
        old, actual, core, calls, verify = self.fixture()
        verify()
        self.assertEqual(len(calls), 1)
        self.assertEqual(core.AUTO_LABELS, {"original"})
        self.assertEqual(calls[0][1]["NetworkSettings"]["Networks"]["beta"]["NetworkID"], "network")
        self.assertEqual(old["HostConfig"]["Dns"], None)
        self.assertEqual(actual["NetworkSettings"]["Networks"]["beta"]["NetworkID"], "")

    def test_static_endpoint_options_cannot_drift(self):
        for field, value in [("IPAMConfig", {"IPv4Address": "192.0.2.8"}), ("Links", ["foreign"]),
                             ("DriverOpts", {"foreign": "true"}), ("GwPriority", 1), ("Aliases", ["foreign"])]:
            with self.subTest(field=field):
                _, actual, _, _, verify = self.fixture()
                actual["NetworkSettings"]["Networks"]["beta"][field] = value
                with self.assertRaisesRegex(ValueError, "NETWORK_STATIC_OPTIONS_CHANGED"):
                    verify()

    def test_new_nonempty_runtime_endpoint_or_foreign_dns_is_refused(self):
        for field, value in [("IPAddress", "192.0.2.8"), ("DNSNames", ["foreign", "b" * 12])]:
            with self.subTest(field=field):
                _, actual, _, _, verify = self.fixture()
                actual["NetworkSettings"]["Networks"]["beta"][field] = value
                with self.assertRaises(ValueError):
                    verify()


if __name__ == "__main__":
    unittest.main()
