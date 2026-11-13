"""Offline executable-bind spelling controls; never runtime qualification."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scoped_passport_maintenance as maintenance
from scoped_native_runtime import daemon_source

class ObservedExecutableMountTests(unittest.TestCase):
    def fixture(self):
        source = "C:/Users/maree/.codex/private/demo-functional-continuation-20261108/d05-current-native-b7-source-r1/native-compact-47e-r1/output/marty-auth"
        bound = {"role":"auth", "containerId":"a"*64, "imageId":"sha256:"+"b"*64,
                 "source":"47e", "sha256":"c"*64, "binaryMounts":[{"type":"bind", "source":daemon_source(source), "destination":"/usr/local/bin/marty-auth", "writable":False}]}
        actual = {"Id":bound["containerId"], "Image":bound["imageId"], "Mounts":[{"Type":"bind", "Source":source.replace("/", chr(92)), "Destination":"/usr/local/bin/marty-auth", "RW":False}],
                  "State":{"StartedAt":"0001-01-01T00:00:00Z", "Running":False,"Paused":False,"Pid":0,"Status":"created","ExitCode":0,"OOMKilled":False}}
        return bound, actual
    def test_windows_and_daemon_spellings_preserve_bound_source_and_elf(self):
        bound,actual=self.fixture()
        for value in (actual["Mounts"][0]["Source"], bound["binaryMounts"][0]["source"]):
            actual["Mounts"][0]["Source"]=value
            result=maintenance.observed_role_state(bound,actual)
            self.assertEqual(result["binaryMounts"],bound["binaryMounts"])
            self.assertEqual(result["sha256"],bound["sha256"])
            self.assertEqual(result["source"],bound["source"])
            self.assertEqual(result["state"],"created")
    def test_wrong_source_type_rw_destination_or_duplicate_refused(self):
        for key,value in (("Source","C:/different/marty-auth"),("Type","volume"),("RW",True),("Destination","/usr/local/bin/other")):
            with self.subTest(key=key):
                bound,actual=self.fixture();actual["Mounts"][0][key]=value
                with self.assertRaisesRegex(ValueError,"OBSERVED_EXECUTABLE_MOUNT_CHANGED"):
                    maintenance.observed_role_state(bound,actual)
        bound,actual=self.fixture();actual["Mounts"].append(copy.deepcopy(actual["Mounts"][0]))
        with self.assertRaisesRegex(ValueError,"OBSERVED_EXECUTABLE_MOUNT_CHANGED"):
            maintenance.observed_role_state(bound,actual)
    def test_unsupported_alias_traversal_and_control_refused(self):
        for source in ("/host_mnt/c/Users/marty-auth","/mnt/host/c/Users/marty-auth","C:/Users/../marty-auth","C:/Users/marty-auth"+chr(10)):
            with self.subTest(source=source):
                bound,actual=self.fixture();actual["Mounts"][0]["Source"]=source
                with self.assertRaises(ValueError):maintenance.observed_role_state(bound,actual)

if __name__ == "__main__":unittest.main()
