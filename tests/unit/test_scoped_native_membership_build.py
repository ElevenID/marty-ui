"""Closed D05 lifecycle controls; no daemon or compiler is invoked."""
import copy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import scoped_native_build as build


CID = "a" * 64
OWN = "b" * 64


def terminal():
    return {"Id": CID, "Name": "/retained", "Created": "creation", "Image": "sha256:" + "c" * 64,
            "State": {"Status": "exited", "Pid": 0, "Running": False, "Restarting": False,
                      "Paused": False, "OOMKilled": False, "StartedAt": "start", "FinishedAt": "end", "ExitCode": 0},
            "HostConfig": {"RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}},
            "Config": {"Labels": {}, "Cmd": ["cargo", "metadata"]},
            "Mounts": [{"Type": "volume", "Name": "ui-canvas-cargo", "Source": "/opaque/cache", "Destination": "/cargo", "RW": True},
                       {"Type": "bind", "Source": "/source", "Destination": "/source", "RW": False}]}


class Helper:
    def __init__(self, row=None, target=(), changing=False):
        self.row = row or terminal()
        self.target = target
        self.changing = changing
        self.cache_reads = 0

    def run(self, *args):
        if "ps" in args:
            if args[-1] == "volume=ui-canvas-cargo":
                self.cache_reads += 1
                value = "" if self.changing and self.cache_reads > 1 else CID
            else:
                value = "\n".join(self.target)
        else:
            value = json.dumps([self.row])
        return SimpleNamespace(stdout=value)


class MembershipBuildTests(unittest.TestCase):
    def test_current_ten_role_scope_keeps_original_six_and_closes_login_chain(self):
        old = build.build_scope(build.D05_MEMBERSHIP_PROFILE)
        current = build.build_scope(build.D05_MEMBERSHIP_LATEST_PROFILE)
        self.assertEqual(current['uiRevision'], 'b7c7055830722d10512ccac042b1e0abe0e1ecec')
        self.assertEqual(current['coreRevision'], old['coreRevision'])
        self.assertEqual(current['volumes'], old['volumes'])
        self.assertEqual(current['roles'], {**old['roles'], 'auth': 'marty-auth', 'flow': 'marty-flow',
                         'issuance-native': 'marty-issuance-service', 'organization': 'marty-organization'})
        recipe = build.render_recipe(build.D05_MEMBERSHIP_LATEST_PROFILE)
        self.assertIn('--build-profile d05-membership-current-native-ten-role', recipe)
        self.assertIn('assert len(services)==10', recipe)
        self.assertEqual(set(current['packages']), set(current['roles'].values()))
        self.assertEqual(build.cargo_arguments(build.D05_MEMBERSHIP_LATEST_PROFILE).count('--bin'), 10)

    def test_profile_capacity_bounds_current_and_preserves_historical(self):
        for profile, windows, current, parent in (
                (build.D05_MEMBERSHIP_PROFILE, 1024 ** 3, 4362076160, 5435817984),
                (build.D05_MEMBERSHIP_LATEST_PROFILE, 128 * 1024 ** 2, 3422552064, 3422552064)):
            self.assertEqual(build.membership_windows_memory_bytes(profile), windows)
            for before_parent, threshold in ((False, current), (True, parent)):
                self.assertEqual(build.membership_required_free_bytes(profile, before_parent=before_parent), threshold)
                for free, accepted in ((threshold, True), (threshold - 1024, False)):
                    helper = SimpleNamespace(run=lambda *args: SimpleNamespace(stdout=str(free // 1024)))
                    with self.subTest(profile=profile, before_parent=before_parent, free=free), \
                         patch.object(build.shutil, 'disk_usage', return_value=SimpleNamespace(free=8 * 1024 ** 3)):
                        if accepted:
                            build.membership_capacity(helper, Path('.'), profile, before_parent=before_parent)
                        else:
                            with self.assertRaisesRegex(ValueError, f'freeBytes={free} requiredBytes={threshold}'):
                                build.membership_capacity(helper, Path('.'), profile, before_parent=before_parent)
        helper = SimpleNamespace(run=unittest.mock.Mock())
        with self.assertRaisesRegex(ValueError, 'D05_BUILD_PROFILE_REQUIRED'):
            build.membership_capacity(helper, Path('.'), 'unreviewed-profile')
        helper.run.assert_not_called()

    def test_r5_terminal_mount_order_is_not_identity(self):
        row = terminal()
        expected = build.membership_terminal_cache_projection(row)
        row["Mounts"].reverse()
        self.assertEqual(expected, build.membership_terminal_cache_projection(row))

    def test_live_unknown_and_restart_consumers_refused(self):
        for path, value in ((('State', 'Status'), 'running'), (('State', 'Pid'), True),
                            (('State', 'Running'), True), (('State', 'Paused'), True),
                            (('State', 'Restarting'), True), (('HostConfig', 'RestartPolicy'),
                             {"Name": "always", "MaximumRetryCount": 0})):
            with self.subTest(path=path):
                row = terminal()
                row[path[0]][path[1]] = value
                with self.assertRaises(ValueError):
                    build.membership_terminal_cache_projection(row)

    def test_duplicate_mount_destination_refused(self):
        row = terminal()
        row['Mounts'].append(copy.deepcopy(row['Mounts'][0]))
        with self.assertRaises(ValueError):
            build.membership_terminal_cache_projection(row)

    def test_stable_baseline_and_post_retirement_zero_target(self):
        baseline = build.membership_consumers(Helper(), {})
        self.assertEqual(baseline, build.membership_consumers(Helper(), {}, baseline))
        with self.assertRaises(ValueError):
            build.membership_consumers(Helper(target=[OWN]), {}, baseline)
        with self.assertRaises(ValueError):
            build.membership_consumers(Helper(changing=True), {}, baseline)

    def test_generation_source_rw_and_destination_changes_refused(self):
        baseline = build.membership_consumers(Helper(), {})
        for field, value in (("Source", "/different"), ("RW", False), ("Destination", "/different")):
            with self.subTest(field=field):
                row = terminal()
                row['Mounts'][0][field] = value
                with self.assertRaises(ValueError):
                    build.membership_consumers(Helper(row), {}, baseline)
        row = terminal()
        row['State']['StartedAt'] = 'new generation'
        with self.assertRaises(ValueError):
            build.membership_consumers(Helper(row), {}, baseline)

    def test_exact_owned_compiler_must_be_verified_before_exception(self):
        with patch.object(build, 'membership_created_identity', side_effect=ValueError('foreign')) as verify:
            with self.assertRaises(ValueError):
                build.membership_consumers(Helper(), {}, {}, OWN, 'created')
            verify.assert_called_once_with(unittest.mock.ANY, {}, OWN, 'created')

    def test_compiler_limits_and_target_mount_mutations_refused(self):
        plan = {"containerName": "owned", "runId": "run", "builderImage": "image",
                "sources": {"ui": {"directory": "/ui"}, "core": {"directory": "/core"}},
                "outputDirectory": "/out", "recipe": {"path": "/recipe"}, "lockGuard": {"path": "/guard"}}
        scope = build.build_scope(build.D05_MEMBERSHIP_PROFILE)
        row = {"Id": OWN, "Name": "/owned", "Image": "image", "State": {"Status": "created"},
               "Config": {"Entrypoint": ["/bin/sh"], "Cmd": ["/build.sh"],
                          "Labels": {"inherited": "yes", "elevenid.owner": scope['owner'], "elevenid.run": "run"}},
               "HostConfig": {"NetworkMode": "none", "Memory": 2 * 1024 ** 3, "MemorySwap": 4 * 1024 ** 3,
                              "PidsLimit": 128, "NanoCpus": 10 ** 9, "Privileged": False,
                              "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"]},
               "Mounts": [{"Type": "bind", "Source": source, "Destination": dest, "RW": dest == '/out'}
                          for dest, source in (("/src/ui", "/ui"), ("/build/core", "/core"), ("/out", "/out"),
                                               ("/build.sh", "/recipe"), ("/build/lock_guard.py", "/guard"))]
                         + [{"Type": "volume", "Name": volume, "Destination": dest, "RW": True}
                            for volume, dest in zip(scope['volumes'], ('/cargo', '/target'))]}
        def verify(candidate):
            helper = SimpleNamespace(run=lambda *args: SimpleNamespace(stdout=json.dumps(
                [{"Config": {"Labels": {"inherited": "yes"}}}] if 'image' in args else [candidate])))
            return build.membership_created_identity(helper, plan, OWN)
        with patch.object(build, 'daemon_source', side_effect=lambda value: value):
            verify(row)
            for field, value in (("Memory", 1024 ** 3), ("MemorySwap", 8 * 1024 ** 3),
                                 ("PidsLimit", 129), ("NetworkMode", "bridge")):
                with self.subTest(field=field):
                    changed = copy.deepcopy(row)
                    changed['HostConfig'][field] = value
                    with self.assertRaises(ValueError):
                        verify(changed)
            changed = copy.deepcopy(row)
            changed['Mounts'][-1]['Name'] = 'foreign-target'
            with self.assertRaises(ValueError):
                verify(changed)


if __name__ == '__main__':
    unittest.main()
