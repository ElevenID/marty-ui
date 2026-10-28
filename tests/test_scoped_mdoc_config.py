"""Source-only delta controls. No Docker, secret files or operational authority."""

import copy
import json
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scoped_mdoc_config as subject


def fixture():
    org = "00000000-0000-0000-0000-000000000001"

    def row(name):
        return {
            "organization_id": org,
            "issuer_did": "did:web:example.test:" + name,
            "certificate": {
                "issuer_contact_uri": "https://example.test",
                "crl_distribution_uri": "https://example.test/" + name + ".crl",
            },
        }

    before = {
        "name": "elevenid-beta",
        "services": {
            role: {
                "image": "sha256:" + "a" * 64,
                "environment": {"UNRELATED": "fixed"},
                "volumes": [
                    {
                        "type": "bind",
                        "source": "C:/private/native-" + role,
                        "target": "/usr/local/bin/" + role,
                        "read_only": True,
                    }
                ],
                "user": "1000:1000",
                "cap_drop": ["ALL"],
            }
            for role in ["gateway", "signing-keys", "issuance-native"]
        },
    }
    before["services"]["signing-keys"]["environment"][subject.PUBLIC] = json.dumps(
        [row("legacy")]
    )
    bindings = {
        n: {"path": "C:/private/" + n, "sha256": digit * 64, "bytes": 64}
        for n, digit in zip(subject.NAMES, "12")
    }
    additions = [row("new-trusted-iaca"), row("new-rejected-iaca")]
    after = copy.deepcopy(before)
    delta = subject.overlay(before, bindings, additions)
    for role, patch in delta["services"].items():
        after["services"][role]["environment"].update(patch["environment"])
        after["services"][role]["volumes"].extend(patch["volumes"])
    return before, after, bindings, additions


class DeltaControls(unittest.TestCase):
    def test_exact_additions_and_existing_authority_preserved(self):
        before, after, bindings, additions = fixture()
        self.assertEqual(
            subject.validate_delta(before, after, bindings, additions)[
                "newIacaMetadataRows"
            ],
            2,
        )
        old = json.loads(
            before["services"]["signing-keys"]["environment"][subject.PUBLIC]
        )
        actual = json.loads(
            after["services"]["signing-keys"]["environment"][subject.PUBLIC]
        )
        self.assertEqual(actual, old + additions)
        self.assertNotIn(subject.PUBLIC, after["services"]["gateway"]["environment"])

    def test_closed_environment_mount_role_and_project_delta(self):
        def env(a):
            a["services"]["gateway"]["environment"].update(EXTRA="forbidden")

        def direct(a):
            a["services"]["gateway"]["environment"][
                subject.variable(subject.NAMES[0])
            ] = "forbidden"

        def unselected(a):
            a["services"]["issuance-native"]["environment"].update(EXTRA="forbidden")

        def user(a):
            a["services"]["signing-keys"]["user"] = "0"

        def image(a):
            a["services"]["gateway"]["image"] = "different"

        def project(a):
            a["name"] = "different"

        def writable(a):
            a["services"]["gateway"]["volumes"][-1]["read_only"] = False

        def mkdir(a):
            a["services"]["gateway"]["volumes"][-1]["bind"]["create_host_path"] = True

        def source(a):
            a["services"]["gateway"]["volumes"][-1]["source"] = "C:/private/other"

        def existing(a):
            a["services"]["gateway"]["volumes"][0]["source"] = "C:/private/other"

        def duplicate(a):
            a["services"]["gateway"]["volumes"].append(
                copy.deepcopy(a["services"]["gateway"]["volumes"][-1])
            )

        def role(a):
            a["services"]["other"] = {}

        for mutate in (
            env,
            direct,
            unselected,
            user,
            image,
            project,
            writable,
            mkdir,
            source,
            existing,
            duplicate,
            role,
        ):
            with self.subTest(mutation=mutate.__name__):
                before, after, bindings, additions = fixture()
                mutate(after)
                with self.assertRaises(ValueError):
                    subject.validate_delta(before, after, bindings, additions)

    def test_desktop_mount_equivalence_only_for_new_sources(self):
        before, after, bindings, additions = fixture()
        for role in subject.ROLES:
            for mount in after["services"][role]["volumes"][-2:]:
                mount["source"] = subject.daemon_source(mount["source"])
        subject.validate_delta(before, after, bindings, additions)
        after["services"]["gateway"]["volumes"][-1]["source"] = (
            "/mnt/host/c/private/other"
        )
        with self.assertRaises(ValueError):
            subject.validate_delta(before, after, bindings, additions)

    def test_authority_collision_duplicates_and_existing_rewrite_refused(self):
        before, after, bindings, additions = fixture()
        legacy = json.loads(
            before["services"]["signing-keys"]["environment"][subject.PUBLIC]
        )[0]
        with self.assertRaises(ValueError):
            subject.merged_authorities(json.dumps([legacy]), [legacy, additions[0]])
        with self.assertRaises(ValueError):
            subject.merged_authorities(None, [additions[0], additions[0]])
        with self.assertRaises(ValueError):
            subject.authorities('[{"organization_id":"x","organization_id":"y"}]')
        after["services"]["signing-keys"]["environment"][subject.PUBLIC] = json.dumps(
            additions
        )
        with self.assertRaises(ValueError):
            subject.validate_delta(before, after, bindings, additions)

    def test_operator_distinctness_preexisting_sources_and_mounts(self):
        for mutation in (
            "digest",
            "source",
            "existing_direct",
            "existing_file",
            "existing_mount",
        ):
            with self.subTest(mutation=mutation):
                before, after, bindings, additions = fixture()
                if mutation == "digest":
                    bindings[subject.NAMES[1]]["sha256"] = bindings[subject.NAMES[0]][
                        "sha256"
                    ]
                elif mutation == "source":
                    bindings[subject.NAMES[1]]["path"] = bindings[subject.NAMES[0]][
                        "path"
                    ]
                elif mutation == "existing_mount":
                    before["services"]["gateway"]["volumes"].append(
                        {"target": "/run/secrets/" + subject.NAMES[0]}
                    )
                else:
                    before["services"]["gateway"]["environment"][
                        subject.variable(subject.NAMES[0])
                        + ("_FILE" if mutation == "existing_file" else "")
                    ] = "already"
                with self.assertRaises(ValueError):
                    subject.overlay(before, bindings, additions)

    def test_public_metadata_refuses_control_and_uri_authority_ambiguity(self):
        _, _, _, additions = fixture()
        for uri in (
            "https://@example.test/contact",
            "https://example.test/contact?",
            "https://example.test/contact#",
            "https://example.test:99999/contact",
            "https://example.test\\contact",
            "https://%/issuer.crl",
            "https://bad|host/issuer.crl",
            "https://999.999.999.999/issuer.crl",
            "https://xn--a/issuer.crl",
            "https://[fe80::1%25eth0]/issuer.crl",
        ):
            rows = copy.deepcopy(additions)
            rows[0]["certificate"]["issuer_contact_uri"] = uri
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                subject.merged_authorities(None, rows)
        rows = copy.deepcopy(additions)
        rows[0]["issuer_did"] += "\u0085"
        with self.assertRaises(ValueError):
            subject.merged_authorities(None, rows)
        for uri in (
            "https://beta.elevenidllc.com/issuer.crl",
            "http://127.0.0.1/issuer.crl",
            "https://[::1]/issuer.crl",
        ):
            rows = copy.deepcopy(additions)
            rows[0]["certificate"]["crl_distribution_uri"] = uri
            subject.merged_authorities(None, rows)

    def test_runtime_environment_seam_does_not_hide_extra_values(self):
        before, after, bindings, additions = fixture()
        for role in subject.ROLES:
            old = [
                k + "=" + v for k, v in before["services"][role]["environment"].items()
            ]
            new = [
                k + "=" + v for k, v in after["services"][role]["environment"].items()
            ]
            self.assertEqual(
                subject.peel_inspect_environment(old, new, role, additions), old
            )
            for bad in (new + ["EXTRA=forbidden"], new + [new[0]], new[:-1]):
                with self.assertRaises(ValueError):
                    subject.peel_inspect_environment(old, bad, role, additions)

    def test_created_and_readback_seam_preserves_full_strict_checker(self):
        before, after, bindings, additions = fixture()
        old = {
            "Config": {"Env": ["UNRELATED=fixed"], "Image": "same", "User": "1000"},
            "HostConfig": {"Binds": None, "CapDrop": ["ALL"], "Privileged": False},
            "Mounts": [],
            "Image": "sha256:" + "a" * 64,
            "NetworkSettings": {"Networks": {"beta": {"NetworkID": "same"}}},
        }
        actual = copy.deepcopy(old)
        actual["Config"]["Env"] = [
            k + "=" + v for k, v in after["services"]["gateway"]["environment"].items()
        ]
        actual["HostConfig"]["Binds"] = []
        for name in subject.NAMES:
            source = subject.daemon_source(bindings[name]["path"])
            target = "/run/secrets/" + name
            actual["HostConfig"]["Binds"].append(source + ":" + target + ":ro")
            actual["Mounts"].append(
                {
                    "Type": "bind",
                    "Source": source,
                    "Destination": target,
                    "Mode": "ro",
                    "RW": False,
                    "Propagation": "rprivate",
                }
            )
        called = []

        def checker(a, b, role):
            called.append(role)
            self.assertEqual(a, b)

        subject.checked_container(old, actual, "gateway", bindings, additions, checker)
        self.assertEqual(called, ["gateway"])
        self.assertEqual(len(actual["Mounts"]), 2)  # caller document not mutated
        for field in ("privilege", "network", "image", "unknown_config"):
            bad = copy.deepcopy(actual)
            if field == "privilege":
                bad["HostConfig"]["Privileged"] = True
            elif field == "network":
                bad["NetworkSettings"]["Networks"]["beta"]["NetworkID"] = "changed"
            elif field == "image":
                bad["Image"] = "changed"
            else:
                bad["Config"]["Extra"] = True
            with self.subTest(field=field), self.assertRaises(AssertionError):
                subject.checked_container(
                    old, bad, "gateway", bindings, additions, checker
                )
        for field in (
            "writable",
            "host_bind",
            "duplicate",
            "unproved_mount_key",
            "host_mounts",
        ):
            bad = copy.deepcopy(actual)
            if field == "writable":
                bad["Mounts"][0]["RW"] = True
            elif field == "host_bind":
                bad["HostConfig"]["Binds"][0] = (
                    bad["HostConfig"]["Binds"][0][:-2] + "rw"
                )
            elif field == "duplicate":
                bad["Mounts"].append(copy.deepcopy(bad["Mounts"][0]))
            elif field == "host_mounts":
                bad["HostConfig"]["Mounts"] = [
                    {"Type": "bind", "BindOptions": {"NonRecursive": True}}
                ]
            else:
                bad["Mounts"][0]["Unproved"] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                subject.checked_container(
                    old, bad, "gateway", bindings, additions, checker
                )
        with self.assertRaises(ValueError):
            subject.checked_container(old, actual, "gateway", bindings, additions, None)

    def test_explicit_rollback_seam_refuses_retained_operator_authority(self):
        old = {
            "Config": {"Env": ["EXISTING=fixed"]},
            "Mounts": [],
            "HostConfig": {"Binds": None, "Mounts": []},
            "Image": "same",
        }
        checked = []

        def strict(a, b, role):
            checked.append(role)
            self.assertEqual(a, b)

        subject.checked_rollback_container(old, copy.deepcopy(old), "gateway", strict)
        self.assertEqual(checked, ["gateway"])
        old["HostConfig"]["Binds"] = ["C:/private/native:/usr/local/bin/gateway:ro"]
        equivalent = copy.deepcopy(old)
        equivalent["HostConfig"]["Binds"] = [
            "/run/desktop/mnt/host/c/private/native:/usr/local/bin/gateway:ro"
        ]
        subject.checked_rollback_container(old, equivalent, "gateway", strict)
        for field in ("env", "mount", "host_bind", "host_mount", "image"):
            actual = copy.deepcopy(old)
            if field == "env":
                actual["Config"]["Env"].append(
                    subject.variable(subject.NAMES[0]) + "_FILE=/run/secrets/new"
                )
            elif field == "mount":
                actual["Mounts"].append(
                    {"Destination": "/run/secrets/" + subject.NAMES[0]}
                )
            elif field == "host_bind":
                actual["HostConfig"]["Binds"] = ["/secret:/run/secrets/new:ro"]
            elif field == "host_mount":
                actual["HostConfig"]["Mounts"] = [{"Type": "bind"}]
            else:
                actual["Image"] = "different"
            with (
                self.subTest(field=field),
                self.assertRaises((ValueError, AssertionError)),
            ):
                subject.checked_rollback_container(old, actual, "gateway", strict)


if __name__ == "__main__":
    unittest.main()
