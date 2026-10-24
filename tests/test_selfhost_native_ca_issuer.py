"""Resumable CA staging stays scoped, internal and exclusive over real HTTPS."""

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import provision_selfhost_ca_rotation_identity as rotation  # noqa: E402
from tests.test_selfhost_native_approle import approle_server as approle_server, TOKEN  # noqa: E402
from tests.test_selfhost_native_certificates import key, certificate, pem  # noqa: E402


@pytest.mark.parametrize(
    "kind,version",
    [(kind, version) for kind in ("workload", "keycloak") for version in range(2, 9)],
)
@pytest.mark.parametrize("resume", [False, True])
def test_native_ca_create_or_resume_all_reviewed_mounts(
    approle_server, kind, version, resume
):
    state = approle_server
    bao, identity = state.prepare("ca-rotation")
    output = identity.parent / "ca-output"
    output.mkdir(mode=0o700)
    signer = key()
    cert = pem(
        certificate(
            f"Marty self-host {kind} CA v{version}",
            signer.public_key(),
            signer=signer,
            ca=True,
            after=365 * 86400,
        )
    ).decode()
    mount = f"{kind}-pki-v{version}"
    state.created = False

    def hook(method, path, body, token):
        if path == "sys/mounts":
            assert token == TOKEN
            return 200, {"data": {mount + "/": {"type": "pki"}} if resume else {}}
        if path == "sys/mounts/" + mount:
            if method == "POST":
                assert not resume and body == {
                    "type": "pki",
                    "config": {"max_lease_ttl": "8760h"},
                }
                return 204, {}
            return 200, {
                "data": {"type": "pki", "config": {"max_lease_ttl": 365 * 86400}}
            }
        if path == mount + "/cert/ca":
            return (
                (200, {"data": {"certificate": cert}})
                if resume or state.created
                else (404, {})
            )
        if path == mount + "/root/generate/internal":
            assert not resume and not state.created
            assert body == {
                "common_name": f"Marty self-host {kind} CA v{version}",
                "ttl": "8760h",
                "key_type": "ec",
                "key_bits": 256,
            }
            state.created = True
            return 200, {"data": {"certificate": cert}}
        return None

    state.hook = hook
    assert rotation.stage_issuer(bao, identity, output, kind, version) == mount
    destination = output / f"{kind}-ca-v{version}.crt"
    assert destination.read_bytes() == cert.encode()
    assert destination.stat().st_mode & 0o777 == 0o600
    assert len(list(output.iterdir())) == 1
    assert state.created is not resume
    seen = len(state.seen)
    with pytest.raises(ValueError):
        rotation.stage_issuer(bao, identity, output, kind, version)
    assert len(state.seen) == seen  # preflight refusal before login/mutation


@pytest.mark.parametrize(
    "fault",
    [
        "mount-kind",
        "mount-ttl",
        "read-403",
        "read-500",
        "private-field",
        "private-pem",
        "wrong-cn",
        "short-ca",
        "live-drift",
        "generate-lost",
        "mount-lost",
        "malformed-existing",
        "output-race",
    ],
)
def test_ca_faults_report_recovery_without_publishing(approle_server, fault):
    state = approle_server
    bao, identity = state.prepare("ca-rotation")
    output = identity.parent / "ca-output"
    output.mkdir(mode=0o700)
    signer = key()
    cert = pem(
        certificate(
            "wrong" if fault == "wrong-cn" else "Marty self-host workload CA v2",
            signer.public_key(),
            signer=signer,
            ca=True,
            after=10 * 86400 if fault == "short-ca" else 365 * 86400,
        )
    ).decode()
    created = False

    def hook(method, path, body, token):
        nonlocal created
        if path == "sys/mounts":
            return 200, {"data": {}}
        if path == "sys/mounts/workload-pki-v2":
            if method == "POST":
                return (0, {}) if fault == "mount-lost" else (204, {})
            return 200, {
                "data": {
                    "type": "kv" if fault == "mount-kind" else "pki",
                    "config": {
                        "max_lease_ttl": 1 if fault == "mount-ttl" else 365 * 86400
                    },
                }
            }
        if path == "workload-pki-v2/cert/ca":
            if not created:
                if fault == "malformed-existing":
                    return 200, {"data": {"certificate": True}}
                return (
                    403 if fault == "read-403" else 500 if fault == "read-500" else 400
                ), {}
            if fault == "output-race":
                (output / "workload-ca-v2.crt").write_bytes(b"other-attempt")
            return 200, {
                "data": {"certificate": cert + "\n" if fault == "live-drift" else cert}
            }
        if path == "workload-pki-v2/root/generate/internal":
            assert not created
            created = True
            if fault == "generate-lost":
                return 0, {}
            data = {
                "certificate": "-----BEGIN PRIVATE KEY-----\nforbidden"
                if fault == "private-pem"
                else cert
            }
            if fault == "private-field":
                data["private_key"] = "forbidden"
            return 200, {"data": data}
        return None

    state.hook = hook
    with pytest.raises(
        rotation.OperatorCleanupError,
        match="^CA issuer staging requires operator recovery$",
    ):
        rotation.stage_issuer(bao, identity, output, "workload", 2)
    if fault == "output-race":
        assert (output / "workload-ca-v2.crt").read_bytes() == b"other-attempt"
    else:
        assert not list(output.iterdir())
    if fault in (
        "read-403",
        "read-500",
        "mount-kind",
        "mount-ttl",
        "mount-lost",
        "malformed-existing",
    ):
        assert not created
    if fault == "generate-lost":
        # A persisted issuer survives a dropped response. A deliberate retry
        # must read and validate it, never regenerate it or widen authority.
        def resumed(method, path, body, token):
            if path == "sys/mounts":
                return 200, {"data": {"workload-pki-v2/": {"type": "pki"}}}
            return hook(method, path, body, token)

        state.hook = resumed
        assert (
            rotation.stage_issuer(bao, identity, output, "workload", 2)
            == "workload-pki-v2"
        )
        assert (
            sum(
                path == "workload-pki-v2/root/generate/internal"
                for _, path, *_ in state.seen
            )
            == 1
        )


@pytest.mark.parametrize(
    "fault", ["kind", "version", "float", "bool", "mode", "nonempty", "symlink"]
)
def test_ca_preflight_refuses_before_login_or_remote_mutation(approle_server, fault):
    state = approle_server
    bao, identity = state.prepare("ca-rotation")
    output = identity.parent / "ca-output"
    output.mkdir(mode=0o700)
    if fault == "mode":
        output.chmod(0o755)
    if fault == "nonempty":
        (output / "operator-note").write_text("keep")
    if fault == "symlink":
        output.rmdir()
        output.symlink_to(identity, target_is_directory=True)
    version = {"version": 9, "float": 2.0, "bool": True}.get(fault, 2)
    with pytest.raises(ValueError):
        rotation.stage_issuer(
            bao, identity, output, "foreign" if fault == "kind" else "workload", version
        )
    assert not state.seen
