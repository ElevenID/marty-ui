"""Synthetic verifier tests exercise binding/refusal, not cryptographic acceptance."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_release as release
import prepare_kubernetes_helm_values as helm


pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux installer file contract")
PREFIX = "ghcr.io/elevenid/marty-ui-oss/"
SOURCE = "a" * 40
CHART_SOURCE = "b" * 40


def reference(role, digit):
    return PREFIX + role + "@sha256:" + digit * 64


def write(path, data, mode=0o600):
    path.write_bytes(data)
    path.chmod(mode)


@pytest.fixture
def inputs(tmp_path, monkeypatch, request):
    for directory in (tmp_path, tmp_path / "assets", tmp_path / "tools", tmp_path / "output"):
        directory.mkdir(exist_ok=True)
        directory.chmod(0o700)
    assets = tmp_path / "assets"
    tag = getattr(request, "param", "v1.2.3")
    service_images = {name: reference("services", "2") for name in (
        "gateway", "auth", "issuance", "issuance-native", "issuance-migrations", "signing-keys")}
    service_images.update({
        "ui": reference("ui-selfhost", "1"),
        "db-migrate": reference("migrations", "3"),
        "kms-initialize": reference("migrations", "3"),
        "keycloak": reference("keycloak", "4"),
        "keycloak-configurator": reference("keycloak", "4"),
        "postgres": "docker.io/library/postgres@sha256:" + "6" * 64,
        "redis": "docker.io/library/redis@sha256:" + "7" * 64,
    })
    for name in release.ARTIFACTS:
        write(assets / name, b"unexecuted synthetic installer payload " + name.encode())
    lock = dict(schema="marty.selfhost-image-lock/v1", release="marty-ui@" + tag[1:],
                services=service_images, openbao_didcomm_image=reference("openbao-didcomm", "5"))
    write(assets / "prepared-selfhost-images.json", release.encode(lock))
    identity = dict(source_sha=SOURCE, release_tag=tag, build_run_id=42, build_run_attempt=2)
    inventory = release.inventory(assets, expected_services=set(service_images), **identity)
    write(assets / "installer-inventory.json", release.encode(inventory))
    for name in helm.SUBJECTS:
        for suffix in (".provenance.jsonl", ".sigstore.json"):
            write(assets / (name + suffix), b"synthetic proof " + name.encode())
    pins = {}
    for name in ("gh", "cosign"):
        raw = b"synthetic verifier " + name.encode()
        write(tmp_path / "tools" / name, raw, 0o700)
        pins[name] = (release.digest(raw), len(raw))
    # Production always uses the existing installer pins. Synthetic binaries
    # and subprocess results are replaced only inside this test process.
    monkeypatch.setattr(helm, "TOOLS", pins)
    workflow = ".github/workflows/nightly-release.yml" if "nightly" in tag else ".github/workflows/cd.yml"
    certificate = dict(
        issuer=helm.provenance.ISSUER, runnerEnvironment="github-hosted",
        sourceRepositoryURI="https://github.com/ElevenID/marty-ui",
        sourceRepositoryIdentifier="1140864197", sourceRepositoryDigest=SOURCE,
        sourceRepositoryRef="refs/heads/main",
        runInvocationURI="https://github.com/ElevenID/marty-ui/actions/runs/42/attempts/2",
        buildSignerURI=f"https://github.com/ElevenID/marty-ui/{workflow}@refs/heads/main")
    calls = []

    def runner(argv):
        calls.append(argv)
        if argv[1] == "attestation":
            return json.dumps([dict(attestation={}, verificationResult=dict(signature=dict(certificate=certificate)))])
        return "verified synthetic signature"

    options = dict(assets=assets, runtime_source_sha=SOURCE, chart_source_sha=CHART_SOURCE,
                   release_tag=tag, build_run_id=42, build_run_attempt=2,
                   gh=tmp_path / "tools/gh", cosign=tmp_path / "tools/cosign",
                   output=tmp_path / "output/marty-images.json",
                   openbao_output=tmp_path / "output/openbao-image.json", runner=runner)
    return options, calls, certificate


def assert_no_outputs(options):
    assert not options["output"].exists()
    assert not options["openbao_output"].exists()


def change_lock(options, change):
    """Mutate consistent synthetic producer records to reach role checks."""
    assets = options["assets"]
    lock_path = assets / "prepared-selfhost-images.json"
    lock = release.decode(lock_path.read_bytes())
    change(lock)
    raw = release.encode(lock)
    write(lock_path, raw)
    inventory_path = assets / "installer-inventory.json"
    inventory = release.decode(inventory_path.read_bytes())
    inventory["images"] = {**lock["services"], "openbao_didcomm_image": lock["openbao_didcomm_image"]}
    for artifact in inventory["artifacts"]:
        if artifact["name"] == lock_path.name:
            artifact.update(sha256=release.digest(raw), size=len(raw))
    write(inventory_path, release.encode(inventory))


@pytest.mark.parametrize("inputs", ["v1.2.3", "v1.2.3-nightly.20261105.42"], indirect=True)
def test_authenticates_complete_installer_before_emitting_exact_chart_images(inputs):
    options, calls, _ = inputs
    values, openbao = helm.prepare(**options)
    assert len(calls) == 10
    assert {Path(call[3]).name for call in calls[::2]} == set(helm.SUBJECTS)
    assert {Path(call[2]).name for call in calls[1::2]} == set(helm.SUBJECTS)
    workflow = "nightly-release.yml" if "nightly" in options["release_tag"] else "cd.yml"
    for call in calls[::2]:
        assert call[0] == str(options["gh"])
        assert call[call.index("--source-digest") + 1] == SOURCE
        assert call[call.index("--source-ref") + 1] == "refs/heads/main"
        assert call[call.index("--signer-workflow") + 1].endswith(workflow)
        assert "--deny-self-hosted-runners" in call
    for call in calls[1::2]:
        assert call[0] == str(options["cosign"])
        assert call[1] == "verify-blob"
        assert call[call.index("--certificate-identity") + 1].endswith(workflow + "@refs/heads/main")
    assert values["images"] == {
        "ui": reference("ui-selfhost", "1"), "services": reference("services", "2"),
        "migrations": reference("migrations", "3"), "keycloak": reference("keycloak", "4"),
        "openbao_didcomm": reference("openbao-didcomm", "5"),
    }
    assert values["postgres"] == {"image": "docker.io/library/postgres@sha256:" + "6" * 64}
    assert values["redis"] == {"image": "docker.io/library/redis@sha256:" + "7" * 64}
    identity = values["release"]
    assert identity["runtimeSourceSha"] == SOURCE
    assert identity["chartSourceSha"] == CHART_SOURCE
    assert identity["tag"] == options["release_tag"]
    assert identity["inventorySha256"] == release.digest((options["assets"] / "installer-inventory.json").read_bytes())
    assert identity["operatorSha256"] == release.digest((options["assets"] / "marty-deploy-linux-amd64").read_bytes())
    assert "verified" not in values and "admission" not in values
    image = openbao["server"]["image"]
    rendered = f"{image['registry']}/{image['repository']}:{image['tag']}"
    assert rendered == PREFIX + "openbao-didcomm:2.5.5@sha256:" + "5" * 64
    assert rendered.split("@", 1)[1] == values["images"]["openbao_didcomm"].split("@", 1)[1]
    for path, record in ((options["output"], values), (options["openbao_output"], openbao)):
        assert release.decode(path.read_bytes()) == record
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("key,value", [
    ("runtime_source_sha", "c" * 40), ("release_tag", "v9.9.9"),
    ("build_run_id", 43), ("build_run_attempt", 3), ("chart_source_sha", "main"),
])
def test_independent_identity_cannot_be_replaced_by_inventory_claims(inputs, key, value):
    options, calls, _ = inputs
    options[key] = value
    with pytest.raises(ValueError):
        helm.prepare(**options)
    assert_no_outputs(options)
    assert not calls


@pytest.mark.parametrize("service,replacement", [
    ("ui", reference("ui", "1")),
    ("gateway", "ghcr.io/other/services@sha256:" + "2" * 64),
    ("issuance-native", reference("services", "7")),
    ("signing-keys", reference("services", "7")),
    ("auth", reference("services", "7")),
    ("keycloak-configurator", reference("keycloak", "7")),
    ("kms-initialize", reference("migrations", "7")),
    ("ui", PREFIX + "ui-selfhost:latest"),
])
def test_cannot_relabel_or_collapse_different_signed_image_roles(inputs, service, replacement):
    options, calls, _ = inputs
    change_lock(options, lambda lock: lock["services"].__setitem__(service, replacement))
    with pytest.raises(ValueError):
        helm.prepare(**options)
    assert_no_outputs(options)
    assert not calls


@pytest.mark.parametrize("service", ["ui", "issuance-native", "signing-keys", "keycloak-configurator"])
def test_missing_required_role_is_refused(inputs, service):
    options, _, _ = inputs
    change_lock(options, lambda lock: lock["services"].pop(service))
    with pytest.raises(ValueError):
        helm.prepare(**options)
    assert_no_outputs(options)


def test_generic_openbao_or_duplicate_role_digest_cannot_replace_plugin(inputs):
    options, _, _ = inputs
    change_lock(options, lambda lock: lock.update(openbao_didcomm_image="docker.io/openbao/openbao@sha256:" + "5" * 64))
    with pytest.raises(ValueError, match="different repository"):
        helm.prepare(**options)
    change_lock(options, lambda lock: lock.update(openbao_didcomm_image=reference("openbao-didcomm", "1")))
    with pytest.raises(ValueError, match="not distinct"):
        helm.prepare(**options)
    assert_no_outputs(options)


@pytest.mark.parametrize("service,replacement", [
    ("postgres", "docker.io/library/postgres:15-alpine"),
    ("redis", "docker.io/other/redis@sha256:" + "7" * 64),
])
def test_infrastructure_pins_cannot_float_or_change_repository(inputs, service, replacement):
    options, calls, _ = inputs
    change_lock(options, lambda lock: lock["services"].__setitem__(service, replacement))
    with pytest.raises(ValueError):
        helm.prepare(**options)
    assert_no_outputs(options)
    assert not calls


@pytest.mark.parametrize("field", ["runInvocationURI", "sourceRepositoryDigest", "buildSignerURI"])
def test_wrong_verified_certificate_identity_is_refused(inputs, field):
    options, _, certificate = inputs
    certificate[field] = "different producer"
    with pytest.raises(ValueError, match="attestation identity"):
        helm.prepare(**options)
    assert_no_outputs(options)


def test_unsigned_verification_claim_is_not_an_input_contract(inputs):
    options, calls, _ = inputs
    path = options["assets"] / "installer-inventory.json"
    record = release.decode(path.read_bytes())
    record["verified"] = True
    write(path, release.encode(record))
    with pytest.raises(ValueError, match="inventory fields differ"):
        helm.prepare(**options)
    assert_no_outputs(options)
    assert not calls


def test_duplicate_record_fields_are_refused(inputs):
    options, _, _ = inputs
    path = options["assets"] / "installer-inventory.json"
    raw = path.read_bytes()
    write(path, b'{"source_sha":"' + SOURCE.encode() + b'",' + raw[1:])
    with pytest.raises(ValueError, match="duplicate record field"):
        helm.prepare(**options)
    assert_no_outputs(options)


@pytest.mark.parametrize("name", ["install.sh", "marty-deploy-linux-amd64", "prepared-selfhost-bundle.zip"])
def test_even_unexecuted_installer_payloads_remain_bound_to_inventory(inputs, name):
    options, calls, _ = inputs
    path = options["assets"] / name
    write(path, b"X" + path.read_bytes()[1:])
    with pytest.raises(ValueError, match="artifact digest differs"):
        helm.prepare(**options)
    assert_no_outputs(options)
    assert not calls


@pytest.mark.parametrize("suffix", [".provenance.jsonl", ".sigstore.json"])
def test_all_payload_sidecars_are_required(inputs, suffix):
    options, calls, _ = inputs
    (options["assets"] / ("install.sh" + suffix)).unlink()
    with pytest.raises(ValueError):
        helm.prepare(**options)
    assert_no_outputs(options)
    assert not calls


@pytest.mark.parametrize("kind", ["attestation", "verify-blob"])
def test_verifier_failure_never_writes_values(inputs, kind):
    options, _, _ = inputs
    original = options["runner"]

    def fail(argv):
        if argv[1] == kind:
            raise ValueError("synthetic cryptographic verifier failure")
        return original(argv)

    options["runner"] = fail
    with pytest.raises(ValueError, match="cryptographic verifier failure"):
        helm.prepare(**options)
    assert_no_outputs(options)


@pytest.mark.parametrize("target", ["proof", "tool", "inventory"])
def test_replacement_during_verification_is_refused(inputs, target):
    options, _, _ = inputs
    paths = {"proof": options["assets"] / "installer-inventory.json.sigstore.json",
             "tool": options["gh"], "inventory": options["assets"] / "installer-inventory.json"}
    path = paths[target]
    original = options["runner"]
    changed = False

    def mutate(argv):
        nonlocal changed
        if not changed:
            raw = path.read_bytes()
            replacement = raw.replace(SOURCE.encode(), b"c" * 40) if target == "inventory" else b"X" + raw[1:]
            write(path, replacement, 0o700 if target == "tool" else 0o600)
            changed = True
        return original(argv)

    options["runner"] = mutate
    with pytest.raises(ValueError):
        helm.prepare(**options)
    assert_no_outputs(options)


def test_unpinned_verifier_is_refused_before_execution(inputs):
    options, calls, _ = inputs
    path = options["gh"]
    write(path, b"X" + path.read_bytes()[1:], 0o700)
    with pytest.raises(ValueError, match="trust anchor differs"):
        helm.prepare(**options)
    assert_no_outputs(options)
    assert not calls


def test_symlinked_payload_is_refused(inputs):
    options, calls, _ = inputs
    path = options["assets"] / "install.sh"
    held = path.with_name("held-install.sh")
    path.rename(held)
    path.symlink_to(held)
    with pytest.raises(ValueError, match="non-symlink"):
        helm.prepare(**options)
    assert_no_outputs(options)
    assert not calls


def test_private_staging_is_required(inputs):
    options, calls, _ = inputs
    options["assets"].chmod(0o755)
    with pytest.raises(ValueError, match="not private"):
        helm.prepare(**options)
    assert_no_outputs(options)
    assert not calls


def test_existing_output_is_preserved_and_outputs_must_be_distinct(inputs):
    options, calls, _ = inputs
    options["openbao_output"] = options["output"]
    with pytest.raises(ValueError, match="different files"):
        helm.prepare(**options)
    write(options["output"], b"existing operator-owned values")
    options["openbao_output"] = options["output"].with_name("openbao-image.json")
    with pytest.raises(ValueError, match="already exists"):
        helm.prepare(**options)
    assert options["output"].read_bytes() == b"existing operator-owned values"
    assert not options["openbao_output"].exists()
    assert not calls
