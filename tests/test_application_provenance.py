"""The package application has its own signed evidence, without gaining cutover authority.

Verifier responses below represent the pinned tools' authenticated output. They
are fixtures for trust decisions, never fabricated signed release evidence.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import application_provenance as package_proof
import package_web_composition as composition
import ui_release as ui
import web_producer_evidence as evidence
import website_producer_policy as policy
import website_provenance as proof
import website_release as web
from tests.test_package_web_composition import candidate

SOURCE = "a" * 40
DIGEST = "sha256:" + "b" * 64
IMAGE = "ghcr.io/elevenid/marty-ui-oss/application"
PRODUCER = {
    "repository": "ElevenID/marty-ui",
    "workflow": ".github/workflows/production-web-release.yml",
    "ref": "refs/heads/main",
    "source_sha": SOURCE,
    "run_id": "231",
    "run_attempt": "2",
}


def certificate_result():
    """Independent expected identity, not derived from the policy under test."""
    return [{"attestation": {}, "verificationResult": {"signature": {"certificate": {
        "issuer": "https://token.actions.githubusercontent.com",
        "runInvocationURI": "https://github.com/ElevenID/marty-ui/actions/runs/231/attempts/2",
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": "https://github.com/ElevenID/marty-ui",
        "sourceRepositoryDigest": SOURCE,
        "sourceRepositoryRef": "refs/heads/main",
        "sourceRepositoryIdentifier": "1140864197",
        "buildSignerURI": "https://github.com/ElevenID/marty-ui/.github/workflows/production-web-release.yml@refs/heads/main",
    }}}}]


def verifier_runner(*, certificate_change=None, image_digest=DIGEST, on_call=None):
    calls = []

    def run(arguments):
        calls.append(arguments)
        if on_call is not None:
            on_call(arguments)
        if arguments[1] == "attestation":
            result = certificate_result()
            if certificate_change is not None:
                certificate_change(result[0]["verificationResult"]["signature"]["certificate"])
            return json.dumps(result)
        if arguments[1] == "verify":
            return json.dumps([{"critical": {"image": {"docker-manifest-digest": image_digest}}}])
        assert arguments[1] == "verify-blob"
        return "verified fixture"

    return run, calls


def write_private(path, data):
    path.write_bytes(data)
    path.chmod(0o600)


@pytest.fixture
def package_files(tmp_path):
    tmp_path.chmod(0o700)
    for name in ("gh", "cosign", "application-release.json", "application-release.json.provenance.jsonl",
                 "application-release.json.sigstore.json", "image.provenance.jsonl"):
        write_private(tmp_path / name, b"fixed trust-test fixture; never executed")
    return tmp_path


def verify_package_subject(directory, run):
    proof.verify_subject(directory / "application-release.json", producer=copy.deepcopy(PRODUCER), role="application",
                         gh=directory / "gh", cosign=directory / "cosign", runner=run)


def verify_package_image(directory, run, *, producer=None, image_uri=IMAGE):
    proof.verify_image({"uri": image_uri, "digest": DIGEST, "platform": "linux/amd64"},
                       directory / "image.provenance.jsonl", producer=producer or copy.deepcopy(PRODUCER),
                       role="application", gh=directory / "gh", cosign=directory / "cosign", runner=run)


def unexpected_verifier(_arguments):
    pytest.fail("unauthorized package identity reached an external verifier")


def test_package_receipt_and_image_use_exact_original_public_identity(package_files, monkeypatch):
    run, calls = verifier_runner()
    monkeypatch.setattr(proof.auth, "registry_command", lambda *_args, **_kwargs: pytest.fail("public package used private credentials"))
    verify_package_subject(package_files, run)
    verify_package_image(package_files, run)
    assert len(calls) == 4
    assert calls[0][3] == str(package_files / "application-release.json")
    assert calls[1][2] == str(package_files / "application-release.json")
    assert calls[2][3] == "oci://" + IMAGE + "@" + DIGEST
    assert calls[3][2] == IMAGE + "@" + DIGEST
    for command in (calls[0], calls[2]):
        assert command[command.index("--repo") + 1] == "ElevenID/marty-ui"
        assert command[command.index("--source-digest") + 1] == SOURCE
        assert command[command.index("--source-ref") + 1] == "refs/heads/main"
        assert command[command.index("--signer-workflow") + 1] == "ElevenID/marty-ui/.github/workflows/production-web-release.yml"
        assert "--deny-self-hosted-runners" in command
        assert command[command.index("--predicate-type") + 1] == "https://slsa.dev/provenance/v1"
    for command in (calls[1], calls[3]):
        assert command[command.index("--certificate-identity") + 1] == (
            "https://github.com/ElevenID/marty-ui/.github/workflows/production-web-release.yml@refs/heads/main")
        assert command[command.index("--certificate-oidc-issuer") + 1] == "https://token.actions.githubusercontent.com"
    assert all("--no-public-good" not in command for command in calls)
    assert policy.PACKAGE_APPLICATION_IMAGE == IMAGE
    assert evidence.subject_role(["application-release.json"]) == "application"


@pytest.mark.parametrize("producer", [
    {**PRODUCER, "repository": "ElevenID/website", "workflow": ".github/workflows/production-website-release.yml"},
    {**PRODUCER, "repository": "ElevenID/marty-subscriptions", "workflow": ".github/workflows/production-ui-release.yml"},
    {**PRODUCER, "repository": "another-owner/marty-ui"},
    {**PRODUCER, "workflow": ".github/workflows/ci.yml"},
    {**PRODUCER, "ref": "refs/pull/2007/merge"},
])
def test_package_image_cannot_be_claimed_by_website_private_or_unapproved_producer(package_files, producer):
    with pytest.raises(ValueError):
        verify_package_image(package_files, unexpected_verifier, producer=producer)


@pytest.mark.parametrize("role", ["website", "composition"])
def test_package_image_and_receipt_cannot_be_relabelled_as_another_role(package_files, role):
    with pytest.raises(ValueError):
        policy.image_policy(IMAGE, role=role)
    with pytest.raises(ValueError, match="subject does not belong"):
        proof.verify_subject(package_files / "application-release.json", producer=copy.deepcopy(PRODUCER), role=role,
                             gh=package_files / "gh", cosign=package_files / "cosign", runner=unexpected_verifier)


@pytest.mark.parametrize("image_uri", [
    "ghcr.io/elevenid/website", "ghcr.io/elevenid/marty-ui-oss/website",
    "ghcr.io/elevenid/marty-subscriptions/website", "ghcr.io/elevenid/marty-subscriptions/ui-production",
    IMAGE + ":latest", IMAGE + "@" + DIGEST, "ghcr.io/another-owner/application",
])
def test_package_proof_does_not_admit_website_private_tagged_or_other_images(package_files, image_uri):
    with pytest.raises(ValueError):
        verify_package_image(package_files, unexpected_verifier, image_uri=image_uri)


@pytest.mark.parametrize("boundary", [verify_package_subject, verify_package_image], ids=["receipt", "image"])
@pytest.mark.parametrize("field,value", [
    ("sourceRepositoryURI", "https://github.com/ElevenID/website"),
    ("sourceRepositoryIdentifier", "1459542519"),
    ("sourceRepositoryDigest", "c" * 40),
    ("sourceRepositoryRef", "refs/heads/topic"),
    ("buildSignerURI", "https://github.com/ElevenID/marty-ui/.github/workflows/ci.yml@refs/heads/main"),
    ("runInvocationURI", "https://github.com/ElevenID/marty-ui/actions/runs/232/attempts/2"),
    ("runInvocationURI", "https://github.com/ElevenID/marty-ui/actions/runs/231/attempts/1"),
    ("runnerEnvironment", "self-hosted"),
    ("issuer", "https://issuer.invalid"),
    ("githubWorkflowSHA", "c" * 40),
])
def test_package_proofs_reject_replay_from_another_owner_workflow_source_or_invocation(package_files, boundary, field, value):
    run, calls = verifier_runner(certificate_change=lambda certificate: certificate.update({field: value}))
    expected = "original private repository ID" if field == "runnerEnvironment" else "certificate differs"
    with pytest.raises(ValueError, match=expected):
        boundary(package_files, run)
    assert len(calls) == 1, "a rejected certificate must not proceed to the second verifier"


def test_package_image_signature_must_bind_the_exact_pinned_digest(package_files):
    run, calls = verifier_runner(image_digest="sha256:" + "c" * 64)
    with pytest.raises(ValueError, match="digest differs"):
        verify_package_image(package_files, run)
    assert len(calls) == 2


@pytest.mark.parametrize("name", [
    "application-release.json", "application-release.json.provenance.jsonl", "application-release.json.sigstore.json",
    "image.provenance.jsonl",
])
def test_package_subjects_and_proofs_cannot_change_while_verifiers_run(package_files, name):
    def mutate(arguments):
        if arguments[1] in {"verify", "verify-blob"}:
            write_private(package_files / name, b"replacement after the original proof was checked")
    run, _ = verifier_runner(on_call=mutate)
    boundary = verify_package_image if name == "image.provenance.jsonl" else verify_package_subject
    with pytest.raises(ValueError, match="changed during"):
        boundary(package_files, run)


@pytest.mark.parametrize("name", [
    "application-release.json", "application-release.json.provenance.jsonl", "application-release.json.sigstore.json",
    "image.provenance.jsonl",
])
def test_package_proof_inputs_must_be_ordinary_local_files(package_files, name):
    path = package_files / name
    path.unlink()
    path.symlink_to(package_files / "gh")
    boundary = verify_package_image if name == "image.provenance.jsonl" else verify_package_subject
    with pytest.raises(ValueError, match="non-symlink"):
        boundary(package_files, unexpected_verifier)


@pytest.mark.parametrize("boundary", [verify_package_subject, verify_package_image], ids=["receipt", "image"])
def test_package_proof_failure_is_not_downgraded_to_metadata_only_admission(package_files, boundary):
    def failed(_arguments):
        raise ValueError("cryptographic verifier rejected the original evidence")
    with pytest.raises(ValueError, match="cryptographic verifier rejected"):
        boundary(package_files, failed)


@pytest.mark.parametrize("extra", [[], ["--commerce-source-sha", "c" * 40], ["--registry-config", "private-config.json"]])
def test_package_cli_requires_exact_public_source_without_private_overrides(package_files, monkeypatch, extra):
    arguments = ["application_provenance.py", "--assets", str(package_files),
                 "--gh", str(package_files / "gh"), "--cosign", str(package_files / "cosign")]
    if extra:
        arguments += ["--source-sha", SOURCE, *extra]
    monkeypatch.setattr(sys, "argv", arguments)
    monkeypatch.setattr(package_proof, "verify_package_application", lambda *_args, **_kwargs: pytest.fail("unpinned or private invocation reached verification"))
    with pytest.raises(SystemExit) as rejected:
        package_proof.main()
    assert rejected.value.code == 2


def test_package_cli_passes_the_requested_source_pin(package_files, monkeypatch):
    calls = []
    monkeypatch.setattr(package_proof, "verify_package_application", lambda *args, **kwargs: calls.append((args, kwargs)))
    monkeypatch.setattr(sys, "argv", ["application_provenance.py", "--assets", str(package_files),
                                     "--gh", str(package_files / "gh"), "--cosign", str(package_files / "cosign"),
                                     "--source-sha", SOURCE])
    package_proof.main()
    assert calls == [((package_files,), {"gh": package_files / "gh", "cosign": package_files / "cosign", "source_sha": SOURCE})]


def test_new_package_image_does_not_expand_combined_release_or_composition_admission(candidate):
    kwargs, _, _, _ = candidate
    application = web.read(kwargs["application_assets"] / "production-web-release.json")
    assert web.validate_combined_release(application) == application
    manifest = composition.package(**kwargs)
    assert composition.validate_record(manifest) == manifest

    application["image"]["uri"] = IMAGE
    with pytest.raises(ValueError):
        web.validate_combined_release(application)

    manifest["application"]["image"]["uri"] = IMAGE
    manifest["images"]["ui"] = IMAGE + "@" + manifest["application"]["image"]["digest"]
    manifest["composition_id"] = ui.digest(ui.canonical({key: value for key, value in manifest.items() if key != "composition_id"}))
    with pytest.raises(ValueError):
        composition.validate_record(manifest)


@pytest.fixture
def qualified_package(tmp_path):
    from tests.test_application_release import make_assets

    directory = tmp_path / "package"
    directory.mkdir(mode=0o700)
    release = make_assets(directory)
    assert release["producer"] == PRODUCER
    assert release["image"] == {"uri": IMAGE, "digest": DIGEST, "platform": "linux/amd64"}
    for name in ("application-release.json.provenance.jsonl", "application-release.json.sigstore.json", "image.provenance.jsonl"):
        write_private(directory / name, b"original proof fixture; never executed")
    for name in ("gh", "cosign"):
        write_private(tmp_path / name, b"verifier fixture; never executed")
    return directory, release


def verify_qualified_package(directory, run, *, source_sha=SOURCE):
    return package_proof.verify_package_application(directory, source_sha=source_sha,
                                                    gh=directory.parent / "gh", cosign=directory.parent / "cosign", runner=run)


def test_package_wrapper_validates_actual_assets_and_verifies_both_original_subjects(qualified_package, monkeypatch):
    directory, release = qualified_package
    run, calls = verifier_runner()
    monkeypatch.setattr(proof.auth, "registry_command", lambda *_args, **_kwargs: pytest.fail("public package used private credentials"))
    assert verify_qualified_package(directory, run) == release
    assert [(args[1], args[2] if args[1] != "attestation" else args[3]) for args in calls] == [
        ("attestation", str(directory / "application-release.json")),
        ("verify-blob", str(directory / "application-release.json")),
        ("attestation", "oci://" + IMAGE + "@" + DIGEST),
        ("verify", IMAGE + "@" + DIGEST),
    ]
    assert release["qualification"]["activated"] is False
    assert release["qualification"]["host_deployment_tested"] is False
    assert release["qualification"]["oidc_journey_tested"] is False
    with pytest.raises(ValueError):
        web.validate_combined_release(release)


def test_package_wrapper_rejects_a_valid_receipt_from_an_unrequested_source(qualified_package):
    directory, _ = qualified_package
    with pytest.raises(ValueError, match="original producer"):
        verify_qualified_package(directory, unexpected_verifier, source_sha="f" * 40)


@pytest.mark.parametrize("field,value", [
    (("producer", "repository"), "ElevenID/website"),
    (("producer", "repository"), "ElevenID/marty-subscriptions"),
    (("producer", "repository"), "another-owner/marty-ui"),
    (("producer", "workflow"), ".github/workflows/ci.yml"),
    (("producer", "ref"), "refs/pull/2007/merge"),
    (("producer", "source_sha"), "c" * 40),
    (("image", "uri"), "ghcr.io/elevenid/website"),
    (("image", "uri"), "ghcr.io/elevenid/marty-ui-oss/ui-public"),
    (("image", "uri"), "ghcr.io/elevenid/marty-subscriptions/ui-production"),
])
def test_package_wrapper_rejects_other_authorities_even_when_generic_application_proof_allows_them(qualified_package, field, value):
    directory, release = qualified_package
    release[field[0]][field[1]] = value
    write_private(directory / "application-release.json", ui.canonical(release))
    with pytest.raises(ValueError):
        verify_qualified_package(directory, unexpected_verifier)


def test_package_wrapper_rejects_receipt_invocation_replay_before_image_verification(qualified_package):
    directory, release = qualified_package
    release["producer"]["run_attempt"] = "3"
    write_private(directory / "application-release.json", ui.canonical(release))
    run, calls = verifier_runner()
    with pytest.raises(ValueError, match="certificate differs"):
        verify_qualified_package(directory, run)
    assert len(calls) == 1


PINNED_ASSETS = (
    "application-source-package.zip", "application-source-origin.json", "application-source-package.json",
    "application-profile-source-closure.json", "application-package-consumer.json", "application-runtime-context.json",
    "application-image-check.json", "application-image-browser.json",
)


@pytest.mark.parametrize("name", PINNED_ASSETS)
def test_package_wrapper_rejects_changed_qualification_bytes_before_any_verifier(qualified_package, name):
    directory, _ = qualified_package
    path = directory / name
    write_private(path, path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="bytes differ"):
        verify_qualified_package(directory, unexpected_verifier)


@pytest.mark.parametrize("name", (
    *PINNED_ASSETS, "application-release.json", "application-release.json.provenance.jsonl",
    "application-release.json.sigstore.json", "image.provenance.jsonl",
))
def test_package_wrapper_rechecks_bytes_after_receipt_verification_and_image_checks(qualified_package, name):
    directory, _ = qualified_package

    def mutate_after_receipt_verification(arguments):
        if arguments[1] == "verify":
            path = directory / name
            # A newline preserves JSON meaning, so parsed-object comparison
            # cannot stand in for preservation of the original signed bytes.
            write_private(path, path.read_bytes() + b"\n")

    run, calls = verifier_runner(on_call=mutate_after_receipt_verification)
    with pytest.raises(ValueError):
        verify_qualified_package(directory, run)
    assert len(calls) == 4


def test_package_wrapper_rejects_image_certificate_replay_after_a_valid_receipt(qualified_package):
    directory, _ = qualified_package
    good_runner, calls = verifier_runner()

    def image_from_another_source(arguments):
        output = good_runner(arguments)
        if arguments[1] == "attestation" and arguments[3].startswith("oci://"):
            value = json.loads(output)
            value[0]["verificationResult"]["signature"]["certificate"]["sourceRepositoryDigest"] = "c" * 40
            return json.dumps(value)
        return output

    with pytest.raises(ValueError, match="certificate differs"):
        verify_qualified_package(directory, image_from_another_source)
    assert len(calls) == 3
