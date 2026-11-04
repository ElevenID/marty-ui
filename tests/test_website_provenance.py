"""Original producer admission applies equally to public and private web artifacts."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ui_release as ui
import website_release as web
import website_provenance as proof

SOURCE, PRIVATE = "a" * 40, "c" * 40
DIGEST = "sha256:" + "b" * 64


def verified(producer):
    return [{"attestation": {}, "verificationResult": {"signature": {"certificate": {
        "issuer": proof.verifier.ISSUER,
        "runInvocationURI": f"https://github.com/{producer['repository']}/actions/runs/{producer['run_id']}/attempts/{producer['run_attempt']}",
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": "https://github.com/" + producer["repository"],
        "sourceRepositoryDigest": producer["source_sha"], "sourceRepositoryRef": web.REF,
        "sourceRepositoryIdentifier": web.REPOSITORIES[producer["repository"]],
        "buildSignerURI": f"https://github.com/{producer['repository']}/{producer['workflow']}@{web.REF}",
    }}}}]


@pytest.fixture
def files(tmp_path):
    tmp_path.chmod(0o700)
    for name in ("gh", "cosign", "subject.json", "subject.json.provenance.jsonl", "subject.json.sigstore.json", "image.provenance.jsonl"):
        (tmp_path / name).write_bytes(b"fixed test bytes, never executed")
    return tmp_path


@pytest.mark.parametrize("full", [False, True])
def test_subject_verifies_exact_original_invocation_and_private_source(files, full):
    producer = web.producer(SOURCE, ui.commerce_identity("full", PRIVATE) if full else None, "21", "2")
    calls = []
    def run(args):
        calls.append(args)
        return json.dumps(verified(producer)) if args[1] == "attestation" else "verified"
    proof.verify_subject(files / "subject.json", producer=producer, gh=files / "gh", cosign=files / "cosign", runner=run)
    assert len(calls) == 2
    assert calls[0][calls[0].index("--source-digest") + 1] == (PRIVATE if full else SOURCE)
    assert calls[0][calls[0].index("--repo") + 1] == producer["repository"]
    assert "--deny-self-hosted-runners" in calls[0]
    assert ("--no-public-good" in calls[0]) is full
    assert "--no-public-good" not in calls[1]
    assert calls[0][calls[0].index("--bundle") + 1] == str(files / "subject.json.provenance.jsonl")
    assert calls[1][calls[1].index("--certificate-identity") + 1].endswith(producer["workflow"] + "@refs/heads/main")


@pytest.mark.parametrize("key,value", [
    ("issuer", "https://example.invalid"), ("runInvocationURI", "https://github.com/ElevenID/marty-ui/actions/runs/21/attempts/1"),
    ("runnerEnvironment", "self-hosted"), ("sourceRepositoryURI", "https://github.com/fork/marty-subscriptions"),
    ("sourceRepositoryDigest", SOURCE), ("sourceRepositoryRef", "refs/heads/topic"),
    ("sourceRepositoryIdentifier", "1"),
    ("githubWorkflowSHA", SOURCE),
])
def test_certificate_rejects_any_changed_identity_field(key, value):
    producer = web.producer(SOURCE, ui.commerce_identity("full", PRIVATE), "21", "2")
    output = verified(producer)
    output[0]["verificationResult"]["signature"]["certificate"][key] = value
    with pytest.raises(ValueError):
        proof.verified_certificate(json.dumps(output), producer)


def test_certificate_rejects_another_workflow_in_the_original_repository():
    producer = web.producer(SOURCE, ui.commerce_identity("full", PRIVATE), "21", "2")
    output = verified(producer)
    certificate = output[0]["verificationResult"]["signature"]["certificate"]
    # Change only the workflow, retaining the original repository/source. This
    # also avoids coupling a synthetic negative fixture to a private repo URL.
    certificate["buildSignerURI"] = certificate["buildSignerURI"].replace(
        producer["workflow"], ".github/workflows/other.yml")
    with pytest.raises(ValueError):
        proof.verified_certificate(json.dumps(output), producer)


@pytest.mark.parametrize("output", ["{}", "[]", '[{},{}]', '[{"attestation":{}}]', '{"x":1,"x":2}', 'invalid'])
def test_malformed_or_ambiguous_proofs_fail_closed(output):
    with pytest.raises(ValueError):
        proof.verified_certificate(output, web.producer(SOURCE, None, "1", "1"))


def test_subject_changed_during_verification_is_not_consumed(files):
    producer = web.producer(SOURCE, None, "21", "2")
    def run(args):
        (files / "subject.json").write_text("changed")
        return json.dumps(verified(producer)) if args[1] == "attestation" else "verified"
    with pytest.raises(ValueError, match="changed during"):
        proof.verify_subject(files / "subject.json", producer=producer, gh=files / "gh", cosign=files / "cosign", runner=run)


def test_symlink_evidence_and_verifier_failure_are_rejected(files):
    producer = web.producer(SOURCE, None, "21", "2")
    (files / "subject.json.provenance.jsonl").unlink()
    (files / "subject.json.provenance.jsonl").symlink_to(files / "subject.json")
    with pytest.raises(ValueError, match="non-symlink"):
        proof.verify_subject(files / "subject.json", producer=producer, gh=files / "gh", cosign=files / "cosign")
    (files / "subject.json.provenance.jsonl").unlink()
    (files / "subject.json.provenance.jsonl").write_bytes(b"proof")
    def failed(_args):
        raise ValueError("cryptographic verification failed")
    with pytest.raises(ValueError, match="cryptographic"):
        proof.verify_subject(files / "subject.json", producer=producer, gh=files / "gh", cosign=files / "cosign", runner=failed)


@pytest.mark.parametrize("full", [False, True])
def test_image_proof_binds_original_producer_and_exact_oci_digest(files, full):
    producer = web.producer(SOURCE, ui.commerce_identity("full", PRIVATE) if full else None, "21", "2")
    image = {"uri": web.COMMERCE_IMAGE if full else web.PUBLIC_IMAGE, "digest": DIGEST, "platform": "linux/amd64"}
    calls = []
    def run(args):
        calls.append(args)
        if args[1] == "attestation":
            return json.dumps(verified(producer))
        return json.dumps([{"critical": {"image": {"docker-manifest-digest": DIGEST}}}])
    proof.verify_image(image, files / "image.provenance.jsonl", producer=producer,
                       gh=files / "gh", cosign=files / "cosign", runner=run)
    assert "oci://" + image["uri"] + "@" + DIGEST in calls[0]
    assert ("--no-public-good" in calls[0]) is full
    assert "--no-public-good" not in calls[1]
    assert image["uri"] + "@" + DIGEST in calls[1]
    wrong = copy.deepcopy(image)
    wrong["uri"] = web.PUBLIC_IMAGE if full else web.COMMERCE_IMAGE
    with pytest.raises(ValueError, match="producer differ"):
        proof.verify_image(wrong, files / "image.provenance.jsonl", producer=producer,
                           gh=files / "gh", cosign=files / "cosign", runner=run)


def test_image_signature_cannot_name_another_digest(files):
    producer = web.producer(SOURCE, None, "21", "2")
    def run(args):
        return json.dumps(verified(producer)) if args[1] == "attestation" else json.dumps(
            [{"critical": {"image": {"docker-manifest-digest": "sha256:" + "e" * 64}}}])
    with pytest.raises(ValueError, match="digest differs"):
        proof.verify_image({"uri": web.PUBLIC_IMAGE, "digest": DIGEST, "platform": "linux/amd64"},
                           files / "image.provenance.jsonl", producer=producer,
                           gh=files / "gh", cosign=files / "cosign", runner=run)
