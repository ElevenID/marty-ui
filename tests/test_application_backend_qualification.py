"""Pending qualification over real validators and inert external verifier output.

The fixtures are not signed publication or runtime evidence. Only the external
gh/cosign responses are inert; original receipt, inventory, certificate, image,
retained-baseline and plan validation all run unchanged. No payload executes.
"""
from __future__ import annotations

import copy
import functools
import json
import os
from pathlib import Path
import stat
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import application_backend_qualification as qualification
import application_release as application
import application_release_intake as intake
import installer_release as installer
import package_web_composition as composition
import stable_installer_assets as stable
import ui_release as ui
from tests.test_application_provenance import DIGEST, PRODUCER, SOURCE, verifier_runner
from tests.test_application_release_intake import publication

BACKEND_SOURCE = "c" * 40
BACKEND_TAG = "v1.1.273"


def backend_certificate():
    return [{"attestation": {}, "verificationResult": {"signature": {"certificate": {
        "issuer": "https://token.actions.githubusercontent.com", "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": "https://github.com/ElevenID/marty-ui", "sourceRepositoryIdentifier": "1140864197",
        "sourceRepositoryDigest": BACKEND_SOURCE, "sourceRepositoryRef": "refs/heads/main",
        "runInvocationURI": "https://github.com/ElevenID/marty-ui/actions/runs/121/attempts/2",
        "buildSignerURI": "https://github.com/ElevenID/marty-ui/.github/workflows/cd.yml@refs/heads/main",
    }}}}]


@pytest.fixture
def evidence(publication, tmp_path, monkeypatch):
    backend = tmp_path / "backend-original"
    backend.mkdir(mode=0o700)
    for name in installer.ARTIFACTS:
        (backend / name).write_bytes(b"inert original backend payload: " + name.encode())
    lock = {"schema": "marty.selfhost-image-lock/v1", "release": "marty-ui@1.1.273",
            "services": {name: "ghcr.io/elevenid/" + name + "@sha256:" + digit * 64
                         for name, digit in (("gateway", "1"), ("auth", "2"), ("edge", "3"), ("ui", "4"))},
            "openbao_didcomm_image": "ghcr.io/elevenid/plugin@sha256:" + "5" * 64}
    (backend / "prepared-selfhost-images.json").write_bytes(installer.encode(lock))
    inventory = installer.inventory(backend, source_sha=BACKEND_SOURCE, release_tag=BACKEND_TAG,
                                    build_run_id=121, build_run_attempt=2, expected_services=set(lock["services"]))
    (backend / "installer-inventory.json").write_bytes(installer.encode(inventory))
    for name in stable.SUBJECTS:
        (backend / (name + ".provenance.jsonl")).write_bytes(b"inert original backend proof: " + name.encode())
    backend_calls = []
    state = {"certificate_change": None, "on_call": None}

    def external_backend_runner(arguments):
        backend_calls.append(arguments)
        if state["on_call"]:
            state["on_call"](arguments)
        result = backend_certificate()
        if state["certificate_change"]:
            state["certificate_change"](result[0]["verificationResult"]["signature"]["certificate"])
        return json.dumps(result)

    # Preserve the real shared verifier, including every certificate check.
    original_verify_subject = stable.provenance.verify_subject
    monkeypatch.setattr(stable.provenance, "verify_subject",
                        functools.partial(original_verify_subject, runner=external_backend_runner))
    app_runner, app_calls = verifier_runner()
    return {"application": tmp_path / "original", "backend": backend, "lock": lock,
            "application_calls": app_calls, "backend_calls": backend_calls, "runner": app_runner,
            "state": state, "publication": publication}


def prepare(evidence, tmp_path, **changes):
    options = dict(application_assets=evidence["application"], application_source_sha=SOURCE,
                   backend_assets=evidence["backend"], backend_source_sha=BACKEND_SOURCE, backend_tag=BACKEND_TAG,
                   output=tmp_path / "prepared", gh=tmp_path / "gh", cosign=tmp_path / "cosign", runner=evidence["runner"])
    options.update(changes)
    return qualification.prepare(**options)


def validate(evidence, tmp_path, value, **changes):
    options = dict(assets=tmp_path / "prepared", application_source_sha=SOURCE, backend_source_sha=BACKEND_SOURCE,
                   backend_tag=BACKEND_TAG, expected_plan_id=value["plan_id"], gh=tmp_path / "gh", cosign=tmp_path / "cosign",
                   runner=evidence["runner"])
    options.update(changes)
    return qualification.validate(**options)


def originals(evidence):
    return {prefix + "/" + path.name: path.read_bytes() for prefix in ("application", "backend")
            for path in evidence[prefix].iterdir()}


def absent(tmp_path):
    assert not os.path.lexists(tmp_path / "prepared")
    assert list(tmp_path.glob(".application-backend-qualification-*")) == []


def rewrite_plan(tmp_path, value):
    value["plan_id"] = qualification.plan_id(value)
    (tmp_path / "prepared" / qualification.PLAN_NAME).write_bytes(ui.canonical(value))


def test_prepare_retains_originals_and_validate_reauthenticates_exact_independent_producers(evidence, tmp_path):
    before = originals(evidence)
    value = prepare(evidence, tmp_path)
    destination = tmp_path / "prepared"
    assert len(before) == 24
    assert {path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file()} == {
        *before, qualification.PLAN_NAME, qualification.PROFILE_NAME}
    assert {name: (destination / name).read_bytes() for name in before} == before == originals(evidence)
    assert all(stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600)
               for path in (destination, *destination.rglob("*")))
    assert value["schema"] == "marty.application-backend-qualification-plan/v1" and value["status"] == "unqualified"
    assert value["application"]["source_sha"] == SOURCE != value["backend"]["source_sha"] == BACKEND_SOURCE
    assert value["application"]["producer"] == PRODUCER
    assert value["application"]["image"] == {"uri": application.IMAGE, "digest": DIGEST, "platform": "linux/amd64"}
    assert value["backend"]["producer"] == {
        "repository": "ElevenID/marty-ui", "repository_id": "1140864197", "workflow": ".github/workflows/cd.yml",
        "ref": "refs/heads/main", "source_sha": BACKEND_SOURCE, "run_id": 121, "run_attempt": 2}
    assert value["backend"]["image_lock"] == evidence["lock"]
    assert value["backend"]["image_lock"]["services"]["ui"] != application.IMAGE + "@" + DIGEST
    assert all(flag is False for flag in value["qualification"].values())
    assert all(row["status"] == "pending" for row in value["required_observations"] + value["separate_gates"])
    assert value["profile"]["sha256"] == qualification.PROFILE_SHA256
    assert (destination / qualification.PROFILE_NAME).read_bytes() == qualification.PROFILE_PATH.read_bytes()
    assert len(evidence["application_calls"]) == 4 and len(evidence["backend_calls"]) == 5
    assert validate(evidence, tmp_path, value) == value
    assert len(evidence["application_calls"]) == 8 and len(evidence["backend_calls"]) == 10
    for command in evidence["backend_calls"]:
        assert command[command.index("--source-digest") + 1] == BACKEND_SOURCE
        assert command[command.index("--signer-workflow") + 1] == "ElevenID/marty-ui/.github/workflows/cd.yml"
        assert "--deny-self-hosted-runners" in command
    assert {name: (destination / name).read_bytes() for name in before} == before == originals(evidence)


@pytest.mark.parametrize("field,value", [("application_source_sha", "d" * 40), ("backend_source_sha", SOURCE),
                                         ("backend_tag", "v1.1.274"), ("application_source_sha", "main"),
                                         ("backend_source_sha", None), ("backend_tag", "v1.2.3-rc.1")])
def test_prepare_requires_independently_selected_exact_sources_and_stable_tag(evidence, tmp_path, field, value):
    with pytest.raises(ValueError):
        prepare(evidence, tmp_path, **{field: value})
    absent(tmp_path)


@pytest.mark.parametrize("field,value", [("application_source_sha", "d" * 40), ("backend_source_sha", SOURCE),
                                         ("backend_tag", "v1.1.274"), ("expected_plan_id", "sha256:" + "0" * 64)])
def test_validate_never_retargets_external_review_selection(evidence, tmp_path, field, value):
    plan = prepare(evidence, tmp_path)
    evidence["application_calls"].clear()
    evidence["backend_calls"].clear()
    with pytest.raises(ValueError):
        validate(evidence, tmp_path, plan, **{field: value})
    assert not evidence["application_calls"] and not evidence["backend_calls"]


@pytest.mark.parametrize("field", ["issuer", "runnerEnvironment", "sourceRepositoryURI", "sourceRepositoryIdentifier",
                                  "sourceRepositoryDigest", "sourceRepositoryRef", "runInvocationURI", "buildSignerURI"])
@pytest.mark.parametrize("role", ["application", "backend"])
def test_original_certificate_trust_fields_cannot_be_substituted(evidence, tmp_path, field, role):
    def change(certificate):
        certificate[field] += "wrong"
    if role == "application":
        evidence["runner"], _ = verifier_runner(certificate_change=change)
    else:
        evidence["state"]["certificate_change"] = change
    with pytest.raises(ValueError):
        prepare(evidence, tmp_path)
    absent(tmp_path)


@pytest.mark.parametrize("name", tuple(qualification.ORIGINAL_LIMITS))
def test_every_original_byte_is_review_bound_on_validate(evidence, tmp_path, name):
    value = prepare(evidence, tmp_path)
    path = tmp_path / "prepared" / name
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="originals differ"):
        validate(evidence, tmp_path, value)


@pytest.mark.parametrize("change", ["extra", "missing", "symlink", "directory", "fifo", "empty", "oversize"])
@pytest.mark.parametrize("role", ["application", "backend"])
def test_inputs_have_bounded_closed_normal_file_rosters(evidence, tmp_path, change, role):
    directory = evidence[role]
    name = intake.PROOFS[0] if role == "application" else "installer-inventory.json.provenance.jsonl"
    path = directory / name
    if change == "extra":
        (directory / "unselected.json").write_bytes(b"extra")
    elif change == "empty":
        path.write_bytes(b"")
    elif change == "oversize":
        limit = intake.FILE_LIMITS[name] if role == "application" else qualification.BACKEND_LIMITS[name]
        with path.open("wb") as output:
            output.truncate(limit + 1)
    else:
        path.unlink()
        if change == "symlink":
            path.symlink_to(tmp_path / "gh")
        elif change == "directory":
            path.mkdir()
        elif change == "fifo":
            os.mkfifo(path)
    with pytest.raises((OSError, ValueError)):
        prepare(evidence, tmp_path)
    absent(tmp_path)


@pytest.mark.parametrize("claim", tuple(qualification.QUALIFICATION))
@pytest.mark.parametrize("value", [True, 0])
def test_rehashed_plan_cannot_claim_testing_or_admission(evidence, tmp_path, claim, value):
    plan = prepare(evidence, tmp_path)
    plan["qualification"][claim] = value
    rewrite_plan(tmp_path, plan)
    with pytest.raises(ValueError, match="claim success"):
        validate(evidence, tmp_path, plan)


@pytest.mark.parametrize("path,value", [
    (("application", "image", "digest"), "sha256:" + "0" * 64),
    (("application", "producer", "run_attempt"), "3"),
    (("application", "repository_id"), "1"),
    (("application", "route_contract", "sha256"), "sha256:" + "0" * 64),
    (("backend", "producer", "run_id"), 122),
    (("backend", "image_lock", "services", "ui"), application.IMAGE + "@" + DIGEST),
    (("backend", "image_lock", "openbao_didcomm_image"), "ghcr.io/elevenid/plugin@sha256:" + "0" * 64),
])
def test_rehashed_plan_must_reconstruct_from_authenticated_originals(evidence, tmp_path, path, value):
    plan = prepare(evidence, tmp_path)
    target = plan
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    rewrite_plan(tmp_path, plan)
    with pytest.raises(ValueError, match="original authenticated"):
        validate(evidence, tmp_path, plan)


def test_same_source_different_original_application_attempt_requires_new_review_id(evidence, tmp_path):
    first = prepare(evidence, tmp_path)
    release_path = evidence["application"] / application.RECEIPT
    release = application.read(release_path)
    release["producer"]["run_attempt"] = "3"
    release_path.write_bytes(ui.canonical(release))
    evidence["runner"], _ = verifier_runner(certificate_change=lambda cert: cert.update(
        runInvocationURI="https://github.com/ElevenID/marty-ui/actions/runs/231/attempts/3"))
    second = prepare(evidence, tmp_path, output=tmp_path / "other-attempt")
    assert first["plan_id"] != second["plan_id"]
    with pytest.raises(ValueError, match="plan ID"):
        validate(evidence, tmp_path, first, assets=tmp_path / "other-attempt")
    assert validate(evidence, tmp_path, second, assets=tmp_path / "other-attempt") == second


def test_different_valid_proof_bytes_require_new_review_id(evidence, tmp_path):
    first = prepare(evidence, tmp_path)
    path = evidence["backend"] / "install.sh.provenance.jsonl"
    path.write_bytes(b"another inert external-verifier proof fixture")
    second = prepare(evidence, tmp_path, output=tmp_path / "other-proof")
    assert first["application"] == second["application"] and first["backend"] == second["backend"]
    assert first["plan_id"] != second["plan_id"]
    with pytest.raises(ValueError, match="plan ID"):
        validate(evidence, tmp_path, first, assets=tmp_path / "other-proof")


@pytest.mark.parametrize("role,key", [("application", "run_id"), ("application", "run_attempt"),
                                     ("backend", "build_run_id"), ("backend", "build_run_attempt")])
def test_changed_original_invocation_requires_its_own_certificate(evidence, tmp_path, role, key):
    path = evidence[role] / (application.RECEIPT if role == "application" else "installer-inventory.json")
    value = application.read(path)
    target = value["producer"] if role == "application" else value
    target[key] = str(int(target[key]) + 1) if role == "application" else target[key] + 1
    path.write_bytes(ui.canonical(value))
    with pytest.raises(ValueError):
        prepare(evidence, tmp_path)
    absent(tmp_path)


@pytest.mark.parametrize("change", ["unknown-field", "schema", "pending-observation", "pending-gate", "duplicate-json"])
def test_plan_is_closed_and_cannot_record_observations(evidence, tmp_path, change):
    value = prepare(evidence, tmp_path)
    if change == "unknown-field":
        value["command"] = ["execute-downloaded-payload"]
    elif change == "schema":
        value["schema"] = "marty.web-composition/v1"
    elif change == "pending-observation":
        value["required_observations"][0]["status"] = "passed"
    elif change == "pending-gate":
        value["separate_gates"][0]["status"] = "passed"
    rewrite_plan(tmp_path, value)
    if change == "duplicate-json":
        path = tmp_path / "prepared" / qualification.PLAN_NAME
        path.write_bytes(b'{"status":"unqualified",' + path.read_bytes().lstrip()[1:])
    with pytest.raises(ValueError):
        validate(evidence, tmp_path, value)


@pytest.mark.parametrize("source", ["retained", "trusted"])
def test_modified_profile_is_rejected_even_with_matching_forged_plan(evidence, tmp_path, monkeypatch, source):
    plan = prepare(evidence, tmp_path)
    profile = tmp_path / "prepared" / qualification.PROFILE_NAME
    raw = profile.read_bytes() + b"\n"
    profile.write_bytes(raw)
    plan["profile"].update(application.file_record(raw))
    rewrite_plan(tmp_path, plan)
    if source == "trusted":
        fake_profile = tmp_path / "changed-profile.json"
        fake_profile.write_bytes(raw)
        monkeypatch.setattr(qualification, "PROFILE_PATH", fake_profile)
    with pytest.raises(ValueError, match="profile"):
        validate(evidence, tmp_path, plan)
    if source == "trusted":
        with pytest.raises(ValueError, match="reviewed tool"):
            prepare(evidence, tmp_path, output=tmp_path / "new-output")
        assert not (tmp_path / "new-output").exists()


@pytest.mark.parametrize("name", ["application/" + intake.FULL_BASELINE, "backend/install.sh.provenance.jsonl",
                                  qualification.PLAN_NAME, qualification.PROFILE_NAME])
def test_validate_detects_evidence_changed_by_verifier(evidence, tmp_path, name):
    plan = prepare(evidence, tmp_path)
    path = tmp_path / "prepared" / name
    once = False

    def mutate(_arguments):
        nonlocal once
        if not once:
            once = True
            path.write_bytes(path.read_bytes() + b"\n")

    evidence["state"]["on_call"] = mutate
    with pytest.raises(ValueError, match="changed during authentication"):
        validate(evidence, tmp_path, plan)


@pytest.mark.parametrize("location", ["input", "staged"])
@pytest.mark.parametrize("name", ["application/" + intake.FULL_BASELINE, "backend/install.sh.provenance.jsonl"])
def test_prepare_detects_original_or_staged_substitution_and_leaves_no_destination(evidence, tmp_path, location, name):
    once = False

    def mutate(_arguments):
        nonlocal once
        if once:
            return
        once = True
        if location == "input":
            role, filename = name.split("/", 1)
            path = evidence[role] / filename
        else:
            path = next(tmp_path.glob(".application-backend-qualification-*")) / "assets" / name
        path.write_bytes(path.read_bytes() + b"\n")

    evidence["state"]["on_call"] = mutate
    with pytest.raises(ValueError, match="changed during"):
        prepare(evidence, tmp_path)
    absent(tmp_path)


def test_verifier_failure_does_not_publish_or_retry_without_checks(evidence, tmp_path):
    def failure(_arguments):
        raise ValueError("inert external verification failed")
    evidence["state"]["on_call"] = failure
    with pytest.raises(ValueError, match="external verification failed"):
        prepare(evidence, tmp_path)
    assert len(evidence["backend_calls"]) == 1
    absent(tmp_path)


def test_atomic_publication_never_replaces_concurrent_empty_destination(evidence, tmp_path, monkeypatch):
    publish = intake._publish_directory
    inode = None

    def occupied(source, destination):
        nonlocal inode
        destination.mkdir()
        inode = destination.stat().st_ino
        publish(source, destination)

    monkeypatch.setattr(intake, "_publish_directory", occupied)
    with pytest.raises(ValueError, match="appeared"):
        prepare(evidence, tmp_path)
    assert (tmp_path / "prepared").stat().st_ino == inode
    assert not list((tmp_path / "prepared").iterdir())
    assert not list(tmp_path.glob(".application-backend-qualification-*"))


@pytest.mark.parametrize("change", ["relative", "symlink-parent", "nul", "unsupported-platform"])
def test_local_path_and_platform_bounds(evidence, tmp_path, monkeypatch, change):
    options = {}
    if change == "relative":
        options["application_assets"] = Path("original")
    elif change == "symlink-parent":
        link = tmp_path / "alias"
        link.symlink_to(evidence["application"].parent, target_is_directory=True)
        options["application_assets"] = link / evidence["application"].name
    elif change == "nul":
        options["output"] = tmp_path / "invalid\0name"
    else:
        monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(ValueError):
        prepare(evidence, tmp_path, **options)
    absent(tmp_path)


def test_backend_payloads_are_streamed_and_never_executed(evidence, tmp_path, monkeypatch):
    read_bytes = Path.read_bytes

    def bounded_reads(path):
        if path.name in {"marty-deploy-linux-amd64", "prepared-selfhost-bundle.zip", "install.sh"}:
            pytest.fail("backend payload was read into memory as a whole")
        return read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", bounded_reads)
    monkeypatch.setattr(application, "_command", lambda *_args: pytest.fail("payload producer was executed"))
    plan = prepare(evidence, tmp_path)
    assert validate(evidence, tmp_path, plan) == plan


def test_profile_has_concrete_pending_provider_runtime_and_separate_website_gates():
    raw, profile = qualification._profile()
    assert qualification.PROFILE_SHA256 == ui.digest(raw)
    observations = {row["id"]: " ".join(row["requires"]) for row in profile["required_observations"]}
    assert len(observations) == 7
    assert "/v1/auth/provider" in observations["provider-capabilities"]
    assert all(name in observations["provider-capabilities"] for name in (
        "provider_name", "registration_supported", "passkey_enrollment_supported", "provider_logout_supported"))
    assert "/v1/auth/passkeys/enroll" in observations["passkey-route-and-capability"]
    assert "missing route never" in observations["passkey-route-and-capability"]
    assert "organizationCreationEnabled: false" in observations["production-runtime-configuration"]
    assert "ORGANIZATION_CREATION_ENABLED" in observations["production-runtime-configuration"]
    assert "GET /v1/organizations/{id}" in observations["organization-api-and-wasm"]
    assert "website-route-contract-matching" in profile["separate_gates"]


def test_existing_composition_rejects_pending_plan_and_independent_application_image(evidence, tmp_path):
    plan = prepare(evidence, tmp_path)
    with pytest.raises(ValueError):
        composition.validate_record(plan)
    # Pure current-composition validation, without any replacement crypto mock.
    pin = {"sha256": "sha256:" + "1" * 64, "bytes": 1}
    record = {"schema": composition.SCHEMA, "producer": copy.deepcopy(PRODUCER), "platform": "linux/amd64",
              "route_contract": plan["application"]["route_contract"],
              "website": {"revision": SOURCE, "source_sha": SOURCE, "producer": copy.deepcopy(PRODUCER),
                          "image": {"uri": "ghcr.io/elevenid/marty-ui-oss/website", "digest": DIGEST, "platform": "linux/amd64"},
                          "release_sha256": pin["sha256"]},
              "application": {"source_sha": SOURCE, "producer": copy.deepcopy(PRODUCER),
                              "image": {"uri": ui.PUBLIC_IMAGE, "digest": DIGEST, "platform": "linux/amd64"},
                              "release_sha256": pin["sha256"], "compatibility_sha256": pin["sha256"]},
              "backend": {"source_sha": SOURCE, "release_tag": BACKEND_TAG, "repository": "ElevenID/marty-ui",
                          "workflow": stable.WORKFLOW, "run_id": 121, "run_attempt": 2,
                          "inventory_sha256": pin["sha256"], "bundle_root": "bundle"},
              "images": evidence["lock"]["services"], "openbao_didcomm_image": evidence["lock"]["openbao_didcomm_image"],
              "production_pages": "public", "kms_provider": "openbao",
              "qualification": {"runtime_tested": False, "billing_journey_tested": False},
              "files": {name: dict(pin) for name in composition.PAYLOAD_NAMES}}
    record["composition_id"] = ui.digest(ui.canonical(record))
    assert composition.validate_record(record) == record
    record["application"]["image"]["uri"] = application.IMAGE
    record["composition_id"] = ui.digest(ui.canonical({key: value for key, value in record.items() if key != "composition_id"}))
    with pytest.raises(ValueError, match="original combined application"):
        composition.validate_record(record)


@pytest.mark.parametrize("missing", ["--application-source-sha", "--backend-source-sha", "--backend-tag", "--plan-id"])
def test_cli_validation_requires_every_external_selection(monkeypatch, tmp_path, missing):
    args = ["validate", "--assets", str(tmp_path), "--application-source-sha", SOURCE,
            "--backend-source-sha", BACKEND_SOURCE, "--backend-tag", BACKEND_TAG,
            "--plan-id", "sha256:" + "1" * 64, "--gh", str(tmp_path / "gh"), "--cosign", str(tmp_path / "cosign")]
    index = args.index(missing)
    del args[index:index + 2]
    monkeypatch.setattr(sys, "argv", ["application_backend_qualification.py", *args])
    with pytest.raises(SystemExit) as error:
        qualification.main()
    assert error.value.code == 2


def test_cli_prepare_and_validate_print_the_exact_review_token(evidence, tmp_path, monkeypatch, capsys):
    # Adapt only the external application verifier runner; both CLI operations
    # still run the complete real implementation and shared trust validators.
    monkeypatch.setattr(qualification, "prepare", functools.partial(qualification.prepare, runner=evidence["runner"]))
    monkeypatch.setattr(qualification, "validate", functools.partial(qualification.validate, runner=evidence["runner"]))
    common = ["--application-source-sha", SOURCE, "--backend-source-sha", BACKEND_SOURCE, "--backend-tag", BACKEND_TAG,
              "--gh", str(tmp_path / "gh"), "--cosign", str(tmp_path / "cosign")]
    monkeypatch.setattr(sys, "argv", ["application_backend_qualification.py", "prepare", *common,
                                    "--application-assets", str(evidence["application"]),
                                    "--backend-assets", str(evidence["backend"]), "--output", str(tmp_path / "prepared")])
    qualification.main()
    first = capsys.readouterr().out.strip()
    value = application.read(tmp_path / "prepared" / qualification.PLAN_NAME)
    assert first == value["plan_id"]
    monkeypatch.setattr(sys, "argv", ["application_backend_qualification.py", "validate", *common,
                                    "--assets", str(tmp_path / "prepared"), "--plan-id", first])
    qualification.main()
    assert capsys.readouterr().out.strip() == first


def test_stream_copy_rejects_a_source_changed_during_read(evidence, tmp_path, monkeypatch):
    fdopen = os.fdopen
    selected = evidence["backend"] / "marty-deploy-linux-amd64"
    selected_inode = selected.stat().st_ino
    changed = False

    class ConcurrentReader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self):
            return self.stream.fileno()

        def read(self, maximum):
            nonlocal changed
            assert 0 < maximum <= qualification.CHUNK_BYTES
            value = self.stream.read(maximum)
            if not changed and os.fstat(self.fileno()).st_ino == selected_inode:
                changed = True
                with selected.open("ab") as output:
                    output.write(b"changed while streaming")
            return value

    monkeypatch.setattr(os, "fdopen", lambda *args, **kwargs: ConcurrentReader(fdopen(*args, **kwargs)))
    with pytest.raises(ValueError, match="changed while reading"):
        prepare(evidence, tmp_path)
    assert changed
    absent(tmp_path)
