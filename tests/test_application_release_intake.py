"""Original package publication intake, with inert transport and verifier fixtures.

The real receipt/asset/certificate/image validators run in these tests. Fixture
verifier responses are never publication evidence and no downloaded code runs.
"""
from __future__ import annotations

import copy
from contextlib import nullcontext
import io
import json
import os
from pathlib import Path
import stat
import struct
import sys
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import application_release as application
import application_release_intake as intake
import ui_release as ui
import web_auth as auth
from tests.test_application_provenance import DIGEST, PRODUCER, SOURCE, verifier_runner
from tests.test_application_release import make_assets


def write(directory, name, value):
    raw = value if isinstance(value, bytes) else ui.canonical(value)
    (directory / name).write_bytes(raw)
    return application.file_record(raw)


class StreamingZip:
    """Match the pinned Actions uploader's streaming data-descriptor format."""
    def __init__(self):
        self.stream = io.BytesIO()

    def write(self, value):
        return self.stream.write(value)

    def flush(self):
        pass


def archive_bytes(files, *, compression=zipfile.ZIP_STORED, streaming=False):
    output = StreamingZip() if streaming else io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        for name, value in files.items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = compression
            archive.writestr(info, value)
    return (output.stream if streaming else output).getvalue()


@pytest.fixture
def publication(tmp_path):
    source = tmp_path / "original"
    release = make_assets(source)
    full = {"schema": "marty.application-source-closure-rehearsal/v4", "status": "passed",
            "plan": {"schema": "marty.application-source-closure-plan/v4",
                     "source": {"commit": SOURCE, "working_tree_dirty": False, "git_status": []}}}
    full_pin = write(source, intake.FULL_BASELINE, full)
    profile = application.read(source / "application-profile-source-closure.json")
    profile["dependency_profile"] = {"name": "application", "baseline_report": {"path": "/inert/full.json", **full_pin}}
    profile_pin = write(source, "application-profile-source-closure.json", profile)
    producer = application.read(source / "application-source-package.json")
    producer["baseline_report"] = profile_pin
    producer_pin = write(source, "application-source-package.json", producer)
    consumer = application.read(source / "application-package-consumer.json")
    consumer["inputs"].update(baseline_report=profile_pin, producer_report=producer_pin)
    consumer_pin = write(source, "application-package-consumer.json", consumer)
    release["build_plan"]["inputs"].update({"application-profile-source-closure.json": profile_pin,
                                          "application-source-package.json": producer_pin,
                                          "application-package-consumer.json": consumer_pin})
    release["build_plan_sha256"] = ui.digest(ui.canonical(release["build_plan"]))
    write(source, intake.PLAN, release["build_plan"])
    write(source, application.RECEIPT, release)
    for name in intake.PROOFS:
        write(source, name, b"original proof fixture; never executed")
    assert application.validate_assets(source, source_sha=SOURCE) == release
    files = {name: (source / name).read_bytes() for name in intake.FILES}
    run = {"id": 231, "run_attempt": 2, "status": "completed", "conclusion": "success",
           "event": "workflow_dispatch", "head_branch": "main", "head_sha": SOURCE,
           "path": ".github/workflows/production-web-release.yml@main",
           "repository": {"id": 1140864197, "full_name": "ElevenID/marty-ui"}}
    artifact = {"id": 55, "name": "application-release-231-2", "expired": False,
                "workflow_run": {"id": 231, "head_sha": SOURCE, "head_branch": "main", "repository_id": 1140864197}}
    for name in ("gh", "cosign"):
        (tmp_path / name).write_bytes(b"pinned verifier fixture; never executed")
    return {"release": release, "files": files, "run": run, "artifact": artifact}


def fetch(publication, tmp_path, *, raw=None, listed=None, run=None, runner=None, **changes):
    raw = archive_bytes(publication["files"]) if raw is None else raw
    metadata = {**publication["artifact"], "size_in_bytes": len(raw), "digest": ui.digest(raw)}
    if listed is None:
        listed = {"total_count": 1, "artifacts": [metadata]}
    if run is None:
        run = publication["run"]
    calls = []

    class Reader:
        def attempt(self):
            calls.append("attempt")
            return run if isinstance(run, str) else json.dumps(run)

        def artifacts(self):
            calls.append("artifacts")
            return listed if isinstance(listed, str) else json.dumps(listed)

        def archive(self, artifact_id, *, maximum):
            calls.append(("archive", artifact_id, maximum))
            assert artifact_id == 55 and maximum == len(raw)
            return raw

    fixture_runner, crypto = verifier_runner() if runner is None else (runner, [])
    options = dict(run_id="231", attempt="2", source_sha=SOURCE, destination=tmp_path / "intake",
                   gh=tmp_path / "gh", cosign=tmp_path / "cosign", reader=Reader(), runner=fixture_runner)
    options.update(changes)
    result = intake.fetch(**options)
    return result, calls, crypto


def absent(tmp_path):
    assert not os.path.lexists(tmp_path / "intake")
    assert list(tmp_path.glob(".application-intake-*")) == []


@pytest.mark.parametrize("compression,streaming", [(zipfile.ZIP_STORED, False), (zipfile.ZIP_DEFLATED, False),
                                                   (zipfile.ZIP_DEFLATED, True)])
def test_intake_preserves_every_original_and_authenticates_both_subjects(publication, tmp_path, monkeypatch, compression, streaming):
    monkeypatch.setattr(intake.proof.auth, "registry_command", lambda *_args, **_kwargs: pytest.fail("public image used private credentials"))
    raw = archive_bytes(publication["files"], compression=compression, streaming=streaming)
    result, calls, crypto = fetch(publication, tmp_path, raw=raw)
    assert result == publication["release"] and result["producer"] == PRODUCER
    assert calls == ["attempt", "artifacts", ("archive", 55, len(raw))]
    directory = tmp_path / "intake"
    assert {path.name: path.read_bytes() for path in directory.iterdir()} == publication["files"]
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in directory.iterdir())
    assert [args[1] for args in crypto] == ["attestation", "verify-blob", "attestation", "verify"]
    assert Path(crypto[0][3]).name == Path(crypto[1][2]).name == application.RECEIPT
    assert crypto[2][3] == "oci://ghcr.io/elevenid/marty-ui-oss/application@" + DIGEST
    assert crypto[3][2] == "ghcr.io/elevenid/marty-ui-oss/application@" + DIGEST
    assert all(result["qualification"][name] is False for name in ("activated", "host_deployment_tested", "oidc_journey_tested"))
    assert list(tmp_path.glob(".application-intake-*")) == []


@pytest.mark.parametrize("field,value", [
    ("status", "in_progress"), ("conclusion", "failure"), ("conclusion", "cancelled"),
    ("event", "pull_request"), ("event", "push"), ("head_branch", "feature"), ("head_sha", "f" * 40),
    ("head_sha", "main"), ("run_attempt", 1), ("run_attempt", True), ("id", 232), ("id", "231"),
    ("path", ".github/workflows/ci.yml"), ("repository", {"full_name": "ElevenID/website", "id": 1459542519}),
    ("repository", {"full_name": "ElevenID/marty-ui", "id": 1}), ("repository", None),
])
def test_wrong_attempt_is_rejected_before_artifact_download(publication, tmp_path, monkeypatch, field, value):
    publication["run"][field] = value
    monkeypatch.setattr(intake, "archive_selection", lambda *_args, **_kwargs: pytest.fail("rejected attempt reached artifacts"))
    with pytest.raises(ValueError):
        fetch(publication, tmp_path)
    absent(tmp_path)


@pytest.mark.parametrize("changes", [
    {"source_sha": "main"}, {"source_sha": ""}, {"source_sha": None}, {"run_id": "0"}, {"attempt": "02"},
    {"repository": "ElevenID/website"}, {"repository": "ElevenID/marty-subscriptions"}, {"repository": "another-owner/marty-ui"},
])
def test_selection_is_closed_before_any_transport(publication, tmp_path, monkeypatch, changes):
    monkeypatch.setattr(intake.proof, "parse_verified_json", lambda *_args: pytest.fail("invalid selection reached metadata"))
    with pytest.raises(ValueError):
        fetch(publication, tmp_path, **changes)
    absent(tmp_path)


@pytest.mark.parametrize("field,value", [
    ("name", "application-release-diagnostics-231-2"), ("name", "application-release-231-1"),
    ("name", "web-application-231-2"), ("name", "application-image-candidate-231-2"), ("expired", True),
    ("expired", 0), ("id", 0), ("id", True), ("size_in_bytes", 0), ("size_in_bytes", intake.MAX_ARCHIVE + 1),
    ("digest", "sha256:" + "9" * 64), ("workflow_run", None),
    ("workflow_run", {"id": 231, "head_sha": SOURCE, "head_branch": "main", "repository_id": 1459542519}),
    ("workflow_run", {"id": 232, "head_sha": SOURCE, "head_branch": "main", "repository_id": 1140864197}),
    ("workflow_run", {"id": 231, "head_sha": "f" * 40, "head_branch": "main", "repository_id": 1140864197}),
])
def test_wrong_artifact_identity_and_bounds_fail_without_output(publication, tmp_path, field, value):
    raw = archive_bytes(publication["files"])
    artifact = {**publication["artifact"], "size_in_bytes": len(raw), "digest": ui.digest(raw), field: value}
    with pytest.raises(ValueError):
        fetch(publication, tmp_path, raw=raw, listed={"total_count": 1, "artifacts": [artifact]})
    absent(tmp_path)


@pytest.mark.parametrize("run,listed", [([], None), ('{"id":231,"id":231}', None),
                                       (None, {"total_count": 2, "artifacts": []}), (None, []),
                                       (None, '{"total_count":1,"total_count":1,"artifacts":[]}')])
def test_metadata_objects_cannot_be_ambiguous(publication, tmp_path, run, listed):
    with pytest.raises(ValueError):
        fetch(publication, tmp_path, run=run, listed=listed)
    absent(tmp_path)


@pytest.mark.parametrize("change", ["source", "run", "attempt"])
def test_valid_receipt_cannot_replace_another_requested_publication(publication, tmp_path, change):
    options = {}
    if change == "source":
        publication["run"]["head_sha"] = publication["artifact"]["workflow_run"]["head_sha"] = "f" * 40
        options["source_sha"] = "f" * 40
    elif change == "run":
        publication["run"]["id"] = publication["artifact"]["workflow_run"]["id"] = 232
        publication["artifact"]["name"] = "application-release-232-2"
        options["run_id"] = "232"
    else:
        publication["run"]["run_attempt"] = 3
        publication["artifact"]["name"] = "application-release-231-3"
        options["attempt"] = "3"
    with pytest.raises(ValueError):
        fetch(publication, tmp_path, runner=lambda _args: pytest.fail("another receipt reached cryptographic verification"), **options)
    absent(tmp_path)


def rewrite_zip(raw, fault):
    with zipfile.ZipFile(io.BytesIO(raw)) as source:
        entries = [(copy.copy(entry), source.read(entry)) for entry in source.infolist()]
    entry, value = entries[0]
    if fault == "duplicate":
        entries[-1] = (copy.copy(entry), value)
    elif fault == "missing":
        entries.pop()
    elif fault in {"extra", "traversal", "absolute", "backslash"}:
        entry.filename = {"extra": "run.py", "traversal": "../application-release.json",
                          "absolute": "/application-release.json", "backslash": "folder\\application-release.json"}[fault]
    elif fault in {"symlink", "fifo", "executable", "world-writable", "directory"}:
        entry.external_attr = {"symlink": stat.S_IFLNK | 0o777, "fifo": stat.S_IFIFO | 0o600,
                               "executable": stat.S_IFREG | 0o700, "world-writable": stat.S_IFREG | 0o666,
                               "directory": stat.S_IFDIR | 0o700}[fault] << 16
    elif fault == "entry-comment":
        entry.comment = b"unselected metadata"
    elif fault == "extra-field":
        entry.extra = b"\x55\x54\x01\x00\x00"
    elif fault == "compression":
        entry.compress_type = zipfile.ZIP_BZIP2
    elif fault == "empty":
        entries[0] = (entry, b"")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for current, data in entries:
            archive.writestr(current, data)
    return output.getvalue()


@pytest.mark.parametrize("fault", ["duplicate", "missing", "extra", "traversal", "absolute", "backslash", "symlink", "fifo",
                                  "executable", "world-writable", "directory", "entry-comment", "extra-field", "compression", "empty"])
def test_archive_members_are_closed_ordinary_and_bounded(publication, tmp_path, fault):
    with pytest.warns(UserWarning) if fault == "duplicate" else nullcontext():
        raw = rewrite_zip(archive_bytes(publication["files"]), fault)
    with pytest.raises(ValueError):
        fetch(publication, tmp_path, raw=raw)
    absent(tmp_path)


@pytest.mark.parametrize("fault", ["crc", "local-name", "encrypted", "strong-encryption", "unsupported-flags", "oversize",
                                  "overlap", "trailing", "prefix", "disk", "member-disk", "nul", "truncated"])
def test_archive_headers_and_actual_crc_cannot_disagree(publication, tmp_path, fault):
    raw = bytearray(archive_bytes(publication["files"]))
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        first, second = archive.infolist()[:2]
        central = archive.start_dir
    if fault == "crc":
        raw[30 + len(first.filename)] ^= 1
    elif fault == "local-name":
        raw[30] ^= 1
    elif fault in {"encrypted", "strong-encryption", "unsupported-flags"}:
        bit = {"encrypted": 1, "strong-encryption": 64, "unsupported-flags": 32}[fault]
        struct.pack_into("<H", raw, central + 8, bit)
        struct.pack_into("<H", raw, 6, bit)
    elif fault == "oversize":
        struct.pack_into("<I", raw, central + 24, application.JSON_LIMIT + 1)
    elif fault == "overlap":
        second_central = central + 46 + len(first.filename)
        struct.pack_into("<I", raw, second_central + 42, 0)
    elif fault == "trailing":
        raw += b"unselected trailing data"
    elif fault == "prefix":
        raw = b"unselected prefix" + raw
    elif fault == "disk":
        struct.pack_into("<H", raw, len(raw) - 18, 1)
    elif fault == "member-disk":
        struct.pack_into("<H", raw, central + 34, 1)
    elif fault == "nul":
        raw[central + 46 + len(first.filename) - 1] = 0
    else:
        raw = raw[:-23]
    with pytest.raises(ValueError):
        fetch(publication, tmp_path, raw=bytes(raw))
    absent(tmp_path)


def test_expanded_archive_total_is_bounded_before_extraction(publication, tmp_path, monkeypatch):
    monkeypatch.setattr(intake, "MAX_EXPANDED", sum(len(value) for value in publication["files"].values()) - 1)
    with pytest.raises(ValueError, match="expanded application"):
        fetch(publication, tmp_path)
    absent(tmp_path)


@pytest.mark.parametrize("name", intake.FILES)
def test_no_original_can_change_while_verifiers_run(publication, tmp_path, name):
    held = None

    def mutate(arguments):
        nonlocal held
        if arguments[1] == "verify-blob":
            held = Path(arguments[2]).parent
        if arguments[1] == "verify":
            with (held / name).open("ab") as stream:
                stream.write(b"\n")

    run, _calls = verifier_runner(on_call=mutate)
    with pytest.raises(ValueError):
        fetch(publication, tmp_path, runner=run)
    absent(tmp_path)


@pytest.mark.parametrize("fault", ["extra-file", "symlink", "file-mode", "removed"])
def test_private_staging_identity_survives_verifier_execution(publication, tmp_path, fault):
    held = None

    def mutate(arguments):
        nonlocal held
        if arguments[1] == "verify-blob":
            held = Path(arguments[2]).parent
        if arguments[1] == "verify":
            path = held / intake.PLAN
            if fault == "extra-file":
                (held / "unexpected").write_bytes(b"unselected")
            elif fault == "symlink":
                path.unlink()
                path.symlink_to(tmp_path / "gh")
            elif fault == "file-mode":
                path.chmod(0o644)
            else:
                path.unlink()

    run, _calls = verifier_runner(on_call=mutate)
    with pytest.raises(ValueError):
        fetch(publication, tmp_path, runner=run)
    absent(tmp_path)


@pytest.mark.parametrize("field,value", [
    ("sourceRepositoryIdentifier", "1459542519"), ("sourceRepositoryDigest", "f" * 40),
    ("runInvocationURI", "https://github.com/ElevenID/marty-ui/actions/runs/231/attempts/1"),
    ("buildSignerURI", "https://github.com/ElevenID/marty-ui/.github/workflows/ci.yml@refs/heads/main"),
    ("runnerEnvironment", "self-hosted"),
])
def test_intake_uses_real_original_certificate_policy(publication, tmp_path, field, value):
    run, _calls = verifier_runner(certificate_change=lambda certificate: certificate.update({field: value}))
    with pytest.raises(ValueError, match="certificate differs"):
        fetch(publication, tmp_path, runner=run)
    absent(tmp_path)


def test_wrong_registry_digest_is_rejected_by_real_image_verifier(publication, tmp_path):
    run, _calls = verifier_runner(image_digest="sha256:" + "f" * 64)
    with pytest.raises(ValueError, match="digest differs"):
        fetch(publication, tmp_path, runner=run)
    absent(tmp_path)


def test_failed_cryptography_never_falls_back_to_structural_acceptance(publication, tmp_path):
    def fail(_arguments):
        raise ValueError("original verifier rejected this fixture")
    with pytest.raises(ValueError, match="original verifier rejected"):
        fetch(publication, tmp_path, runner=fail)
    absent(tmp_path)


@pytest.mark.parametrize("name", [intake.PLAN, intake.FULL_BASELINE, "application-package-consumer.json"])
def test_downloaded_evidence_must_match_its_transitive_signed_pin(publication, tmp_path, name):
    publication["files"][name] += b"\n"
    with pytest.raises(ValueError):
        fetch(publication, tmp_path)
    absent(tmp_path)


@pytest.mark.parametrize("existing", ["file", "directory", "dangling-symlink"])
def test_existing_destination_is_preserved_before_transport(publication, tmp_path, monkeypatch, existing):
    target = tmp_path / "intake"
    if existing == "file":
        target.write_bytes(b"user-owned existing file")
    elif existing == "directory":
        target.mkdir()
        (target / "original").write_bytes(b"user-owned existing directory")
    else:
        target.symlink_to(tmp_path / "missing")
    monkeypatch.setattr(intake.proof, "parse_verified_json", lambda *_args: pytest.fail("existing destination reached metadata"))
    with pytest.raises(ValueError, match="destination already exists"):
        fetch(publication, tmp_path)
    assert os.path.lexists(target)
    if existing == "file":
        assert target.read_bytes() == b"user-owned existing file"
    elif existing == "directory":
        assert (target / "original").read_bytes() == b"user-owned existing directory"
    else:
        assert target.is_symlink()


def test_destination_appearing_during_verification_is_not_replaced(publication, tmp_path):
    def create_destination(arguments):
        if arguments[1] == "verify":
            (tmp_path / "intake").mkdir()
            (tmp_path / "intake/original").write_bytes(b"concurrent user output")
    run, _calls = verifier_runner(on_call=create_destination)
    with pytest.raises(ValueError, match="destination appeared"):
        fetch(publication, tmp_path, runner=run)
    assert list((tmp_path / "intake").iterdir()) == [tmp_path / "intake/original"]
    assert (tmp_path / "intake/original").read_bytes() == b"concurrent user output"
    assert list(tmp_path.glob(".application-intake-*")) == []


def test_empty_destination_racing_the_final_publish_is_never_replaced(publication, tmp_path, monkeypatch):
    publish = intake._publish_directory
    raced = []

    def concurrent_output(source, destination):
        # This happens after the final lexists check. A plain POSIX rename
        # would replace the newly created empty directory.
        destination.mkdir(mode=0o700)
        raced.append(destination.stat().st_ino)
        publish(source, destination)

    monkeypatch.setattr(intake, "_publish_directory", concurrent_output)
    with pytest.raises(ValueError, match="destination appeared"):
        fetch(publication, tmp_path)
    destination = tmp_path / "intake"
    assert destination.stat().st_ino == raced[0] and list(destination.iterdir()) == []
    assert list(tmp_path.glob(".application-intake-*")) == []


def test_missing_no_replace_primitive_has_no_weaker_fallback(publication, tmp_path, monkeypatch):
    monkeypatch.setattr(intake.ctypes, "CDLL", lambda *_args, **_kwargs: object())
    with pytest.raises(ValueError, match="requires renameat2"):
        fetch(publication, tmp_path)
    absent(tmp_path)


@pytest.mark.parametrize("invalid", ["source", "destination"])
def test_native_publish_rejects_nul_paths_without_truncation(tmp_path, invalid):
    source, destination = tmp_path / "source", tmp_path / "destination"
    source.mkdir(mode=0o700)
    inode = source.stat().st_ino
    supplied_source = Path(str(source) + "\0unselected") if invalid == "source" else source
    supplied_destination = Path(str(destination) + "\0unselected") if invalid == "destination" else destination
    with pytest.raises(ValueError, match="NUL bytes"):
        intake._publish_directory(supplied_source, supplied_destination)
    assert source.stat().st_ino == inode and not destination.exists()


@pytest.mark.parametrize("extra", [[], ["--registry-config", "private.json"], ["--commerce-source-sha", "f" * 40],
                                  ["--artifact-name", "anything"], ["--repository", "ElevenID/website"]])
def test_cli_requires_source_without_private_or_arbitrary_artifact_options(tmp_path, monkeypatch, extra):
    arguments = ["application_release_intake.py", "--run-id", "231", "--run-attempt", "2", "--assets", str(tmp_path / "intake"),
                 "--gh", str(tmp_path / "gh"), "--cosign", str(tmp_path / "cosign")]
    if extra:
        arguments.extend(["--source-sha", SOURCE, *extra])
    monkeypatch.setattr(sys, "argv", arguments)
    monkeypatch.setattr(intake, "fetch", lambda **_kwargs: pytest.fail("invalid CLI reached intake"))
    with pytest.raises(SystemExit) as rejected:
        intake.main()
    assert rejected.value.code == 2


def test_cli_forwards_only_the_explicit_public_selection(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(intake, "fetch", lambda **kwargs: calls.append(kwargs))
    monkeypatch.setattr(sys, "argv", ["application_release_intake.py", "--run-id", "231", "--run-attempt", "2",
                                     "--source-sha", SOURCE, "--assets", str(tmp_path / "intake"), "--gh", str(tmp_path / "gh"),
                                     "--cosign", str(tmp_path / "cosign"), "--github-token-env", "GITHUB_TOKEN"])
    intake.main()
    assert calls == [dict(repository="ElevenID/marty-ui", run_id="231", attempt="2", source_sha=SOURCE,
                          destination=tmp_path / "intake", gh=tmp_path / "gh", cosign=tmp_path / "cosign",
                          github_token_env="GITHUB_TOKEN")]
