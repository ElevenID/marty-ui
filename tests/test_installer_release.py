"""Record production and admission failures; synthetic verifier output is not crypto proof."""
import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_release as release
import installer_acceptance as acceptance


@pytest.fixture
def prepared(tmp_path):
    directory = tmp_path / "assets"
    directory.mkdir(mode=0o700)
    tag = "v1.2.3-nightly.20261025.42"
    for name in release.ARTIFACTS:
        (directory / name).write_bytes(b"actual fixture artifact " + name.encode())
    lock = dict(schema="marty.selfhost-image-lock/v1", release="marty-ui@" + tag[1:],
                services={"gateway": "ghcr.io/elevenid/service@sha256:" + "a" * 64},
                openbao_didcomm_image="ghcr.io/elevenid/plugin@sha256:" + "b" * 64)
    (directory / "prepared-selfhost-images.json").write_bytes(release.encode(lock))
    args = dict(source_sha="a" * 40, release_tag=tag, build_run_id=42,
                build_run_attempt=1, expected_services={"gateway"})
    return directory, args


@pytest.fixture
def evidence(prepared, tmp_path):
    directory, args = prepared
    inventory_bytes = release.encode(release.inventory(directory, **args))
    private = tmp_path / "evidence"
    private.mkdir(mode=0o700)
    gh = private / "gh"
    gh.write_bytes(b"mock pinned tool")
    reports = {}
    for index, phase in enumerate(("staged", "published"), 101):
        report = dict(schema=acceptance.SCHEMA, repository=release.REPOSITORY,
                      source_sha=args["source_sha"], harness_source_sha=args["source_sha"],
                      source_ref="refs/heads/main", release_tag=args["release_tag"],
                      phase=phase, platform="linux/amd64", inventory_sha256="sha256:" + release.digest(inventory_bytes),
                      workflow=acceptance.WORKFLOW, run_id=index, run_attempt=1,
                      cases=dict.fromkeys(acceptance.CASES, "passed"),
                      host=dict(docker_version="28.0.0", compose_version="2.39.0", memory_bytes=1,
                                disk_free_bytes=1, image_cache_empty=True, source_available=False,
                                development_tools_available=False, credentials_available=False, tls_errors_ignored=False),
                      cleanup=dict(owned_containers_remaining=0, owned_networks_remaining=0,
                                   owned_volumes_remaining=0, recovery_retention_verified=True))
        path = private / (phase + ".json")
        path.write_bytes(release.encode(report))
        bundle = private / (phase + ".bundle")
        bundle.write_bytes(b"mock, not genuine cryptographic evidence")
        run = dict(id=index, run_attempt=1, path=acceptance.WORKFLOW, head_sha=args["source_sha"],
                   head_branch="main", event="workflow_dispatch", status="completed", conclusion="success",
                   repository={"full_name": release.REPOSITORY})
        reports[phase] = path, bundle, run

    def runner(argv):
        path = Path(argv[3])
        report = json.loads(path.read_bytes())
        certificate = dict(issuer=release.provenance.ISSUER, runnerEnvironment="github-hosted",
                           sourceRepositoryURI="https://github.com/ElevenID/marty-ui",
                           sourceRepositoryIdentifier="1140864197", sourceRepositoryDigest=report["harness_source_sha"],
                           sourceRepositoryRef="refs/heads/main",
                           buildSignerURI=f"https://github.com/ElevenID/marty-ui/{acceptance.WORKFLOW}@refs/heads/main",
                           runInvocationURI=f"https://github.com/ElevenID/marty-ui/actions/runs/{report['run_id']}/attempts/1")
        return json.dumps([{"attestation": {}, "verificationResult": {"signature": {"certificate": certificate}}}])
    options = dict(reports=reports, gh=gh, promotion_source_sha="b" * 40,
                   promotion_run_id=200, promotion_run_attempt=1, runner=runner)
    return inventory_bytes, options


def test_inventory_hashes_actual_bytes_and_complete_images(prepared):
    directory, args = prepared
    record = release.inventory(directory, **args)
    release.validate_inventory(record)
    for entry in record["artifacts"]:
        data = (directory / entry["name"]).read_bytes()
        assert entry["sha256"] == release.digest(data)
        assert entry["size"] == len(data)
    assert set(record["images"]) == {"gateway", "openbao_didcomm_image"}


@pytest.mark.parametrize("name", sorted(release.ARTIFACTS))
def test_inventory_refuses_oversize_artifact_before_hashing(prepared, monkeypatch, name):
    directory, args = prepared
    # Exercise the producer's real byte-size guard without allocating hundreds
    # of MiB merely to test rejection. The public boundary is tested below.
    monkeypatch.setitem(release.ARTIFACT_MAX_BYTES, name, 32)
    (directory / name).write_bytes(b"x" * 33)
    original = release.hashlib.file_digest

    def no_oversize_hash(stream, algorithm):
        assert Path(stream.name).name != name, "oversized artifact was read"
        return original(stream, algorithm)

    monkeypatch.setattr(release.hashlib, "file_digest", no_oversize_hash)
    with pytest.raises(ValueError, match="artifact size"):
        release.inventory(directory, **args)


@pytest.mark.parametrize("name,maximum", [
    ("install.sh", 65536),
    ("marty-deploy-linux-amd64", 536870912),
    ("prepared-selfhost-bundle.zip", 268435456),
    ("prepared-selfhost-images.json", 65536),
])
def test_inventory_consumer_size_boundaries(prepared, name, maximum):
    directory, args = prepared
    record = release.inventory(directory, **args)
    entry = next(item for item in record["artifacts"] if item["name"] == name)
    entry["size"] = maximum
    release.validate_inventory(record)
    entry["size"] = maximum + 1
    with pytest.raises(ValueError, match="artifact exceeds limit"):
        release.validate_inventory(record)
    entry["size"] = 0
    with pytest.raises(ValueError):
        release.validate_inventory(record)


@pytest.mark.parametrize("mode", ["extra", "missing", "empty", "wrong-services", "unpinned", "wrong-release"])
def test_invalid_artifact_directory_or_lock_refused(prepared, mode):
    directory, args = prepared
    if mode == "extra":
        (directory / "surprise").write_text("x")
    elif mode == "missing":
        (directory / "install.sh").unlink()
    elif mode == "empty":
        (directory / "install.sh").write_bytes(b"")
    elif mode == "wrong-services":
        args["expected_services"].add("missing")
    else:
        path = directory / "prepared-selfhost-images.json"
        lock = json.loads(path.read_bytes())
        if mode == "unpinned":
            lock["services"]["gateway"] = "ghcr.io/example:latest"
        else:
            lock["release"] = "marty-ui@1.2.2"
        path.write_bytes(release.encode(lock))
    with pytest.raises(ValueError):
        release.inventory(directory, **args)


def test_admission_requires_both_verified_phases_and_separate_promotion_source(evidence):
    inventory_bytes, options = evidence
    accepted = release.admission(inventory_bytes, **options)
    release.validate_admission(accepted)
    assert accepted["source_sha"] == "a" * 40
    assert accepted["promotion_source_sha"] == "b" * 40
    assert accepted["inventory_sha256"] == release.digest(inventory_bytes)
    assert accepted["acceptance"]["published"]["run_id"] == 102


def test_later_main_harness_is_bound_separately_from_tested_release(evidence):
    inventory_bytes, options = evidence
    for path, _, run in options["reports"].values():
        report = json.loads(path.read_bytes())
        report["harness_source_sha"] = "d" * 40
        run["head_sha"] = "d" * 40
        path.write_bytes(release.encode(report))
    accepted = release.admission(inventory_bytes, **options)
    assert accepted["source_sha"] == "a" * 40


def test_harness_certificate_cannot_claim_another_source(evidence):
    inventory_bytes, options = evidence
    original = options["runner"]
    def wrong_source(argv):
        result = json.loads(original(argv))
        result[0]["verificationResult"]["signature"]["certificate"]["sourceRepositoryDigest"] = "e" * 40
        return json.dumps(result)
    options["runner"] = wrong_source
    with pytest.raises(ValueError, match="identity"):
        release.admission(inventory_bytes, **options)


@pytest.mark.parametrize("mode", ["missing-phase", "failed-case", "wrong-run", "wrong-inventory", "bad-crypto"])
def test_admission_refuses_unqualified_evidence(evidence, mode):
    inventory_bytes, options = evidence
    if mode == "missing-phase":
        options["reports"].pop("published")
    elif mode == "bad-crypto":
        options["runner"] = lambda _: "[]"
    else:
        path, _, run = options["reports"]["published"]
        if mode == "wrong-run":
            run["run_attempt"] = 2
        else:
            report = json.loads(path.read_bytes())
            if mode == "failed-case":
                report["cases"]["owned-cleanup"] = "failed"
            else:
                report["inventory_sha256"] = "sha256:" + "f" * 64
            path.write_bytes(release.encode(report))
    with pytest.raises(ValueError):
        release.admission(inventory_bytes, **options)


def channel_args():
    return dict(channel_name="nightly", previous_bytes=None, promotion_source_sha="c" * 40,
                promotion_run_id=300, promotion_run_attempt=2, now=1000000)


def test_channel_sequence_generation_and_exact_previous_byte_hash(evidence):
    inv, options = evidence
    accepted = release.admission(inv, **options)
    prior = release.channel(release.encode(accepted), **channel_args())
    prior_bytes = release.encode(prior)
    accepted["release_tag"] = "v1.2.3-nightly.20261026.43"
    next_record = release.channel(release.encode(accepted), **{**channel_args(), "previous_bytes": prior_bytes})
    assert next_record["generation"] == 2
    assert next_record["previous_sha256"] == release.digest(prior_bytes)
    assert next_record["promotion_source_sha"] == "c" * 40


@pytest.mark.parametrize("mode", ["same", "older", "tier", "expired", "excess-lifetime", "duplicate", "unaccepted"])
def test_channel_rejects_stale_or_invalid_promotion(evidence, mode):
    inv, options = evidence
    accepted = release.admission(inv, **options)
    args = channel_args()
    if mode in ("same", "older"):
        args["previous_bytes"] = release.encode(release.channel(release.encode(accepted), **args))
        if mode == "older":
            accepted["release_tag"] = "v1.2.3-nightly.20261024.41"
    elif mode == "tier":
        args["channel_name"] = "stable"
    elif mode == "expired":
        args["lifetime"] = 0
    elif mode == "excess-lifetime":
        args["lifetime"] = 604801
    elif mode == "unaccepted":
        accepted["status"] = "failed"
    raw = release.encode(accepted)
    if mode == "duplicate":
        raw = raw.replace(b'{', b'{"schema":"bad",', 1)
    with pytest.raises(ValueError):
        release.channel(raw, **args)


@pytest.mark.parametrize("mutation", ["duplicate-artifact", "extra", "wrong-platform", "unpinned"])
def test_closed_inventory_validator(prepared, mutation):
    directory, args = prepared
    record = copy.deepcopy(release.inventory(directory, **args))
    if mutation == "duplicate-artifact":
        record["artifacts"][0] = record["artifacts"][1]
    elif mutation == "extra":
        record["unexpected"] = True
    elif mutation == "wrong-platform":
        record["platform"] = "linux/arm64"
    else:
        record["images"]["gateway"] = "image:latest"
    with pytest.raises(ValueError):
        release.validate_inventory(record)
