"""Record production and admission failures; synthetic verifier output is not crypto proof."""
import copy
import json
import sys
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_release as release
import installer_acceptance as acceptance


def test_inventory_cli_produces_bound_release_input_and_refuses_replacement(prepared, tmp_path):
    directory, args = prepared
    model = tmp_path / "compose.json"
    model.write_text(json.dumps({"services": {"gateway": {}}}), encoding="utf-8")
    output = tmp_path / "installer-inventory.json"
    command = [sys.executable, str(Path(release.__file__)), "inventory",
               "--artifacts", str(directory), "--compose-model", str(model),
               "--source-sha", args["source_sha"], "--release-tag", args["release_tag"],
               "--build-run-id", "42", "--build-run-attempt", "1", "--output", str(output)]
    result = subprocess.run(command, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    original = output.read_bytes()
    assert release.decode(original) == release.inventory(directory, **args)
    assert subprocess.run(command, capture_output=True, timeout=30).returncode != 0
    assert output.read_bytes() == original
    output.unlink()
    model.write_text('{"services":{"foreign":{}}}', encoding="utf-8")
    assert subprocess.run(command, capture_output=True, timeout=30).returncode != 0
    assert not output.exists()
    model.write_text('{"services":{"gateway":{},"gateway":{}}}', encoding="utf-8")
    assert subprocess.run(command, capture_output=True, timeout=30).returncode != 0
    assert not output.exists()


@pytest.mark.parametrize("fault", [None, "bytes", "image", "run", "attempt", "extra"])
def test_release_rechecks_installer_inventory_against_published_bytes(prepared, fault):
    directory, args = prepared
    record = release.inventory(directory, **args)
    if fault == "image":
        record["images"]["gateway"] = "ghcr.io/elevenid/foreign@sha256:" + "f" * 64
    elif fault == "run":
        record["build_run_id"] += 1
    elif fault == "attempt":
        record["build_run_attempt"] += 1
    (directory / "installer-inventory.json").write_bytes(release.encode(record))
    if fault == "bytes":
        path = directory / "install.sh"
        path.write_bytes(b"x" * path.stat().st_size)
    if fault == "extra":
        # Full release has other assets; their allowlist is the publisher's job.
        (directory / "stack-manifest.json").write_bytes(b"other signed release asset")
    options = {key: value for key, value in args.items() if key != "expected_services"}
    if fault in (None, "extra"):
        assert release.verify_inventory_assets(directory, **options) == record
    else:
        with pytest.raises(ValueError):
            release.verify_inventory_assets(directory, **options)


def iso_timestamp(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


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


@pytest.fixture
def renewal(evidence):
    inv, options = evidence
    admitted = release.encode(release.admission(inv, **options))
    prior = release.channel(admitted, **channel_args())
    now = prior["issued_at"] + 3600
    path, bundle, run = options["reports"]["published"]
    report = json.loads(path.read_bytes())
    report["run_id"] = 103
    report["harness_source_sha"] = "d" * 40
    path.write_bytes(release.encode(report))
    run.update(id=103, head_sha="d" * 40, run_started_at=iso_timestamp(now - 600),
               updated_at=iso_timestamp(now - 60))
    args = dict(previous_bytes=release.encode(prior), published_report=(path, bundle, run),
                gh=options["gh"], promotion_source_sha="e" * 40, promotion_run_id=400,
                promotion_run_attempt=1, now=now, runner=options["runner"])
    return admitted, inv, args


def test_renewal_preserves_exact_release_and_links_prior_record(renewal):
    admitted, inv, args = renewal
    prior = release.decode(args["previous_bytes"])
    renewed = release.renew_channel(admitted, inv, **args)
    for field in ("channel", "release_tag", "source_sha", "admission_sha256"):
        assert renewed[field] == prior[field]
    assert renewed["generation"] == prior["generation"] + 1
    assert renewed["previous_sha256"] == release.digest(args["previous_bytes"])
    assert renewed["expires_at"] > prior["expires_at"]
    assert renewed["promotion_source_sha"] == "e" * 40


def test_renewal_can_recover_expired_channel_with_fresh_replay(renewal):
    admitted, inv, args = renewal
    prior = release.decode(args["previous_bytes"])
    prior["expires_at"] = prior["issued_at"] + 10
    args["previous_bytes"] = release.encode(prior)
    assert release.renew_channel(admitted, inv, **args)["expires_at"] > args["now"]


@pytest.mark.parametrize("field,value", [
    ("run_started_at", None), ("updated_at", None),
    ("run_started_at", "not-time"), ("updated_at", "2026-10-25T10:00:00"),
    ("run_started_at", "old"), ("updated_at", "old"),
    ("run_started_at", "future"), ("updated_at", "future"),
    ("run_started_at", "prior"), ("updated_at", "reversed"),
])
def test_renewal_refuses_missing_stale_future_or_reversed_run_times(renewal, field, value):
    admitted, inv, args = renewal
    run = args["published_report"][2]
    if value == "old":
        value = iso_timestamp(args["now"] - 86401)
    elif value == "future":
        value = iso_timestamp(args["now"] + 1)
    elif value == "prior":
        value = iso_timestamp(release.decode(args["previous_bytes"])["issued_at"])
    elif value == "reversed":
        value = iso_timestamp(args["now"] - 601)
    run[field] = value
    with pytest.raises(ValueError, match="renewal"):
        release.renew_channel(admitted, inv, **args)


@pytest.mark.parametrize("mode", ["admission-bytes", "inventory-bytes", "release", "source", "build", "operator",
                                  "failed-case", "failed-run", "wrong-attempt", "crypto", "shorter-expiry"])
def test_renewal_rejects_changed_identity_or_unqualified_replay(renewal, mode):
    admitted, inv, args = renewal
    if mode == "admission-bytes":
        admitted += b" "
    elif mode == "inventory-bytes":
        inv += b" "
    elif mode in ("release", "source", "build", "operator"):
        changed = release.decode(admitted)
        key, value = {"release": ("release_tag", "v1.2.3-nightly.20261026.43"),
                      "source": ("source_sha", "f" * 40), "build": ("build_run_id", 43),
                      "operator": ("operator_sha256", "f" * 64)}[mode]
        changed[key] = value
        admitted = release.encode(changed)
        prior = release.decode(args["previous_bytes"])
        prior["admission_sha256"] = release.digest(admitted)
        args["previous_bytes"] = release.encode(prior)
    elif mode == "crypto":
        args["runner"] = lambda _: "[]"
    elif mode == "shorter-expiry":
        args["lifetime"] = 100
    else:
        path, _, run = args["published_report"]
        if mode == "failed-run":
            run["conclusion"] = "failure"
        elif mode == "wrong-attempt":
            run["run_attempt"] = 2
        else:
            report = json.loads(path.read_bytes())
            report["cases"]["owned-cleanup"] = "failed"
            path.write_bytes(release.encode(report))
    with pytest.raises(ValueError):
        release.renew_channel(admitted, inv, **args)


def test_renewal_replay_cannot_renew_a_second_time(renewal):
    admitted, inv, args = renewal
    renewed = release.renew_channel(admitted, inv, **args)
    args["previous_bytes"] = release.encode(renewed)
    args["now"] += 600
    with pytest.raises(ValueError, match="predates"):
        release.renew_channel(admitted, inv, **args)


@pytest.mark.parametrize("age,accepted", [(86400, True), (86401, False)])
def test_renewal_24_hour_boundary_independent_of_prior_issue_time(renewal, age, accepted):
    admitted, inv, args = renewal
    prior = release.decode(args["previous_bytes"])
    prior["issued_at"] = args["now"] - 100000
    prior["expires_at"] = prior["issued_at"] + 604800
    args["previous_bytes"] = release.encode(prior)
    args["published_report"][2]["run_started_at"] = iso_timestamp(args["now"] - age)
    if accepted:
        assert release.renew_channel(admitted, inv, **args)["generation"] == 2
    else:
        with pytest.raises(ValueError, match="stale"):
            release.renew_channel(admitted, inv, **args)
