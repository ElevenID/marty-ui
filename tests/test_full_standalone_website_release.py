"""Full standalone source keeps the original private producer and product boundary."""
from __future__ import annotations

import json
from pathlib import Path
import zipfile

import pytest

from tests.test_package_web_composition import (
    candidate, full_standalone_website, write_json, SOURCE, WEBSITE_SOURCE, PRIVATE,
)
from tests.test_website_provenance import verified
from tests.test_deploy_website import Host
import deploy_website as deploy
import package_web_composition as composition
import ui_release as ui
import website_provenance as proof
import website_release as web

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def full_release():
    return web.read(ROOT / "tests/fixtures/standalone-website-release-v4.json")["release"]


def test_full_fixture_matches_original_javascript_contract_without_reading_application_sources(full_release, monkeypatch):
    monkeypatch.setattr(web, "console_dependencies", lambda *_: pytest.fail("standalone imported application dependencies"))
    plan = full_release["build_plan"]
    assert plan == web.full_standalone_plan(plan["source_sha"], commerce_source_sha=plan["commerce_extension"]["source_sha"],
                                          input_sha256=plan["input_sha256"], output=plan["output"],
                                          route_contract=plan["route_contract"])
    assert full_release == web.full_standalone_record(plan, metadata=web.image_metadata(plan),
                                                     digest=full_release["image"]["digest"],
                                                     run_id=full_release["producer"]["run_id"], run_attempt="2")
    assert full_release["build_plan_sha256"] == "sha256:fb9a0fe427f40dc89a700e1b9ac4ac1bffe0f116bc53348465d54755f7185831"
    assert full_release["source_sha"] != full_release["producer"]["source_sha"]
    assert full_release["producer"]["source_sha"] == full_release["commerce_extension"]["source_sha"]
    assert plan["package_manager"] == "bun@1.4.4" and plan["dependency_lock"] == "bun.lock"


@pytest.mark.parametrize("path,value", [
    (("repository",), ui.REPOSITORY), (("production_pages",), "public"), (("commerce_extension",), None),
    (("commerce_extension", "repository"), web.STANDALONE_REPOSITORY),
    (("commerce_extension", "source_sha"), "main"), (("workflow",), web.STANDALONE_WORKFLOW),
    (("image",), web.STANDALONE_IMAGE), (("revision",), "a" * 40),
    (("dockerfile",), "Dockerfile.website"), (("platform",), "linux/arm64"),
    (("build_kind",), "source"), (("dependency_lock",), "package-lock.json"),
    (("package_manager",), "npm@11"), (("input_sha256", "bun.lock"), "not-a-digest"),
    (("output", "directory"), "../private"), (("output", "file_count"), True),
    (("output", "file_count"), 10001), (("output", "total_bytes"), 512 * 1024 * 1024 + 1),
    (("route_contract", "version"), True), (("build_args", "COMMERCE_SOURCE_SHA"), "a" * 40),
    (("build_args", "WEBSITE_SOURCE_SHA"), "b" * 40), (("build_args", "WEBSITE_REVISION"), "a" * 40),
])
def test_full_plan_rejects_public_authority_and_inconsistent_or_unbounded_inputs(full_release, path, value):
    plan = full_release["build_plan"]
    target = plan
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError):
        web.validate_plan(plan)


@pytest.mark.parametrize("field", ["schema", "producer", "image_metadata"])
@pytest.mark.parametrize("version", [1, 2, 3])
def test_full_receipt_cannot_mix_historical_envelopes(full_release, field, version):
    if field == "schema":
        full_release[field] = "marty.website-release/v" + str(version)
    elif field == "producer":
        full_release[field] = web.standalone_producer(full_release["source_sha"], "1234567890", "2")
    else:
        full_release[field]["schema"] = "marty.website-image/v" + str(version)
    with pytest.raises(ValueError):
        web.validate_release(full_release)


@pytest.mark.parametrize("path,value", [
    (("producer", "source_sha"), "a" * 40), (("producer", "workflow"), web.STANDALONE_WORKFLOW),
    (("producer", "ref"), "refs/heads/topic"), (("producer", "run_id"), 1234567890),
    (("producer", "run_attempt"), "0"), (("production_pages",), "public"),
    (("source_sha",), "b" * 40), (("commerce_extension", "source_sha"), "a" * 40),
    (("image", "uri"), web.STANDALONE_IMAGE), (("image_metadata", "repository"), ui.COMMERCE_REPOSITORY),
    (("image_metadata", "route_contract", "version"), True), (("build_plan_sha256",), "sha256:" + "0" * 64),
    (("qualification",), {"runtime_tested": True}),
])
def test_full_receipt_rejects_substituted_identity_or_unearned_runtime_claim(full_release, path, value):
    target = full_release
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError):
        web.validate_release(full_release)


def test_full_expected_source_selection_checks_both_independent_sources(full_release):
    source, private = full_release["source_sha"], full_release["commerce_extension"]["source_sha"]
    assert web.validate_release(full_release, source_sha=source, commerce_source_sha=private) == full_release
    for options in ({"source_sha": source}, {"source_sha": "c" * 40, "commerce_source_sha": private},
                    {"source_sha": source, "commerce_source_sha": "c" * 40}, {"commerce_source_sha": "c" * 40}):
        with pytest.raises(ValueError):
            web.validate_release(full_release, **options)


def test_historical_public_receipts_stay_public_and_cannot_gain_full_authority():
    for version in (2, 3):
        release = web.read(ROOT / f"tests/fixtures/standalone-website-release-v{version}.json")["release"]
        assert web.validate_release(release) == release
        release["schema"] = web.STANDALONE_FULL_RELEASE_SCHEMA
        with pytest.raises(ValueError):
            web.validate_release(release)


def test_full_original_hosted_proofs_remain_valid_with_role_aware_private_authority(full_release, tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    for name in (*composition.WEBSITE_FILES, "gh", "cosign"):
        (tmp_path / name).write_bytes(b"test proof bytes; verifier calls are simulated")
        (tmp_path / name).chmod(0o600)
    write_json(tmp_path / "website-release.json", full_release)
    write_json(tmp_path / "web-surface-routes.json", web.read(ROOT / web.ROUTE_PATH))
    calls = []
    registry = tmp_path / "operator-config.json"
    producer = full_release["producer"]

    def run(args):
        calls.append(("subject", args))
        return json.dumps(verified(producer)) if args[1] == "attestation" else "verified"

    def private_run(args, *, config):
        assert config == registry
        calls.append(("image", args))
        if args[1] == "attestation":
            return json.dumps(verified(producer))
        return json.dumps([{"critical": {"image": {"docker-manifest-digest": full_release["image"]["digest"]}}}])

    monkeypatch.setattr(proof.auth, "registry_command", private_run)
    result = proof.verify_website(tmp_path, gh=tmp_path / "gh", cosign=tmp_path / "cosign",
                                  registry_config=registry, runner=run)
    assert result == full_release and [kind for kind, _ in calls] == ["subject", "subject", "image", "image"]
    for _, args in (calls[0], calls[2]):
        assert args[args.index("--source-digest") + 1] == producer["source_sha"]
        assert args[args.index("--repo") + 1] == ui.COMMERCE_REPOSITORY
        assert "--deny-self-hosted-runners" not in args
        assert "--no-public-good" in args
    calls.clear()
    with pytest.raises(ValueError, match="requires --registry-config"):
        proof.verify_website(tmp_path, gh=tmp_path / "gh", cosign=tmp_path / "cosign", runner=run)
    assert all(kind == "subject" for kind, _ in calls)
    calls.clear()

    def unapproved_local(args):
        calls.append(("subject", args))
        value = verified(producer)
        value[0]["verificationResult"]["signature"]["certificate"]["runnerEnvironment"] = "self-hosted"
        return json.dumps(value)

    # Removing the blanket CLI flag never authorizes an unbound local signer.
    with pytest.raises(ValueError, match="private signed release authorization is invalid"):
        proof.verify_website(tmp_path, gh=tmp_path / "gh", cosign=tmp_path / "cosign",
                             registry_config=registry, runner=unapproved_local)
    assert len(calls) == 1 and calls[0][1][1] == "attestation"


def full_candidate(candidate):
    kwargs, calls, lock, model = candidate
    source = kwargs["application_assets"].parent / "source"
    options = {"production_pages": "full", "commerce_source_sha": PRIVATE}
    plan = ui.production_plan(source, SOURCE, **options)
    metadata = {"component": "ui", "release_version": plan["version"], "marty_ui_sha": SOURCE,
                "audience": "production", "ui_variant": "public", "production_pages": "full",
                "commerce_extension": ui.commerce_identity("full", PRIVATE)}
    application = ui.production_release(source, plan, source_sha=SOURCE, metadata=metadata,
                                        image_digest="sha256:" + "d" * 64, run_id="123", run_attempt="1", **options)
    path = kwargs["application_assets"] / "production-web-release.json"
    write_json(path, application)
    write_json(kwargs["application_assets"] / "application-web-compatibility.json",
               web.compatibility_record(application, web.application_marker(source, SOURCE), path.read_bytes()))
    website = full_standalone_website(WEBSITE_SOURCE, web.read(source / web.ROUTE_PATH))
    write_json(kwargs["website_assets"] / "website-release.json", website)
    kwargs["producer"] = web.producer(SOURCE, ui.commerce_identity("full", PRIVATE), "126", "1")
    return kwargs, calls, lock, application, website


def test_full_standalone_composition_preserves_original_full_application_and_backend_bytes(candidate):
    kwargs, calls, lock, application, website = full_candidate(candidate)
    result = composition.package(**kwargs)
    assert result["production_pages"] == "full"
    assert result["website"]["producer"] == website["producer"]
    assert result["website"]["source_sha"] == WEBSITE_SOURCE
    assert result["application"]["image"] == application["image"]
    assert result["images"]["ui"] == application["image"]["uri"] + "@" + application["image"]["digest"]
    assert result["images"]["gateway"] == lock["services"]["gateway"]
    assert result["openbao_didcomm_image"] == lock["openbao_didcomm_image"]
    assert result["qualification"] == {"runtime_tested": False, "billing_journey_tested": False}
    with zipfile.ZipFile(kwargs["output"] / "web-composition.zip") as archive:
        for prefix, names in (("application", composition.APPLICATION_FILES), ("backend", composition.BACKEND_FILES)):
            for name in names:
                assert archive.read(f"web-composition/{prefix}/{name}") == (kwargs[prefix + "_assets"] / name).read_bytes()
    for name in ("web-composition.json", "web-composition.zip"):
        for suffix in (".sigstore.json", ".provenance.jsonl"):
            (kwargs["output"] / (name + suffix)).write_bytes(b"test proof")
    calls.clear()
    with composition.verified_package(kwargs["output"], gh=kwargs["gh"], cosign=kwargs["cosign"]) as (record, _):
        assert record == result
        assert [kind for kind, *_ in calls] == ["subject", "subject", "subject", "image", "subject", "subject", "image", "backend"]


def test_full_standalone_cannot_compose_with_public_application(candidate):
    kwargs, _, _, _ = candidate
    routes = web.read(kwargs["website_assets"] / "web-surface-routes.json")
    write_json(kwargs["website_assets"] / "website-release.json", full_standalone_website(WEBSITE_SOURCE, routes))
    with pytest.raises(ValueError, match="audiences differ"):
        composition.package(**kwargs)
    assert not kwargs["output"].exists()


@pytest.mark.parametrize("full_first", [False, True])
def test_full_receipt_transition_retains_legacy_rollback_and_exact_product(candidate, tmp_path, full_first):
    kwargs, calls, _, application, full = full_candidate(candidate)
    source = kwargs["application_assets"].parent / "source"
    legacy_source = "d" * 40
    options = {"production_pages": "full", "commerce_source_sha": PRIVATE}
    legacy_plan = web.plan(source, legacy_source, **options)
    legacy = web.record(source, legacy_plan, source_sha=legacy_source, metadata=web.image_metadata(legacy_plan),
                        digest="sha256:" + "e" * 64, run_id="201", run_attempt="1", **options)
    releases = (full, legacy) if full_first else (legacy, full)
    verifiers = {key: kwargs[key] for key in ("gh", "cosign")}
    states, original_bytes = [], {}
    host = None
    for index, release in enumerate(releases):
        write_json(kwargs["website_assets"] / "website-release.json", release)
        original_bytes[release["revision"]] = (kwargs["website_assets"] / "website-release.json").read_bytes()
        selected = {**kwargs, "output": tmp_path / f"full-output-{index}"}
        manifest = composition.package(**selected)
        for name in ("web-composition.json", "web-composition.zip"):
            for suffix in (".sigstore.json", ".provenance.jsonl"):
                (selected["output"] / (name + suffix)).write_bytes(b"test proof")
        if host is None:
            host = Host(tmp_path, manifest, candidate[3])
            before, _ = host.snapshot()
        states.append(deploy.apply(host, selected["output"], **verifiers))
    assert states[1]["active"] != states[0]["active"]
    assert states[0]["product"] == states[1]["product"] == before
    assert before["images"]["ui"] == application["image"]["uri"] + "@" + application["image"]["digest"]
    calls.clear()
    rolled = deploy.rollback(host, **verifiers)
    assert rolled["active"] == states[0]["active"] and rolled["product"] == before
    assert all(call[2] == releases[0]["producer"] for call in calls)
    assert deploy.rollback(host, **verifiers)["active"] == states[1]["active"]
    assert deploy.start_current(host, **verifiers) == states[1]
    assert host.snapshot()[0] == before
    for revision, raw in original_bytes.items():
        assert (host.directory / "receipts" / revision / "website-release.json").read_bytes() == raw
