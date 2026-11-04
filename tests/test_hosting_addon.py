"""Optional connector ownership, immutable identity and package closure."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import hosting_addon as addon
import nightly_release
import publish_nightly_release
import publish_hosting_addon

TAG = "v1.2.3-nightly.20261031.123"
IMAGE = addon.IMAGE + "@sha256:" + "a" * 64


@pytest.fixture(params=[TAG, "v1.2.3"], ids=["nightly", "stable"])
def packaged(tmp_path, request):
    source = tmp_path / "source"
    source.mkdir()
    item = addon.policy(ROOT)
    for name in [addon.POLICY, item["compose_source"], item["dockerfile"], *item["source_files"].values()]:
        destination = source / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "-c", "user.name=CI", "-c", "user.email=ci@example.invalid",
                    "commit", "-qm", "connector fixture"], check=True)
    sha = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    sbom = tmp_path / "sbom.json"
    sbom.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6"}\n')
    output = tmp_path / "addon"
    value = addon.package(source, output, source_sha=sha, release_tag=request.param,
        build_run_id=1234, build_run_attempt=2, image=IMAGE, sbom=sbom)
    return source, output, value, sbom


def validate(output: Path, value: dict) -> dict:
    return addon.validate_assets(output, **{name: value[name] for name in
        ("source_sha", "release_tag", "build_run_id", "build_run_attempt")})


def test_core_release_has_no_connector_requirement():
    assert "cloudflared_wrapper" not in nightly_release.IMAGE_COORDINATES
    assert addon.SBOM not in publish_nightly_release.policy(ROOT)
    manifest = json.loads((ROOT / "deploy-config/bundles/selfhost.json").read_text())
    assert not {"scripts/cloudflared-selfhost.sh", "docker/tunnel-nginx-proxy.edge.conf",
                "docker/secrets/selfhost.example/cloudflare_tunnel_token"} & set(manifest["assets"])
    base = yaml.safe_load((ROOT / "docker-compose.selfhost.prod.yml").read_text())
    assert not {"cloudflared", "cloudflared-beta", "tunnel-nginx-proxy"} & set(base["services"])
    assert not {"cloudflare_tunnel_token", "cloudflare_beta_tunnel_token"} & set(base["secrets"])


def test_packaged_connector_has_one_exact_image_and_no_credentials(packaged):
    _, output, value, _ = packaged
    assert validate(output, value) == value
    assert set(output.iterdir()) == {output / name for name in addon.ASSETS}
    assert value["services"] == {"cloudflared": IMAGE}
    with zipfile.ZipFile(output / addon.ARCHIVE) as bundle:
        assert set(bundle.namelist()) == addon.FILES
        # Native admission consumes this same strict JSON document; Compose
        # accepts JSON as YAML and still evaluates its normal interpolation.
        assert json.loads(bundle.read("compose.cloudflare.yml"))["services"]["cloudflared"]["image"] == IMAGE
        service = yaml.safe_load(bundle.read("compose.cloudflare.yml"))["services"]["cloudflared"]
    assert service["image"] == IMAGE
    assert "ports" not in service and "build" not in service
    assert service["depends_on"] == {"installer-ingress": {"condition": "service_healthy"}}
    assert service["user"] == "10001:10001" and service["read_only"] is True
    assert service["init"] is True
    assert all(mount["read_only"] and mount["bind"]["create_host_path"] is False
               for mount in service["volumes"])


def test_signing_rejects_foreign_attempt_and_linked_signature(packaged, monkeypatch, tmp_path):
    _, output, value, _ = packaged
    for key, current in {"GITHUB_REF": "refs/heads/main", "GITHUB_SHA": value["source_sha"],
                         "GITHUB_RUN_ID": str(value["build_run_id"]),
                         "GITHUB_RUN_ATTEMPT": str(value["build_run_attempt"])}.items():
        monkeypatch.setenv(key, current)
    assert publish_hosting_addon.validate(output) == value
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "99")
    with pytest.raises(ValueError, match="protected-main attempt"):
        publish_hosting_addon.validate(output)
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", str(value["build_run_attempt"]))
    target = tmp_path / "signature"
    target.write_bytes(b"untrusted")
    (output / (addon.ARCHIVE + ".sigstore.json")).symlink_to(target)
    calls = []
    monkeypatch.setattr(publish_hosting_addon, "command", lambda *args: calls.append(args))
    with pytest.raises(ValueError, match="non-symlink"):
        publish_hosting_addon.verify_signatures(output)
    assert not calls


@pytest.mark.parametrize("fault", [None, "different-core-attempt", "different-existing-addon"])
def test_publication_authenticates_same_core_attempt_and_never_replaces_assets(packaged, monkeypatch, tmp_path, fault):
    _, output, value, _ = packaged
    for name in addon.ASSETS:
        for suffix in (".sigstore.json", ".provenance.jsonl"):
            (output / (name + suffix)).write_bytes(b"fixture verification evidence")
    inventory = {"schema": "elevenid.installer-inventory/v1", "repository": "ElevenID/marty-ui",
        "platform": "linux/amd64", **{key: value[key] for key in
            ("source_sha", "release_tag", "build_run_id", "build_run_attempt")},
        "artifacts": [{"name": name, "sha256": "b" * 64, "size": 10} for name in
            ("install.sh", "marty-deploy-linux-amd64", "prepared-selfhost-bundle.zip", "prepared-selfhost-images.json")],
        "images": {"gateway": "ghcr.io/elevenid/app@sha256:" + "f" * 64,
                   "openbao_didcomm_image": "ghcr.io/elevenid/plugin@sha256:" + "e" * 64}}
    if fault == "different-core-attempt":
        inventory["build_run_attempt"] += 1
    names = publish_hosting_addon.core_assets(value["release_tag"])
    remote = {name: b"core fixture" for name in names}
    remote["installer-inventory.json"] = json.dumps(inventory).encode()
    if fault == "different-existing-addon":
        remote[addon.MANIFEST] = b"different immutable manifest"
    calls, verified = [], []

    def command(*args):
        calls.append(args)
        if args[0] == "bash":
            return "\n".join(sorted(names))
        if args[:2] == ("gh", "api"):
            if "/releases/tags/" in args[2]:
                return json.dumps({"tag_name": value["release_tag"], "prerelease": "-nightly." in value["release_tag"], "draft": False,
                    "assets": [{"name": name, "size": len(data), "state": "uploaded"} for name, data in remote.items()]})
            if "/git/ref/" in args[2]:
                return json.dumps({"object": {"type": "tag", "sha": "c" * 40}})
            if "/git/tags/" in args[2]:
                return json.dumps({"tag": value["release_tag"], "object": {"type": "commit", "sha": value["source_sha"]}})
        if args[:3] == ("gh", "release", "download"):
            name = args[args.index("--pattern") + 1]
            (Path(args[args.index("--dir") + 1]) / name).write_bytes(remote[name])
        elif args[:3] == ("gh", "release", "upload"):
            for name in args[6:]:
                path = Path(name)
                assert path.name not in remote
                remote[path.name] = path.read_bytes()
        return ""

    monkeypatch.setattr(publish_hosting_addon, "command", command)
    monkeypatch.setattr(publish_hosting_addon, "verify_signatures", lambda _: value)
    monkeypatch.setattr(publish_hosting_addon, "verify_subject", lambda *args, **kwargs: verified.append((args, kwargs)))
    if fault:
        with pytest.raises(ValueError, match="attempt differ|refusing overwrite"):
            publish_hosting_addon.publish(output, tmp_path / "gh")
        assert not any(call[:3] == ("gh", "release", "upload") for call in calls)
    else:
        publish_hosting_addon.publish(output, tmp_path / "gh")
        assert all(remote[name] == (output / name).read_bytes() for name in publish_hosting_addon.publication_files())
        assert len(verified) == 4
        assert all(kwargs["run_attempt"] == value["build_run_attempt"] for _, kwargs in verified)
        assert all(kwargs["workflow"] == addon.build_workflow(value["release_tag"]) for _, kwargs in verified)
        assert all("--clobber" not in call for call in calls)


@pytest.mark.parametrize("mutation", [
    lambda v: v.update(unknown=True),
    lambda v: v["services"].update(gateway=IMAGE),
    lambda v: v["services"].update(cloudflared=addon.IMAGE + ":latest"),
    lambda v: v["services"].update(cloudflared="ghcr.io/other/connector@sha256:" + "a" * 64),
    lambda v: v["files"].update({"../escape": "sha256:" + "b" * 64}),
    lambda v: v.update(build_run_attempt=True),
    lambda v: v.update(archive_size_bytes=addon.MAX_ARCHIVE + 1),
])
def test_manifest_rejects_unknown_unpinned_or_unsafe_inputs(packaged, mutation):
    _, _, value, _ = packaged
    changed = copy.deepcopy(value)
    mutation(changed)
    with pytest.raises(ValueError):
        addon.validate_manifest(changed)


def test_cross_release_and_cross_attempt_addons_are_rejected(packaged):
    _, output, value, _ = packaged
    for field, different in [("source_sha", "f" * 40), ("release_tag", "v1.2.4"),
                             ("build_run_id", 9999), ("build_run_attempt", 3)]:
        expected = {name: value[name] for name in ("source_sha", "release_tag", "build_run_id", "build_run_attempt")}
        expected[field] = different
        with pytest.raises(ValueError, match="producer or release differs"):
            addon.validate_assets(output, **expected)


def test_archive_and_sbom_bytes_are_bound(packaged):
    _, output, value, _ = packaged
    (output / addon.SBOM).write_bytes(b"altered")
    with pytest.raises(ValueError, match="SBOM differs"):
        validate(output, value)


def test_archive_cannot_add_a_runtime_file_even_with_new_archive_digest(packaged):
    _, output, value, _ = packaged
    archive = output / addon.ARCHIVE
    with zipfile.ZipFile(archive, "a") as bundle:
        bundle.writestr("../escape", "foreign")
    value["archive_size_bytes"] = archive.stat().st_size
    value["archive_sha256"] = addon.digest(archive.read_bytes())
    (output / addon.MANIFEST).write_bytes(addon.encode(value))
    with pytest.raises(ValueError, match="ZIP entry closure"):
        validate(output, value)


def test_packaging_refuses_source_drift_and_existing_output(packaged, tmp_path):
    source, output, value, sbom = packaged
    args = dict(source_sha=value["source_sha"], release_tag=value["release_tag"], build_run_id=1234,
                build_run_attempt=2, image=IMAGE, sbom=sbom)
    with pytest.raises(ValueError, match="fresh"):
        addon.package(source, output, **args)
    (source / "scripts/cloudflared-selfhost.sh").write_text("echo changed\n")
    with pytest.raises(ValueError, match="claimed Git blob"):
        addon.package(source, tmp_path / "changed", **args)


@pytest.mark.parametrize("filename, needs, condition", [
    ("nightly-release.yml", ["admit", "publish"],
     "${{ inputs.publish_cloudflare_addon }}"),
    ("cd.yml", ["resolve-transaction", "publish-manifest"],
     "${{ inputs.publish_cloudflare_addon && inputs.publication_contract == 'v1' }}"),
])
def test_optional_producer_runs_only_after_core_publication(filename, needs, condition):
    workflow = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())
    inputs = workflow.get("on", workflow.get(True))["workflow_dispatch"]["inputs"]
    assert inputs["publish_cloudflare_addon"] == {
        "description": "Publish the optional signed Cloudflare connector after the core release",
        "required": False, "type": "boolean", "default": False,
    }
    jobs = workflow["jobs"]
    optional = jobs["publish-cloudflare-addon"]
    assert optional["needs"] == needs
    assert optional["if"] == condition
    assert all("publish-cloudflare-addon" not in job.get("needs", []) for name, job in jobs.items()
               if name != "publish-cloudflare-addon")
    build = next(s for s in optional["steps"] if s.get("id") == "image")
    assert build["with"]["provenance"] == "mode=max"
    assert build["with"]["sbom"] is True
    assert "push-by-digest=true" in build["with"]["outputs"]


@pytest.mark.parametrize("tag, script, check", [
    (TAG, "nightly-release-assets.sh", "nightly_release_require_remote_allowlist"),
    ("v1.2.3", "operator-release-assets.sh", "operator_release_require_remote_allowlist"),
])
def test_operator_consumers_keep_core_available_during_known_optional_upload(tmp_path, tag, script, check):
    core = publish_hosting_addon.core_assets(tag)
    optional = publish_hosting_addon.publication_files()
    def accepts(document):
        response = tmp_path / "release.json"
        response.write_text(json.dumps(document))
        return subprocess.run(["bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
            'source "$1"; "$2" "$3"', "--", str(ROOT / "scripts" / script), check, str(response)],
            text=True, capture_output=True, check=False).returncode == 0

    for added, success in [(set(), True), (optional, True), ({addon.MANIFEST}, True),
                            (optional | {"foreign-addon.zip"}, False)]:
        document = {"prerelease": "-nightly." in tag, "draft": False,
            "assets": [{"name": name, "state": "uploaded" if name in core else "starter",
                        "size": 1 if name in core else 0} for name in sorted(core | added)]}
        assert accepts(document) == success
    document = {"prerelease": "-nightly." in tag, "draft": False,
        "assets": [{"name": name, "state": "uploaded", "size": 1} for name in sorted(core)]}
    duplicate = copy.deepcopy(document)
    duplicate["assets"].extend([{"name": addon.MANIFEST, "state": "starter", "size": 0}] * 2)
    assert not accepts(duplicate)
    missing = copy.deepcopy(document)
    missing["assets"] = [item for item in missing["assets"] if item["name"] != "install.sh"]
    assert not accepts(missing)
    unfinished_core = copy.deepcopy(document)
    unfinished_core["assets"][0]["state"] = "starter"
    assert not accepts(unfinished_core)


def test_selected_addon_still_requires_the_complete_proof_closure(packaged, monkeypatch, tmp_path):
    _, output, value, _ = packaged
    calls = []
    monkeypatch.setattr(publish_hosting_addon, "verify_signatures", lambda _: value)
    monkeypatch.setattr(publish_hosting_addon, "command", lambda *args: calls.append(args))
    with pytest.raises(ValueError, match="asset closure"):
        publish_hosting_addon.publish(output, tmp_path / "gh")
    assert not calls


def test_legacy_tunnels_are_explicit_and_keep_their_routes():
    legacy = yaml.safe_load((ROOT / "docker-compose.selfhost.cloudflare-legacy.yml").read_text())
    assert set(legacy["services"]) == {"cloudflared", "cloudflared-beta", "tunnel-nginx-proxy"}
    assert legacy["services"]["cloudflared"]["depends_on"] == {"edge": {"condition": "service_healthy"}}
    assert legacy["services"]["cloudflared-beta"]["profiles"] == ["beta-tunnel"]
    assert legacy["services"]["cloudflared-beta"]["depends_on"] == {"tunnel-nginx-proxy": {"condition": "service_healthy"}}
