"""Optional connector ownership, immutable identity and package closure."""

from __future__ import annotations

import copy
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

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


def publication_fixture(packaged, tmp_path):
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
    names = publish_hosting_addon.core_assets(value["release_tag"])
    core = tmp_path / "core"
    core.mkdir(mode=0o700)
    for name in names:
        (core / name).write_bytes(b"core fixture")
    (core / "installer-inventory.json").write_text(json.dumps(inventory))
    return output, value, inventory, core


@pytest.mark.parametrize("fault", [None, "source_sha", "release_tag", "build_run_id", "build_run_attempt",
                                  "missing-proof", "extra", "linked", "bad-provenance"])
def test_prepared_addon_authenticates_complete_same_core_before_publication(packaged, monkeypatch, tmp_path, fault):
    output, value, inventory, core = publication_fixture(packaged, tmp_path)
    if fault in {"source_sha", "release_tag", "build_run_id", "build_run_attempt"}:
        inventory[fault] = {"source_sha": "f" * 40, "release_tag": "v9.9.9",
                            "build_run_id": 99, "build_run_attempt": 99}[fault]
        (core / "installer-inventory.json").write_text(json.dumps(inventory))
    elif fault == "missing-proof":
        (output / (addon.ARCHIVE + ".provenance.jsonl")).unlink()
    elif fault == "extra":
        (output / "unselected.txt").write_text("foreign")
    elif fault == "linked":
        path = output / (addon.ARCHIVE + ".provenance.jsonl")
        path.unlink()
        path.symlink_to(core / "install.sh")
    calls, verified = [], []
    monkeypatch.setattr(publish_hosting_addon, "verify_signatures", lambda _: value)
    monkeypatch.setattr(publish_hosting_addon, "command", lambda *args: calls.append(args))
    def verify(*args, **kwargs):
        verified.append((args, kwargs))
        if fault == "bad-provenance":
            raise ValueError("wrong original producer invocation")
    monkeypatch.setattr(publish_hosting_addon, "verify_subject", verify)
    if fault:
        with pytest.raises(ValueError):
            publish_hosting_addon.verify_prepared(output, core, tmp_path / "gh")
    else:
        assert publish_hosting_addon.verify_prepared(output, core, tmp_path / "gh") == value
        assert len(verified) == 4
        assert all(kwargs == dict(gh=tmp_path / "gh", workflow=value["signer_workflow"],
                   source_sha=value["source_sha"], run_id=value["build_run_id"],
                   run_attempt=value["build_run_attempt"]) for _, kwargs in verified)
    assert all(args[0] == "cosign" for args in calls)


@pytest.mark.parametrize("fault", [None, "different-core-attempt", "different-existing-addon",
                                  "missing-addon", "extra", "unfinished", "mutable", "draft"])
def test_published_verification_is_read_only_and_never_repairs_immutable_assets(packaged, monkeypatch, tmp_path, fault):
    output, value, inventory, core = publication_fixture(packaged, tmp_path)
    if fault == "different-core-attempt":
        inventory["build_run_attempt"] += 1
    names = publish_hosting_addon.core_assets(value["release_tag"])
    remote = {name: b"core fixture" for name in names}
    remote["installer-inventory.json"] = json.dumps(inventory).encode()
    remote.update({name: (output / name).read_bytes() for name in publish_hosting_addon.publication_files()})
    if fault == "different-existing-addon":
        remote[addon.MANIFEST] = b"different immutable manifest"
    elif fault == "missing-addon":
        del remote[addon.MANIFEST]
    elif fault == "extra":
        remote["foreign-addon.zip"] = b"foreign"
    calls, verified = [], []

    def command(*args):
        calls.append(args)
        if args[0] == "bash":
            return "\n".join(sorted(names))
        if args[:2] == ("gh", "api"):
            if "/releases/tags/" in args[2]:
                return json.dumps({"tag_name": value["release_tag"], "prerelease": "-nightly." in value["release_tag"],
                    "draft": fault == "draft", "immutable": fault != "mutable",
                    "assets": [{"name": name, "size": len(data),
                                "state": "starter" if fault == "unfinished" and name == addon.MANIFEST else "uploaded"}
                               for name, data in remote.items()]})
            if "/git/ref/" in args[2]:
                return json.dumps({"object": {"type": "tag", "sha": "c" * 40}})
            if "/git/tags/" in args[2]:
                return json.dumps({"tag": value["release_tag"], "object": {"type": "commit", "sha": value["source_sha"]}})
        if args[:3] == ("gh", "release", "download"):
            name = args[args.index("--pattern") + 1]
            (Path(args[args.index("--dir") + 1]) / name).write_bytes(remote[name])
        elif args[:3] == ("gh", "release", "upload"):
            pytest.fail("GitHub rejects uploads after immutable publication")
        return ""

    monkeypatch.setattr(publish_hosting_addon, "command", command)
    monkeypatch.setattr(publish_hosting_addon, "verify_signatures", lambda _: value)
    monkeypatch.setattr(publish_hosting_addon, "validate", lambda _: value)
    monkeypatch.setattr(publish_hosting_addon, "verify_subject", lambda *args, **kwargs: verified.append((args, kwargs)))
    if fault:
        with pytest.raises(ValueError):
            publish_hosting_addon.verify_published(output, tmp_path / "gh")
    else:
        publish_hosting_addon.verify_published(output, tmp_path / "gh")
        assert all(remote[name] == (output / name).read_bytes() for name in publish_hosting_addon.publication_files())
        assert len(verified) == 4
        assert all(kwargs["run_attempt"] == value["build_run_attempt"] for _, kwargs in verified)
        assert all(kwargs["workflow"] == addon.build_workflow(value["release_tag"]) for _, kwargs in verified)
        assert all("--clobber" not in call for call in calls)
    assert not any(call[:3] in (("gh", "release", "upload"), ("gh", "release", "delete"),
                              ("gh", "release", "edit"), ("gh", "release", "create")) for call in calls)


@pytest.mark.parametrize("packaged", [TAG], indirect=True)
@pytest.mark.parametrize("selected", [False, True])
@pytest.mark.parametrize("fault", [None, "existing", "existing-partial", "changed", "missing",
                                  "extra", "duplicate", "unfinished", "mutable", "draft"])
def test_nightly_creates_entire_selected_closure_before_immutability(packaged, monkeypatch, tmp_path, selected, fault):
    """Model GitHub's draft/upload/publish flow; published uploads are forbidden."""
    output, value, _, core = publication_fixture(packaged, tmp_path)
    for key, setting in {"GITHUB_REF": "refs/heads/main", "GITHUB_SHA": value["source_sha"],
                         "GITHUB_RUN_ID": str(value["build_run_id"]),
                         "GITHUB_RUN_ATTEMPT": str(value["build_run_attempt"])}.items():
        monkeypatch.setenv(key, setting)
    candidate = {"source_sha": value["source_sha"], "claim_run_id": "123"}
    expected_paths = list(core.iterdir()) + (list(output.iterdir()) if selected else [])
    expected = {p.name: p.read_bytes() for p in expected_paths}
    assert len(expected) == (51 if selected else 42)
    existing = fault in {"existing", "existing-partial"}
    remote = dict(expected) if existing else {}
    missing_name = addon.MANIFEST if selected else "install.sh"
    if fault == "existing-partial":
        del remote[missing_name]
    calls, verified = [], []
    monkeypatch.setattr(publish_nightly_release, "verify_signed", lambda *args, **kwargs: candidate)
    monkeypatch.setattr(publish_hosting_addon, "verify_subject", lambda *args, **kwargs: verified.append((args, kwargs)))
    monkeypatch.setattr(publish_hosting_addon, "verify_signatures", lambda _: value)
    monkeypatch.setattr(publish_nightly_release.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0 if existing else 1, stdout="" if existing else "HTTP/2 404 Not Found"))
    message = f"Installation-test nightly\nSource-SHA: {value['source_sha']}\nClaim: 123\nRun: {value['build_run_id']}\n"

    def command(*args, **kwargs):
        calls.append(args)
        if args[0] == "git":
            if "merge-base" in args:
                return value["source_sha"]
            if "ls-remote" in args:
                return "existing annotated source ref"
            return ""
        if args[:2] == ("gh", "api"):
            if "/git/ref/" in args[2]:
                return json.dumps({"object": {"type": "tag", "sha": "c" * 40}})
            if "/git/tags/" in args[2]:
                return json.dumps({"tag": value["release_tag"], "message": message,
                                   "object": {"type": "commit", "sha": value["source_sha"]}})
            if "/releases/tags/" in args[2]:
                entries = [{"name": name, "size": len(data),
                            "state": "starter" if fault == "unfinished" and name == missing_name else "uploaded"}
                           for name, data in remote.items()]
                if fault == "duplicate":
                    entries.append(dict(entries[0]))
                return json.dumps({"tag_name": value["release_tag"], "prerelease": True,
                                   "draft": fault == "draft", "immutable": fault != "mutable",
                                   "assets": entries, "html_url": "https://github.com/ElevenID/marty-ui/releases/tag/fixture"})
        if args[:3] == ("gh", "release", "create"):
            assert not existing and not remote
            assert len(verified) == (4 if selected else 0), "selected proofs must precede publication"
            paths = [Path(name) for name in args[args.index("--notes-file") + 2:]]
            assert len(paths) == len(expected) and {p.name for p in paths} == set(expected)
            # The CLI uploads the complete set while draft, then publishes once.
            remote.update({p.name: p.read_bytes() for p in paths})
            if fault == "missing":
                del remote[missing_name]
            elif fault == "extra":
                remote["foreign-addon.zip"] = b"unexpected"
            elif fault == "changed":
                remote[missing_name] = b"changed after selection"
        if args[:3] == ("gh", "release", "download"):
            directory = Path(args[args.index("--dir") + 1])
            names = [args[i + 1] for i, arg in enumerate(args) if arg == "--pattern"]
            assert set(names) == set(expected)
            for name in names:
                (directory / name).write_bytes(remote[name])
        if args[:3] in (("gh", "release", "upload"), ("gh", "release", "edit"), ("gh", "release", "delete")):
            pytest.fail("immutable release must never be repaired or replaced")
        return ""

    monkeypatch.setattr(publish_nightly_release, "command", command)
    monkeypatch.setattr(publish_hosting_addon, "command", command)
    def publish():
        publish_nightly_release.publish(core, ROOT, value["release_tag"], str(value["build_run_id"]), tmp_path / "gh",
                                        cloudflare_addon_assets=output if selected else None)
    if fault not in {None, "existing"}:
        with pytest.raises(ValueError):
            publish()
    else:
        publish()
        assert remote == expected
    assert sum(call[:3] == ("gh", "release", "create") for call in calls) == (0 if existing else 1)
    assert all("--clobber" not in call for call in calls)


@pytest.mark.parametrize("selected", [False, True])
@pytest.mark.parametrize("fault", [None, "missing", "extra", "duplicate", "unfinished", "empty", "mutable", "draft"])
def test_stable_publisher_requires_exact_immutable_selected_closure(tmp_path, selected, fault):
    names = publish_hosting_addon.core_assets("v1.2.3")
    optional = publish_hosting_addon.publication_files()
    expected = names | (optional if selected else set())
    document = {"prerelease": False, "draft": fault == "draft", "immutable": fault != "mutable",
                "assets": [{"name": name, "state": "uploaded", "size": 1} for name in sorted(expected)]}
    chosen = next(a for a in document["assets"] if a["name"] == (addon.MANIFEST if selected else "install.sh"))
    if fault == "missing":
        document["assets"].remove(chosen)
    elif fault == "extra":
        document["assets"].append({"name": "foreign.zip" if selected else addon.MANIFEST, "state": "uploaded", "size": 1})
    elif fault == "duplicate":
        document["assets"].append(dict(chosen))
    elif fault == "unfinished":
        chosen["state"] = "starter"
    elif fault == "empty":
        chosen["size"] = 0
    response = tmp_path / "release.json"
    response.write_text(json.dumps(document))
    result = subprocess.run(["bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
        'source "$1"; operator_release_require_publication_assets "$2" "$3"', "--",
        str(ROOT / "scripts/operator-release-assets.sh"), str(response), str(selected).lower()], capture_output=True, text=True)
    assert (result.returncode == 0) is (fault is None)


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


@pytest.mark.parametrize("filename, needs, publisher, condition", [
    ("nightly-release.yml", ["admit"], "publish",
     "${{ inputs.publish_cloudflare_addon }}"),
    ("cd.yml", ["resolve-transaction"], "publish-manifest",
     "${{ inputs.publish_cloudflare_addon && inputs.publication_contract == 'v1' }}"),
])
def test_optional_producer_prepares_same_attempt_before_selected_publication(filename, needs, publisher, condition):
    workflow = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())
    inputs = workflow.get("on", workflow.get(True))["workflow_dispatch"]["inputs"]
    assert inputs["publish_cloudflare_addon"] == {
        "description": "Include the optional signed Cloudflare connector in the immutable release",
        "required": False, "type": "boolean", "default": False,
    }
    jobs = workflow["jobs"]
    optional = jobs["publish-cloudflare-addon"]
    assert optional["needs"] == needs
    assert optional["if"] == condition
    assert "publish-cloudflare-addon" in jobs[publisher]["needs"]
    assert publisher not in optional["needs"]
    assert optional["permissions"]["contents"] == "read"
    build = next(s for s in optional["steps"] if s.get("id") == "image")
    assert build["with"]["provenance"] == "mode=max"
    assert build["with"]["sbom"] is True
    assert "push-by-digest=true" in build["with"]["outputs"]
    artifact = "cloudflare-addon-publication-${{ github.run_id }}-${{ github.run_attempt }}"
    upload = next(s for s in optional["steps"] if s.get("uses", "").startswith("actions/upload-artifact@"))
    assert upload["with"]["name"] == artifact
    download = next(s for s in jobs[publisher]["steps"] if s.get("with", {}).get("name") == artifact)
    assert download["if"] == "inputs.publish_cloudflare_addon"
    assert not any("--phase publish" in s.get("run", "") for s in optional["steps"])
    assert not any("gh release" in s.get("run", "") for s in optional["steps"])

    expression = jobs[publisher]["if"].removeprefix("${{").removesuffix("}}").strip()
    assert "!cancelled()" in expression  # Override Actions' implicit success() on skipped needs.
    def permitted(selected, results, cancelled=False):
        evaluated = expression.replace("!cancelled()", repr(not cancelled))
        evaluated = evaluated.replace("inputs.publish_cloudflare_addon", repr(selected))
        evaluated = re.sub(r"needs\.([\w-]+)\.result", lambda m: repr(results[m[1]]), evaluated)
        evaluated = evaluated.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
        return eval(" ".join(evaluated.split()), {"__builtins__": {}}, {})
    results = {name: "success" for name in jobs[publisher]["needs"]}
    assert permitted(True, results)
    assert not permitted(False, results)
    assert not permitted(True, results, cancelled=True)
    for outcome in ("failure", "cancelled", "skipped"):
        changed = {**results, "publish-cloudflare-addon": outcome}
        assert not permitted(True, changed)
        assert permitted(False, changed) is (outcome == "skipped")
    for dependency in set(results) - {"publish-cloudflare-addon"}:
        for outcome in ("failure", "cancelled", "skipped"):
            assert not permitted(False, {**results, "publish-cloudflare-addon": "skipped", dependency: outcome})
            assert not permitted(True, {**results, dependency: outcome})


@pytest.mark.parametrize("filename,publisher", [("nightly-release.yml", "publish"), ("cd.yml", "publish-manifest")])
@pytest.mark.parametrize("unexpected", [False, True])
def test_unselected_publisher_refuses_an_accidental_addon_directory(tmp_path, filename, publisher, unexpected):
    jobs = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())["jobs"]
    script = next(s["run"] for s in jobs[publisher]["steps"] if "optional_assets=()" in s.get("run", ""))
    selection = script[script.index("optional_assets=()"):script.index("esac", script.index("optional_assets=()")) + 4]
    if unexpected:
        (tmp_path / "cloudflare-addon").mkdir()
    result = subprocess.run(["bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", selection],
                            env={"PATH": "/usr/bin:/bin", "RUNNER_TEMP": str(tmp_path), "CLOUDFLARE_ADDON_SELECTED": "false"},
                            capture_output=True, text=True)
    assert (result.returncode == 0) is (not unexpected)


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
        publish_hosting_addon.verify_prepared(output, tmp_path, tmp_path / "gh")
    assert not calls


def test_legacy_tunnels_are_explicit_and_keep_their_routes():
    legacy = yaml.safe_load((ROOT / "docker-compose.selfhost.cloudflare-legacy.yml").read_text())
    assert set(legacy["services"]) == {"cloudflared", "cloudflared-beta", "tunnel-nginx-proxy"}
    assert legacy["services"]["cloudflared"]["depends_on"] == {"edge": {"condition": "service_healthy"}}
    assert legacy["services"]["cloudflared-beta"]["profiles"] == ["beta-tunnel"]
    assert legacy["services"]["cloudflared-beta"]["depends_on"] == {"tunnel-nginx-proxy": {"condition": "service_healthy"}}
