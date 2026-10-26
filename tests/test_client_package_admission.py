"""Consumer admission regressions for the versioned CLI/SDK release boundary."""

import copy
import gzip
import hashlib
import importlib.util
import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "client_admission", Path(__file__).parents[1] / "scripts/admit_client_packages.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
VERSION = "0.3.4"
SOURCE = "b" * 40
BASE = f"https://github.com/ElevenID/marty-cli/releases/download/v{VERSION}/"


def archive(name, *, extra=None, version=VERSION, license=True, typed=True, declaration=True, exports=None):
    manifest = {"name": "@elevenid/" + name, "version": version}
    if name == "marty-api-core" and typed:
        manifest.update(types="src/index.d.ts", exports=exports or {
            ".": {"types": "./src/index.d.ts", "default": "./src/index.js"}})
    if name == "marty-cli":
        manifest["optionalDependencies"] = {"@elevenid/marty-cli-" + p: version for p in MODULE.PLATFORMS}
    if name == "marty-cli-linux-x64":
        manifest.update(os=["linux"], cpu=["x64"])
    entry = ("src/wasm/marty_api_client_bg.wasm" if name == "marty-api-core" else
             "bin/marty.js" if name == "marty-cli" else "bin/marty")
    files = {"package/package.json": json.dumps(manifest).encode(), "package/" + entry: b"fixture"}
    if name == "marty-api-core":
        files["package/src/index.js"] = b"fixture"
        if declaration:
            files["package/src/index.d.ts"] = b"export function createApiClient(): unknown;"
    if license:
        files["package/LICENSE"] = b"fixture license"
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as tar:
        for path, payload in files.items():
            member = tarfile.TarInfo(path)
            member.size = len(payload)
            tar.addfile(member, io.BytesIO(payload))
        if extra is not None:
            tar.addfile(extra, io.BytesIO(b""))
    return output.getvalue()


def bom(name):
    root = {"name": name, "version": VERSION, "bom-ref": name,
            "purl": f"pkg:npm/%40elevenid/{name}@{VERSION}"}
    components = []
    if name == "marty-cli":
        for platform in MODULE.PLATFORMS:
            child = "marty-cli-" + platform
            components.append({"name": child, "version": VERSION, "scope": "optional",
                               "bom-ref": child, "purl": f"pkg:npm/@elevenid/{child}@{VERSION}"})
    else:
        root["externalReferences"] = [{"type": "bom", "url": BASE + "marty-api-client-wasm-rust-sbom.cdx.json"}]
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": root},
            "components": components,
            "dependencies": [{"ref": name, "dependsOn": [c["bom-ref"] for c in components]},
                             *({"ref": c["bom-ref"], "dependsOn": []} for c in components)]}


def fixture():
    components, assets = [], {}
    for name in ("marty-api-core", "marty-cli"):
        uri = BASE + f"elevenid-{name}-{VERSION}.tgz"
        assets[uri] = archive(name)
        sbom = BASE + name + "-sbom.cdx.json"
        assets[sbom] = json.dumps(bom(name)).encode()
        components.append({"name": name, "repository": MODULE.REPOSITORY, "version": VERSION,
                           "commit": SOURCE, "artifacts": [{"type": "npm", "uri": uri, "sbom": sbom,
                           "digest": "sha256:" + hashlib.sha256(assets[uri]).hexdigest()}]})
    assets[BASE + f"elevenid-marty-cli-linux-x64-{VERSION}.tgz"] = archive("marty-cli-linux-x64")
    return {"components": components}, assets


def test_admits_exact_signed_client_family_and_native_package(tmp_path, monkeypatch):
    lock, assets = fixture()
    verified = []

    def download(url, output):
        output.write_bytes(assets[url])
        return assets[url]

    monkeypatch.setattr(MODULE, "download", download)
    monkeypatch.setattr(MODULE, "attest", lambda path, component: verified.append((path.name, component["commit"])))
    output = tmp_path / "fresh"
    MODULE.admit(lock, output)
    assert len(verified) == len(list(output.iterdir())) == 5
    assert all(source == SOURCE for _, source in verified)
    with pytest.raises(ValueError, match="must be new"):
        MODULE.admit(lock, output)


@pytest.mark.parametrize("field,value", [("version", "0.3.1"), ("commit", "c" * 40),
                                        ("repository", "foreign/repository")])
def test_rejects_mixed_or_foreign_client_sources(field, value):
    lock, _ = fixture()
    lock["components"][0][field] = value
    with pytest.raises(ValueError):
        MODULE.client_inputs(lock)


def test_rejects_wrong_archive_or_sbom_release_location():
    lock, _ = fixture()
    for field in ("uri", "sbom"):
        invalid = copy.deepcopy(lock)
        invalid["components"][0]["artifacts"][0][field] = "https://example.com/mutable"
        with pytest.raises(ValueError, match="artifact identity"):
            MODULE.client_inputs(invalid)


def test_rejects_sdk_sbom_that_actually_describes_the_cli():
    with pytest.raises(ValueError, match="wrong package"):
        MODULE.sbom_identity(bom("marty-cli"), "marty-api-core", VERSION)


@pytest.mark.parametrize("options", [
    {"typed": False},
    {"declaration": False},
    {"exports": {".": {"types": "./src/wasm/marty_api_client.d.ts", "default": "./src/index.js"}}},
])
def test_rejects_runtime_packages_without_the_public_factory_type_contract(options):
    with pytest.raises(ValueError, match="public type"):
        MODULE.archive_manifest(archive("marty-api-core", **options), "marty-api-core", VERSION)


@pytest.mark.parametrize("mutation", ["version", "scope", "edge", "extra", "wasm"])
def test_rejects_unbound_or_incomplete_inventory(mutation):
    name = "marty-api-core" if mutation in ("extra", "wasm") else "marty-cli"
    document = bom(name)
    if mutation in ("version", "scope"):
        document["components"][0][mutation] = "wrong"
    elif mutation == "edge":
        document["dependencies"][0]["dependsOn"] = []
    elif mutation == "extra":
        document["components"] = [{"name": "unreviewed"}]
    else:
        document["metadata"]["component"]["externalReferences"] = []
    with pytest.raises(ValueError):
        MODULE.sbom_identity(document, name, VERSION)


@pytest.mark.parametrize("member", ["../escape", "package/../escape", "package/package.json", "symlink",
                                    "package//package.json", "package/./package.json", "package/file:stream"])
def test_rejects_unsafe_or_duplicate_archive_entries(member):
    entry = tarfile.TarInfo(member)
    if member == "symlink":
        entry.name = "package/link"
        entry.type = tarfile.SYMTYPE
        entry.linkname = "../../outside"
    with pytest.raises(ValueError, match="unsafe or duplicate"):
        MODULE.archive_manifest(archive("marty-api-core", extra=entry), "marty-api-core", VERSION)


def test_rejects_missing_license_wrong_version_and_compressed_expansion(monkeypatch):
    with pytest.raises(ValueError, match="license"):
        MODULE.archive_manifest(archive("marty-api-core", license=False), "marty-api-core", VERSION)
    with pytest.raises(ValueError, match="wrong package/version"):
        MODULE.archive_manifest(archive("marty-api-core", version="0.3.1"), "marty-api-core", VERSION)
    monkeypatch.setattr(MODULE, "LIMIT", 1024)
    with pytest.raises(ValueError, match="expanded archive"):
        MODULE.archive_manifest(gzip.compress(b"x" * 2048), "marty-api-core", VERSION)


def test_attestation_requires_exact_source_tag_workflow_and_hosted_runner(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda args, **kwargs: calls.append((args, kwargs)))
    component = fixture()[0]["components"][0]
    MODULE.attest(tmp_path / "package.tgz", component)
    args, kwargs = calls[0]
    assert kwargs == {"check": True}
    for flag, value in (("--source-digest", SOURCE), ("--source-ref", "refs/tags/v" + VERSION),
                        ("--signer-workflow", MODULE.REPOSITORY + "/.github/workflows/release.yml")):
        assert args[args.index(flag) + 1] == value
    assert "--deny-self-hosted-runners" in args


@pytest.mark.parametrize("failure", ["digest", "signature"])
def test_digest_or_signature_failure_blocks_admission_before_other_inputs(tmp_path, monkeypatch, failure):
    lock, assets = fixture()
    fetched = []

    def download(url, output):
        fetched.append(url)
        payload = assets[url] + (b"tampered" if failure == "digest" else b"")
        output.write_bytes(payload)
        return payload

    def attest(*_):
        raise subprocess.CalledProcessError(1, ["gh", "attestation", "verify"])

    monkeypatch.setattr(MODULE, "download", download)
    monkeypatch.setattr(MODULE, "attest", attest)
    error = ValueError if failure == "digest" else subprocess.CalledProcessError
    with pytest.raises(error):
        MODULE.admit(lock, tmp_path / "failed")
    assert fetched == [lock["components"][0]["artifacts"][0]["uri"]]
