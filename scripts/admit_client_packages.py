#!/usr/bin/env python3
"""Admit source-bound CLI/SDK packages for the existing release consumer lane."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import subprocess
import tarfile
import urllib.request
from pathlib import Path, PurePosixPath
from urllib.parse import unquote

REPOSITORY = "ElevenID/marty-cli"
PLATFORMS = ("darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64", "win32-arm64", "win32-x64")
LIMIT = 64 * 1024 * 1024


def require(value, message):
    if not value:
        raise ValueError(message)


def client_inputs(lock):
    selected = [c for c in lock["components"] if c["name"] in {"marty-api-core", "marty-cli"}]
    require(len(selected) == 2 and len({c["name"] for c in selected}) == 2, "Exactly one SDK and CLI are required")
    require(len({(c["version"], c["commit"]) for c in selected}) == 1, "Client family source/version differs")
    for component in selected:
        version = component["version"]
        require(component["repository"] == REPOSITORY and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
                and re.fullmatch(r"[a-f0-9]{40}", component["commit"]), "Client source identity is invalid")
        require(len(component["artifacts"]) == 1, "One client npm archive is required")
        artifact = component["artifacts"][0]
        base = f"https://github.com/{REPOSITORY}/releases/download/v{version}/"
        require(artifact["type"] == "npm"
                and artifact["uri"] == base + f"elevenid-{component['name']}-{version}.tgz"
                and artifact["sbom"] == base + component["name"] + "-sbom.cdx.json"
                and re.fullmatch(r"sha256:[a-f0-9]{64}", artifact["digest"]), "Client artifact identity is invalid")
    return selected


def archive_manifest(payload, name, version):
    require(len(payload) <= LIMIT, "Client archive exceeds the size limit")
    with gzip.GzipFile(fileobj=io.BytesIO(payload)) as compressed:
        contents = compressed.read(LIMIT + 1)
    require(len(contents) <= LIMIT, "Client expanded archive exceeds the size limit")
    with tarfile.open(fileobj=io.BytesIO(contents), mode="r:") as archive:
        members = archive.getmembers()
        require(len(members) <= 256 and sum(m.size for m in members) <= LIMIT, "Client archive inventory is too large")
        names = set()
        for member in members:
            path = PurePosixPath(member.name)
            require(path.parts and not path.is_absolute() and ".." not in path.parts and path.parts[0] == "package"
                    and "\\" not in member.name and (member.isfile() or member.isdir())
                    and member.name not in names, "Client archive has unsafe or duplicate entries")
            names.add(member.name)
        require("package/package.json" in names and "package/LICENSE" in names, "Client metadata/license is missing")
        entry = ("src/wasm/marty_api_client_bg.wasm" if name == "marty-api-core" else
                 "bin/marty.js" if name == "marty-cli" else "bin/marty")
        required = {"package/package.json", "package/LICENSE", "package/" + entry}
        if name == "marty-api-core":
            required.add("package/src/index.js")
        require(all(path in names and archive.getmember(path).isfile() for path in required),
                "Client runtime entry point is missing")
        stream = archive.extractfile("package/package.json")
        require(stream is not None, "Client manifest is not a regular file")
        manifest = json.load(stream)
    require(manifest.get("name") == "@elevenid/" + name and manifest.get("version") == version,
            "Client archive describes the wrong package/version")
    require(not manifest.get("dependencies") and not manifest.get("peerDependencies"), "Unreviewed client runtime dependencies")
    optional = {"@elevenid/marty-cli-" + p: version for p in PLATFORMS} if name == "marty-cli" else {}
    require(manifest.get("optionalDependencies", {}) == optional, "Client optional dependency family differs")
    return manifest


def sbom_identity(bom, name, version):
    root = bom.get("metadata", {}).get("component", {})
    require(bom.get("bomFormat") == "CycloneDX" and bom.get("specVersion") == "1.5"
            and root.get("name") == name and root.get("version") == version
            and unquote(root.get("purl", "")) == f"pkg:npm/@elevenid/{name}@{version}",
            "Client SBOM describes the wrong package/version")
    components = bom.get("components", [])
    expected = {"marty-cli-" + p for p in PLATFORMS} if name == "marty-cli" else set()
    require(len(components) == len(expected) and {c.get("name") for c in components} == expected,
            "Client SBOM omits or adds production packages")
    for child in components:
        require(child.get("version") == version and child.get("scope") == "optional"
                and unquote(child.get("purl", "")) == f"pkg:npm/@elevenid/{child['name']}@{version}",
                "Client SBOM optional package identity differs")
    refs = [root.get("bom-ref"), *(c.get("bom-ref") for c in components)]
    require(all(isinstance(r, str) and r for r in refs) and len(set(refs)) == len(refs), "Client SBOM references are invalid")
    expected_edges = {refs[0]: sorted(refs[1:]), **{r: [] for r in refs[1:]}}
    edges = bom.get("dependencies", [])
    require(len(edges) == len(expected_edges)
            and {e.get("ref"): sorted(e.get("dependsOn", [])) for e in edges} == expected_edges,
            "Client SBOM dependency graph differs")
    if name == "marty-api-core":
        link = f"https://github.com/{REPOSITORY}/releases/download/v{version}/marty-api-client-wasm-rust-sbom.cdx.json"
        require({"type": "bom", "url": link} in root.get("externalReferences", []), "SDK omits its versioned Rust inventory")


def download(url, output):
    request = urllib.request.Request(url, headers={"User-Agent": "marty-client-admission/1"})
    with urllib.request.urlopen(request, timeout=120) as response:
        require(response.geturl().startswith("https://"), "Client download redirected away from HTTPS")
        payload = response.read(LIMIT + 1)
    require(len(payload) <= LIMIT, "Client asset exceeds the size limit")
    with output.open("xb") as stream:
        stream.write(payload)
    return payload


def attest(path, component):
    subprocess.run([
        "gh", "attestation", "verify", str(path), "--repo", REPOSITORY,
        "--signer-workflow", REPOSITORY + "/.github/workflows/release.yml",
        "--source-digest", component["commit"], "--source-ref", "refs/tags/v" + component["version"],
        "--deny-self-hosted-runners",
    ], check=True)


def admit(lock, output):
    components = client_inputs(lock)
    # A fresh caller-owned directory prevents silently reusing previous bytes.
    require(not output.exists() and not output.is_symlink(), "Client admission output must be new")
    output.mkdir()
    for component in components:
        artifact = component["artifacts"][0]
        name, version = component["name"], component["version"]
        package = output / f"elevenid-{name}-{version}.tgz"
        payload = download(artifact["uri"], package)
        require("sha256:" + hashlib.sha256(payload).hexdigest() == artifact["digest"], "Client archive digest differs")
        attest(package, component)
        archive_manifest(payload, name, version)
        sbom = output / (name + "-sbom.cdx.json")
        payload = download(artifact["sbom"], sbom)
        attest(sbom, component)
        sbom_identity(json.loads(payload), name, version)
    # The release smoke runs on Linux x64. The registry is not a client channel;
    # install the exact signed native npm package alongside the launcher.
    cli = next(c for c in components if c["name"] == "marty-cli")
    name = "marty-cli-linux-x64"
    filename = f"elevenid-{name}-{cli['version']}.tgz"
    url = f"https://github.com/{REPOSITORY}/releases/download/v{cli['version']}/{filename}"
    payload = download(url, output / filename)
    attest(output / filename, cli)
    manifest = archive_manifest(payload, name, cli["version"])
    require(manifest.get("os") == ["linux"] and manifest.get("cpu") == ["x64"], "Native client platform differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    admit(json.loads(args.lock.read_text(encoding="utf-8")), args.output)
    print("Admitted signed client archives and SDK/CLI inventory identities")


if __name__ == "__main__":
    main()
