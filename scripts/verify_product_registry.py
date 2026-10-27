#!/usr/bin/env python3
"""Inspect exact GHCR image manifests, BuildKit provenance, and SPDX SBOMs.

This checks digest-linked registry content. A separate signed GitHub attestation
check must authenticate the image digest and producer workflow before its result
can be used for release qualification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.parse
import urllib.request
from pathlib import Path

INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MAX_BLOB = 16 * 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def fetch(url: str, token: str = "", accept: str = "application/json") -> bytes:
    headers = {"Accept": accept}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(MAX_BLOB + 1)
    require(len(raw) <= MAX_BLOB, "registry response exceeds bound")
    return raw


def registry_blob(repository: str, reference: str, token: str,
                  *, manifest: bool = False) -> dict:
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", reference) is not None,
            "registry digest is invalid")
    kind = "manifests" if manifest else "blobs"
    accept = INDEX + ", " + MANIFEST if manifest else "application/octet-stream"
    raw = fetch(f"https://ghcr.io/v2/{repository}/{kind}/{reference}", token, accept)
    require(hashlib.sha256(raw).hexdigest() == reference[7:],
            "registry content differs from selected digest")
    return json.loads(raw)


def verify_image(image: dict, product: str, version: str, source_sha: str,
                 run_id: str, attempt: str) -> dict:
    uri = image["uri"]
    require(re.fullmatch(r"ghcr\.io/elevenid/marty-(?:server|console)/[a-z-]+", uri)
            is not None and uri.startswith("ghcr.io/elevenid/" + product + "/"),
            "image registry namespace changed")
    repository = uri.removeprefix("ghcr.io/")
    raw_token = fetch("https://ghcr.io/token?" + urllib.parse.urlencode({
        "scope": f"repository:{repository}:pull"}))
    token = json.loads(raw_token)["token"]
    index = registry_blob(repository, image["digest"], token, manifest=True)
    require(index.get("schemaVersion") == 2 and index.get("mediaType") == INDEX,
            "image index media type changed")
    descriptors = index.get("manifests")
    require(isinstance(descriptors, list) and len(descriptors) == 2,
            "image index must contain one platform and its attestation")
    platform = [item for item in descriptors if item.get("platform") ==
                {"architecture": "amd64", "os": "linux"}]
    attestation = [item for item in descriptors if item.get("platform") ==
                   {"architecture": "unknown", "os": "unknown"}]
    require(len(platform) == len(attestation) == 1,
            "image index platform or attestation differs")
    platform = platform[0]
    attestation = attestation[0]
    require(platform.get("mediaType") == attestation.get("mediaType") == MANIFEST
            and attestation.get("annotations") == {
                "vnd.docker.reference.digest": platform["digest"],
                "vnd.docker.reference.type": "attestation-manifest"},
            "image attestation does not reference its platform")
    platform_manifest = registry_blob(repository, platform["digest"], token,
                                      manifest=True)
    require(platform_manifest.get("mediaType") == MANIFEST,
            "platform manifest media type changed")
    config_ref = platform_manifest["config"]["digest"]
    config = registry_blob(repository, config_ref, token)
    require(config.get("architecture") == "amd64" and config.get("os") == "linux",
            "image config platform changed")
    labels = config.get("config", {}).get("Labels", {})
    require(labels.get("io.elevenid.product") == product
            and labels.get("io.elevenid.qualification") == "unqualified",
            "image product or qualification label changed")
    attestation_manifest = registry_blob(repository, attestation["digest"], token,
                                         manifest=True)
    require(attestation_manifest.get("mediaType") == MANIFEST,
            "attestation manifest media type changed")
    layers = attestation_manifest.get("layers")
    require(isinstance(layers, list) and len(layers) == 2,
            "SBOM and provenance layers are required")
    predicates = {}
    layer_digests = {}
    for layer in layers:
        require(layer.get("mediaType") == "application/vnd.in-toto+json",
                "attestation layer media type changed")
        declared = layer.get("annotations", {}).get("in-toto.io/predicate-type")
        require(declared in ("https://spdx.dev/Document", "https://slsa.dev/provenance/v1")
                and declared not in predicates, "required attestation predicate differs")
        statement = registry_blob(repository, layer["digest"], token)
        require(statement.get("predicateType") == declared
                and len(statement.get("subject", [])) == 1
                and statement["subject"][0].get("digest") ==
                    {"sha256": platform["digest"][7:]},
                "attestation statement does not bind platform digest")
        predicates[declared] = statement["predicate"]
        layer_digests[declared] = layer["digest"]
    sbom = predicates["https://spdx.dev/Document"]
    require(sbom.get("spdxVersion") == "SPDX-2.3"
            and isinstance(sbom.get("packages"), list) and sbom["packages"],
            "SPDX package inventory missing")
    provenance = predicates["https://slsa.dev/provenance/v1"]
    args = provenance.get("buildDefinition", {}).get("externalParameters", {})
    args = args.get("request", {}).get("args", {})
    builder = provenance.get("runDetails", {}).get("builder", {}).get("id")
    require(args.get("build-arg:MARTY_RELEASE_VERSION") == version
            and args.get("build-arg:MARTY_UI_SHA") == source_sha
            and args.get("label:io.elevenid.product") == product
            and args.get("label:io.elevenid.qualification") == "unqualified"
            and builder == f"https://github.com/ElevenID/marty-ui/actions/runs/{run_id}/attempts/{attempt}",
            "BuildKit provenance source or producer differs")
    return {
        "role": image["role"], "uri": uri, "index_digest": image["digest"],
        "platform_digest": platform["digest"], "config_digest": config_ref,
        "attestation_manifest_digest": attestation["digest"],
        "sbom_digest": layer_digests["https://spdx.dev/Document"],
        "sbom_package_count": len(sbom["packages"]),
        "provenance_digest": layer_digests["https://slsa.dev/provenance/v1"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.payload_report.read_text(encoding="utf-8"))
    require(report.get("schema") == "marty.product-candidate-payload-verification/v1"
            and report.get("result") == "pass", "payload report is not passing")
    product = report["product"]
    version = report.get("version", "0.1.0")
    images = [verify_image(image, product, version, report["source_sha"],
                           report["producer_run_id"], report["producer_run_attempt"])
              for image in report["images"]]
    result = {"schema": "marty.product-registry-verification/v1",
              "product": product, "archive_sha256": report["archive_sha256"],
              "images": sorted(images, key=lambda image: image["role"]),
              "result": "pass"}
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
