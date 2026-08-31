#!/usr/bin/env python3
"""Create a self-contained, nonpublishing Rust verification candidate bundle."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import tarfile
import tempfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterator

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_PIN_SCHEMA = "elevenid.credentials-verifier-candidate-pin/v1"
CANDIDATE_METADATA_SCHEMA = "elevenid.marty-ui.services-candidate-build-metadata/v1"
CANDIDATE_PROVENANCE_SCHEMA = "elevenid.marty-ui.services-candidate-provenance/v1"
REPOSITORY = "ElevenID/marty-ui"
SOURCE_REF = "refs/heads/main"
BUILD_WORKFLOW = ".github/workflows/verification-candidate-build.yml"
IMAGE_URI = "ghcr.io/elevenid/marty-ui-oss/services"
LOCAL_IMAGE_REPOSITORY = "docker.io/elevenid/marty-ui-verification-candidate"
ARCHIVE_ASSET = "marty-ui-services.oci.tar"
SBOM_ASSET = "marty-ui-services-sbom.cdx.json"
METADATA_ASSET = "marty-ui-services-build-metadata.json"
PROVENANCE_ASSET = "marty-ui-services-provenance.json"
DOCKERFILE = "services/Dockerfile"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^[1-9][0-9]*$")
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_GZIP_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
CYCLONEDX_COMPONENT_TYPES = {
    "application",
    "container",
    "cryptographic-asset",
    "data",
    "device",
    "device-driver",
    "file",
    "firmware",
    "framework",
    "library",
    "machine-learning-model",
    "operating-system",
    "platform",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def inspect_oci_archive(path: Path, *, commit: str, version: str) -> dict[str, Any]:
    def normalize(member: tarfile.TarInfo) -> str:
        name = member.name.removeprefix("./")
        parts = PurePosixPath(name).parts
        require(bool(parts) and bool(parts[0]), "OCI archive path changed")
        require(
            ".." not in parts and not name.startswith("/"),
            "OCI archive contains an unsafe path",
        )
        return name

    def metadata_member(
        archive: tarfile.TarFile,
        members: dict[str, tarfile.TarInfo],
        name: str,
    ) -> bytes:
        member = members.get(name)
        require(
            member is not None and member.isfile(),
            f"OCI archive member is missing: {name}",
        )
        require(
            member.size <= 16 * 1024 * 1024, f"OCI metadata member is too large: {name}"
        )
        extracted = archive.extractfile(member)
        require(extracted is not None, f"OCI archive member could not be read: {name}")
        return extracted.read()

    def descriptor_blob(
        archive: tarfile.TarFile,
        members: dict[str, tarfile.TarInfo],
        descriptor: dict[str, Any],
        *,
        metadata: bool,
        sink: BinaryIO | None = None,
    ) -> tuple[str, bytes]:
        digest = str(descriptor.get("digest"))
        require(bool(SHA256.fullmatch(digest)), "OCI descriptor digest changed")
        size_value = descriptor.get("size")
        require(
            type(size_value) is int and size_value >= 0, "OCI descriptor size changed"
        )
        name = f"blobs/sha256/{digest.split(':', 1)[1]}"
        member = members.get(name)
        require(
            member is not None and member.isfile(),
            f"OCI archive member is missing: {name}",
        )
        if metadata:
            require(
                member.size <= 16 * 1024 * 1024,
                f"OCI metadata member is too large: {name}",
            )
        extracted = archive.extractfile(member)
        require(extracted is not None, f"OCI archive member could not be read: {name}")
        digest_state = hashlib.sha256()
        chunks: list[bytes] = []
        size = 0
        for chunk in iter(lambda: extracted.read(1024 * 1024), b""):
            size += len(chunk)
            digest_state.update(chunk)
            if sink is not None:
                sink.write(chunk)
            if metadata:
                chunks.append(chunk)
        require(size == size_value, "OCI descriptor size does not match its blob")
        require(
            f"sha256:{digest_state.hexdigest()}" == digest,
            "OCI descriptor digest does not match its blob",
        )
        return digest, b"".join(chunks)

    def descriptor_json(
        archive: tarfile.TarFile,
        members: dict[str, tarfile.TarInfo],
        descriptor: dict[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        digest, raw = descriptor_blob(archive, members, descriptor, metadata=True)
        value = json.loads(raw)
        require(isinstance(value, dict), "OCI descriptor must contain a JSON object")
        return digest, value

    @contextmanager
    def open_archive() -> Iterator[tarfile.TarFile]:
        try:
            with tarfile.open(path, mode="r:*") as archive:
                yield archive
        except (OSError, tarfile.TarError) as exc:
            raise ValueError("candidate archive is not a readable OCI archive") from exc

    with open_archive() as archive:
        members: dict[str, tarfile.TarInfo] = {}
        for member in archive.getmembers():
            name = normalize(member)
            if member.isdir():
                continue
            require(member.isfile(), "OCI archive contains a non-regular member")
            require(name not in members, "OCI archive contains duplicate members")
            members[name] = member

        layout = json.loads(metadata_member(archive, members, "oci-layout"))
        require(layout == {"imageLayoutVersion": "1.0.0"}, "OCI layout version changed")
        index = json.loads(metadata_member(archive, members, "index.json"))
        require(
            isinstance(index, dict) and index.get("schemaVersion") == 2,
            "OCI index schema changed",
        )
        descriptors = index.get("manifests")
        require(
            isinstance(descriptors, list) and len(descriptors) == 1,
            "OCI archive must contain one image",
        )
        descriptor = descriptors[0]
        require(isinstance(descriptor, dict), "OCI image descriptor changed")
        archive_tag = f"candidate-{commit}"
        annotations = descriptor.get("annotations")
        require(
            isinstance(annotations, dict)
            and annotations.get("org.opencontainers.image.ref.name") == archive_tag,
            "OCI archive tag changed",
        )
        manifest_digest, value = descriptor_json(archive, members, descriptor)
        if descriptor.get("mediaType") == OCI_INDEX:
            nested = value.get("manifests")
            require(
                isinstance(nested, list) and len(nested) == 1,
                "OCI image index must contain one platform",
            )
            descriptor = nested[0]
            require(isinstance(descriptor, dict), "OCI platform descriptor changed")
            require(
                descriptor.get("platform") == {"architecture": "amd64", "os": "linux"},
                "OCI candidate platform changed",
            )
            manifest_digest, value = descriptor_json(archive, members, descriptor)
        elif "platform" in descriptor:
            require(
                descriptor.get("platform") == {"architecture": "amd64", "os": "linux"},
                "OCI candidate platform changed",
            )
        require(
            descriptor.get("mediaType") == OCI_MANIFEST,
            "OCI candidate is not an image manifest",
        )
        require(value.get("schemaVersion") == 2, "OCI manifest schema changed")

        config_descriptor = value.get("config")
        require(isinstance(config_descriptor, dict), "OCI config descriptor is missing")
        require(
            config_descriptor.get("mediaType") == OCI_CONFIG,
            "OCI config media type changed",
        )
        config_digest, config = descriptor_json(archive, members, config_descriptor)
        require(
            config.get("architecture") == "amd64" and config.get("os") == "linux",
            "OCI config platform changed",
        )
        runtime_config = config.get("config")
        require(isinstance(runtime_config, dict), "OCI runtime config is missing")
        environment = runtime_config.get("Env")
        require(isinstance(environment, list), "OCI image environment is missing")
        for name, expected in {
            "SERVICE_NAME": "verification",
            "MARTY_RELEASE_VERSION": version,
            "MARTY_UI_SHA": commit,
        }.items():
            bindings = [
                item
                for item in environment
                if isinstance(item, str) and item.startswith(f"{name}=")
            ]
            require(
                bindings == [f"{name}={expected}"],
                f"OCI image {name} environment binding changed",
            )
        labels = runtime_config.get("Labels")
        require(isinstance(labels, dict), "OCI image labels are missing")
        require(
            {
                "org.opencontainers.image.source": labels.get(
                    "org.opencontainers.image.source"
                ),
                "org.opencontainers.image.revision": labels.get(
                    "org.opencontainers.image.revision"
                ),
                "org.opencontainers.image.version": labels.get(
                    "org.opencontainers.image.version"
                ),
            }
            == {
                "org.opencontainers.image.source": "https://github.com/ElevenID/marty-ui",
                "org.opencontainers.image.revision": commit,
                "org.opencontainers.image.version": version,
            },
            "OCI image source labels changed",
        )

        layers = value.get("layers")
        require(isinstance(layers, list) and layers, "OCI image layers are missing")
        rootfs = config.get("rootfs")
        require(
            isinstance(rootfs, dict) and rootfs.get("type") == "layers",
            "OCI rootfs changed",
        )
        diff_ids = rootfs.get("diff_ids")
        require(
            isinstance(diff_ids, list)
            and len(diff_ids) == len(layers)
            and all(
                isinstance(item, str) and SHA256.fullmatch(item) for item in diff_ids
            ),
            "OCI rootfs diff IDs changed",
        )
        for layer, diff_id in zip(layers, diff_ids, strict=True):
            require(isinstance(layer, dict), "OCI layer descriptor changed")
            require(
                layer.get("mediaType") == OCI_GZIP_LAYER,
                "OCI layer media type changed",
            )
            with (
                tempfile.TemporaryFile() as compressed,
                tempfile.TemporaryFile() as uncompressed,
            ):
                descriptor_blob(
                    archive, members, layer, metadata=False, sink=compressed
                )
                compressed.seek(0)
                digest_state = hashlib.sha256()
                try:
                    with gzip.GzipFile(fileobj=compressed, mode="rb") as source:
                        for chunk in iter(lambda: source.read(1024 * 1024), b""):
                            digest_state.update(chunk)
                            uncompressed.write(chunk)
                except (EOFError, OSError) as exc:
                    raise ValueError("OCI layer is not valid gzip content") from exc
                require(
                    f"sha256:{digest_state.hexdigest()}" == diff_id,
                    "OCI layer does not match its rootfs diff ID",
                )
                uncompressed.seek(0)
                try:
                    with tarfile.open(fileobj=uncompressed, mode="r:") as layer_archive:
                        require(
                            bool(layer_archive.getmembers()), "OCI layer tar is empty"
                        )
                except tarfile.TarError as exc:
                    raise ValueError("OCI layer is not a readable tar archive") from exc
        return {
            "uri": IMAGE_URI,
            "digest": manifest_digest,
            "config_digest": config_digest,
            "archive_tag": archive_tag,
        }


def normalize_sbom(
    raw_path: Path,
    output_path: Path,
    archive_path: Path,
    image: dict[str, str],
    *,
    commit: str,
    version: str,
) -> None:
    value = json.loads(raw_path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), "candidate SBOM must be a JSON object")
    require(value.get("bomFormat") == "CycloneDX", "candidate SBOM must use CycloneDX")
    require(value.get("specVersion") == "1.6", "candidate SBOM must use CycloneDX 1.6")
    components = value.get("components")
    require(
        isinstance(components, list) and bool(components),
        "candidate SBOM components are missing",
    )
    component_refs: set[str] = set()
    for item in components:
        require(isinstance(item, dict), "candidate SBOM component changed")
        require(
            item.get("type") in CYCLONEDX_COMPONENT_TYPES,
            "candidate SBOM component type changed",
        )
        require(
            isinstance(item.get("name"), str) and bool(item["name"].strip()),
            "candidate SBOM component name is missing",
        )
        reference = item.get("bom-ref")
        require(
            isinstance(reference, str) and bool(reference),
            "candidate SBOM component reference is missing",
        )
        require(
            reference not in component_refs,
            "candidate SBOM component reference is duplicated",
        )
        component_refs.add(reference)
    metadata = value.get("metadata")
    require(isinstance(metadata, dict), "candidate SBOM metadata is missing")
    tools = metadata.get("tools")
    require(isinstance(tools, dict), "candidate SBOM scanner identity is missing")
    scanner_components = tools.get("components")
    require(
        isinstance(scanner_components, list)
        and any(
            isinstance(tool, dict) and tool.get("name") == "syft"
            for tool in scanner_components
        ),
        "candidate SBOM was not generated by Syft",
    )
    component = metadata.get("component")
    require(isinstance(component, dict), "candidate SBOM root component is missing")
    archive_names = {
        str(archive_path),
        archive_path.as_posix(),
        f"oci-archive:{archive_path}",
        f"oci-archive:{archive_path.as_posix()}",
    }
    require(
        component.get("type") == "container", "candidate SBOM root is not a container"
    )
    require(
        component.get("name") in archive_names, "candidate SBOM source archive changed"
    )
    require(
        component.get("version") == image["digest"],
        "candidate SBOM source digest changed",
    )
    require(
        isinstance(component.get("bom-ref"), str) and bool(component["bom-ref"]),
        "candidate SBOM root reference is missing",
    )
    root_reference = component["bom-ref"]
    require(
        root_reference not in component_refs,
        "candidate SBOM root reference is duplicated",
    )
    all_references = component_refs | {root_reference}
    dependencies = value.get("dependencies", [])
    require(isinstance(dependencies, list), "candidate SBOM dependencies changed")
    dependency_roots: set[str] = set()
    for dependency in dependencies:
        require(isinstance(dependency, dict), "candidate SBOM dependency changed")
        reference = dependency.get("ref")
        depends_on = dependency.get("dependsOn")
        require(
            isinstance(reference, str)
            and reference in all_references
            and reference not in dependency_roots,
            "candidate SBOM dependency reference changed",
        )
        require(
            isinstance(depends_on, list)
            and all(
                isinstance(item, str) and item in all_references for item in depends_on
            ),
            "candidate SBOM dependency edge changed",
        )
        dependency_roots.add(reference)
    require(
        not ({"purl", "cpe", "hashes", "properties", "swid"} & set(component)),
        "candidate SBOM root identity is contradictory",
    )
    properties = metadata.get("properties")
    require(isinstance(properties, list), "candidate SBOM image labels are missing")
    property_values: dict[str, str] = {}
    for item in properties:
        require(isinstance(item, dict), "candidate SBOM image property changed")
        name = item.get("name")
        property_value = item.get("value")
        require(
            isinstance(name, str) and isinstance(property_value, str),
            "candidate SBOM image property changed",
        )
        require(
            name not in property_values, "candidate SBOM image property is duplicated"
        )
        property_values[name] = property_value
    expected_labels = {
        "syft:image:labels:org.opencontainers.image.source": "https://github.com/ElevenID/marty-ui",
        "syft:image:labels:org.opencontainers.image.revision": commit,
        "syft:image:labels:org.opencontainers.image.version": version,
    }
    require(
        all(
            property_values.get(name) == expected
            for name, expected in expected_labels.items()
        ),
        "candidate SBOM image labels changed",
    )
    normalized_component = {
        **component,
        "name": image["uri"],
    }
    write_json(
        output_path,
        {**value, "metadata": {**metadata, "component": normalized_component}},
    )


def finalize(args: argparse.Namespace) -> dict[str, Any]:
    require(args.repository == REPOSITORY, "candidate repository changed")
    require(args.source_ref == SOURCE_REF, "candidate source ref changed")
    require(args.workflow == BUILD_WORKFLOW, "candidate workflow changed")
    require(
        bool(COMMIT.fullmatch(args.commit)),
        "candidate commit must be a full lowercase SHA",
    )
    require(bool(RUN_ID.fullmatch(args.run_id)), "candidate run ID must be positive")
    require(args.run_attempt > 0, "candidate run attempt must be positive")
    expected_dockerfile = ROOT / DOCKERFILE
    require(
        args.dockerfile.resolve() == expected_dockerfile.resolve(),
        "candidate Dockerfile path changed",
    )
    version = f"0.0.0-candidate.{args.commit[:12]}"
    image = inspect_oci_archive(args.archive, commit=args.commit, version=version)
    normalize_sbom(
        args.raw_sbom,
        args.sbom,
        args.archive,
        image,
        commit=args.commit,
        version=version,
    )

    source = {
        "repository": REPOSITORY,
        "commit": args.commit,
        "ref": SOURCE_REF,
    }
    builder = {
        "repository": REPOSITORY,
        "workflow": BUILD_WORKFLOW,
        "id": args.run_id,
        "attempt": args.run_attempt,
    }
    metadata = {
        "schema": CANDIDATE_METADATA_SCHEMA,
        "source": source,
        "builder": builder,
        "build": {
            "context": ".",
            "dockerfile": DOCKERFILE,
            "dockerfile_digest": file_digest(args.dockerfile),
            "platform": "linux/amd64",
            "version": version,
            "arguments": {
                "SERVICE_NAME": "verification",
                "MARTY_RELEASE_VERSION": version,
                "MARTY_UI_SHA": args.commit,
            },
        },
        "image": image,
    }
    write_json(args.metadata, metadata)

    archive = {"asset": ARCHIVE_ASSET, "digest": file_digest(args.archive)}
    sbom = {"asset": SBOM_ASSET, "digest": file_digest(args.sbom)}
    metadata_asset = {"asset": METADATA_ASSET, "digest": file_digest(args.metadata)}
    provenance = {
        "schema": CANDIDATE_PROVENANCE_SCHEMA,
        "source": source,
        "builder": builder,
        "subjects": {
            "archive": archive,
            "image": image,
            "sbom": sbom,
            "metadata": metadata_asset,
        },
    }
    write_json(args.provenance, provenance)
    pin = {
        "schema": CANDIDATE_PIN_SCHEMA,
        "state": "candidate",
        "repository": REPOSITORY,
        "version": version,
        "commit": args.commit,
        "source_ref": SOURCE_REF,
        "run": builder,
        "archive": archive,
        "image": image,
        "sbom": sbom,
        "metadata": metadata_asset,
        "provenance": {
            "asset": PROVENANCE_ASSET,
            "digest": file_digest(args.provenance),
        },
    }
    write_json(args.pin, pin)
    return pin


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repository", required=True)
    result.add_argument("--commit", required=True)
    result.add_argument("--source-ref", required=True)
    result.add_argument("--workflow", required=True)
    result.add_argument("--run-id", required=True)
    result.add_argument("--run-attempt", type=int, required=True)
    result.add_argument("--archive", type=Path, required=True)
    result.add_argument("--raw-sbom", type=Path, required=True)
    result.add_argument("--sbom", type=Path, required=True)
    result.add_argument("--dockerfile", type=Path, required=True)
    result.add_argument("--metadata", type=Path, required=True)
    result.add_argument("--provenance", type=Path, required=True)
    result.add_argument("--pin", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    pin = finalize(parser().parse_args(argv))
    print(
        json.dumps({"archive": pin["archive"], "image": pin["image"]}, sort_keys=True)
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Verification candidate error: {exc}")
        raise SystemExit(2) from exc
