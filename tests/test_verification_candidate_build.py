from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tarfile
from argparse import Namespace
from collections.abc import Callable
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_verification_candidate",
    ROOT / "scripts" / "build_verification_candidate.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load verification candidate builder")
candidate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(candidate)


@pytest.fixture(scope="session")
def containerd_buildx_backend() -> None:
    if os.environ.get("MARTY_RUN_VERIFICATION_CANDIDATE_DOCKER_TESTS") != "1":
        pytest.skip("supported containerd/Buildx contract was not requested")
    assert shutil.which("docker") is not None, "Docker is required by the live contract"
    for command in (
        ["docker", "info", "--format", "{{json .DriverStatus}}"],
        ["docker", "buildx", "version"],
    ):
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr
    driver_status = json.loads(
        subprocess.run(
            ["docker", "info", "--format", "{{json .DriverStatus}}"],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        ).stdout
    )
    assert ["driver-type", "io.containerd.snapshotter.v1"] in driver_status
    buildx_inspection = subprocess.run(
        ["docker", "buildx", "inspect", "--bootstrap"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    buildx_fields = {
        name.strip(): value.strip()
        for line in buildx_inspection.splitlines()
        if ":" in line
        for name, value in [line.split(":", 1)]
    }
    assert buildx_fields["Driver"] == "docker-container"
    assert buildx_fields["BuildKit version"] == "v0.32.2"


def descriptor(content: bytes, media_type: str, **extra: object) -> dict[str, object]:
    return {
        "mediaType": media_type,
        "digest": f"sha256:{hashlib.sha256(content).hexdigest()}",
        "size": len(content),
        **extra,
    }


def write_oci_archive(
    path: Path,
    *,
    commit: str,
    version: str,
    platform: dict[str, str] | None = None,
    revision: str | None = None,
    corrupt_layer: bool = False,
    corrupt_config: bool = False,
    corrupt_manifest: bool = False,
    malformed_compression: bool = False,
    wrong_diff_id: bool = False,
    environment: list[str] | None = None,
    archive_tag: str | None = None,
    manifest_media_type: str | None = None,
    manifest_schema_version: int = 2,
    manifest_payload_media_type: str | None = candidate.OCI_MANIFEST,
    index_schema_version: int = 2,
    index_payload_media_type: str | None = None,
    nested_index: bool = False,
    nested_index_schema_version: int = 2,
    nested_index_payload_media_type: str | None = candidate.OCI_INDEX,
    omit_platform: bool = False,
    top_index_platform: dict[str, str] | None = None,
    config_media_type: str | None = None,
    layer_media_type: str | None = None,
    manifest_size_delta: int = 0,
    config_size_delta: int = 0,
    layer_size_delta: int = 0,
    config_architecture: str = "amd64",
    config_os: str = "linux",
    config_platform_qualifiers: dict[str, object] | None = None,
    rootfs_type: str = "layers",
    source_label: str = "https://github.com/ElevenID/marty-ui",
    version_label: str | None = None,
    extra_members: dict[str, bytes] | None = None,
    extra_directories: list[str] | None = None,
    uncompressed_layer_override: bytes | None = None,
) -> tuple[str, str]:
    layer_tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=layer_tar_buffer, mode="w") as layer_archive:
        content = b"candidate layer"
        member = tarfile.TarInfo("usr/local/bin/marty-verification-service")
        member.size = len(content)
        layer_archive.addfile(member, io.BytesIO(content))
    uncompressed_layer = (
        uncompressed_layer_override
        if uncompressed_layer_override is not None
        else layer_tar_buffer.getvalue()
    )
    layer = (
        b"not gzip content"
        if malformed_compression
        else gzip.compress(uncompressed_layer, mtime=0)
    )
    diff_id = f"sha256:{hashlib.sha256(uncompressed_layer).hexdigest()}"
    config_value: dict[str, object] = {
        "architecture": config_architecture,
        "os": config_os,
        "rootfs": {
            "type": rootfs_type,
            "diff_ids": ["sha256:" + "8" * 64 if wrong_diff_id else diff_id],
        },
        "config": {
            "Env": (
                environment
                if environment is not None
                else [
                    "SERVICE_NAME=verification",
                    f"MARTY_RELEASE_VERSION={version}",
                    f"MARTY_UI_SHA={commit}",
                ]
            ),
            "Labels": {
                "org.opencontainers.image.source": source_label,
                "org.opencontainers.image.revision": revision or commit,
                "org.opencontainers.image.version": (
                    version if version_label is None else version_label
                ),
            },
        },
    }
    config_value.update(config_platform_qualifiers or {})
    config = candidate.canonical_json(config_value)
    config_descriptor = descriptor(config, config_media_type or candidate.OCI_CONFIG)
    config_descriptor["size"] = int(config_descriptor["size"]) + config_size_delta
    layer_descriptor = descriptor(layer, layer_media_type or candidate.OCI_GZIP_LAYER)
    layer_descriptor["size"] = int(layer_descriptor["size"]) + layer_size_delta
    if corrupt_layer:
        layer_descriptor["digest"] = "sha256:" + "9" * 64
    if corrupt_config:
        config_descriptor["digest"] = "sha256:" + "7" * 64
    manifest_value: dict[str, object] = {
        "schemaVersion": manifest_schema_version,
        "config": config_descriptor,
        "layers": [layer_descriptor],
    }
    if manifest_payload_media_type is not None:
        manifest_value["mediaType"] = manifest_payload_media_type
    manifest = candidate.canonical_json(manifest_value)
    manifest_descriptor_fields: dict[str, object] = {
        "annotations": {
            "org.opencontainers.image.ref.name": archive_tag or f"candidate-{commit}"
        }
    }
    if not omit_platform:
        manifest_descriptor_fields["platform"] = (
            platform
            if platform is not None
            else {"architecture": "amd64", "os": "linux"}
        )
    manifest_descriptor = descriptor(
        manifest,
        manifest_media_type or candidate.OCI_MANIFEST,
        **manifest_descriptor_fields,
    )
    manifest_descriptor["size"] = int(manifest_descriptor["size"]) + manifest_size_delta
    if corrupt_manifest:
        manifest_descriptor["digest"] = "sha256:" + "6" * 64
    index_descriptor = manifest_descriptor
    nested_index_blob: tuple[str, bytes] | None = None
    if nested_index:
        nested_value: dict[str, object] = {
            "schemaVersion": nested_index_schema_version,
            "manifests": [manifest_descriptor],
        }
        if nested_index_payload_media_type is not None:
            nested_value["mediaType"] = nested_index_payload_media_type
        nested = candidate.canonical_json(nested_value)
        nested_descriptor_fields: dict[str, object] = {
            "annotations": {
                "org.opencontainers.image.ref.name": archive_tag
                or f"candidate-{commit}"
            }
        }
        if top_index_platform is not None:
            nested_descriptor_fields["platform"] = top_index_platform
        index_descriptor = descriptor(
            nested,
            candidate.OCI_INDEX,
            **nested_descriptor_fields,
        )
        nested_index_blob = (
            f"blobs/sha256/{str(index_descriptor['digest']).split(':', 1)[1]}",
            nested,
        )
    index_value: dict[str, object] = {
        "schemaVersion": index_schema_version,
        "manifests": [index_descriptor],
    }
    if index_payload_media_type is not None:
        index_value["mediaType"] = index_payload_media_type
    index = candidate.canonical_json(index_value)
    layout = candidate.canonical_json({"imageLayoutVersion": "1.0.0"})
    members = {
        "oci-layout": layout,
        "index.json": index,
        f"blobs/sha256/{str(config_descriptor['digest']).split(':', 1)[1]}": config,
        f"blobs/sha256/{str(manifest_descriptor['digest']).split(':', 1)[1]}": manifest,
        f"blobs/sha256/{hashlib.sha256(layer).hexdigest()}": layer,
    }
    if nested_index_blob is not None:
        members[nested_index_blob[0]] = nested_index_blob[1]
    members.update(extra_members or {})
    with tarfile.open(path, "w") as archive:
        for name in extra_directories or []:
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            archive.addfile(member)
        for name, content in members.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return str(manifest_descriptor["digest"]), str(config_descriptor["digest"])


def special_tar_record(typeflag: bytes, size: int, payload: bytes = b"") -> bytes:
    member = tarfile.TarInfo("special-header")
    member.type = typeflag
    member.size = size
    header = member.tobuf(format=tarfile.GNU_FORMAT)
    padding = bytes((-len(payload)) % candidate.TAR_BLOCK_BYTES)
    return header + payload + padding


def special_tar_header(typeflag: bytes, size: int, payload: bytes = b"") -> bytes:
    return special_tar_record(typeflag, size, payload) + bytes(
        candidate.TAR_BLOCK_BYTES * 2
    )


def trim_tar_end(content: bytes, zero_blocks: int) -> bytes:
    blocks = [
        content[offset : offset + candidate.TAR_BLOCK_BYTES]
        for offset in range(0, len(content), candidate.TAR_BLOCK_BYTES)
    ]
    first_zero = next(index for index, block in enumerate(blocks) if not any(block))
    return b"".join(blocks[: first_zero + zero_blocks])


def minimal_layer_tar() -> bytes:
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode="w") as archive:
        member = tarfile.TarInfo("candidate")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    return content.getvalue()


def archive_resource_dimensions(path: Path) -> dict[str, int]:
    with tarfile.open(path, "r:*") as archive:
        outer_members = archive.getmembers()
        regular_members = [member for member in outer_members if member.isfile()]
        index_member = archive.extractfile("index.json")
        assert index_member is not None
        index = json.load(index_member)
        manifest_descriptor = index["manifests"][0]
        manifest_member = archive.extractfile(
            "blobs/sha256/" + manifest_descriptor["digest"].removeprefix("sha256:")
        )
        assert manifest_member is not None
        manifest = json.load(manifest_member)
        layers = manifest["layers"]
        expanded_bytes = 0
        layer_members = 0
        for layer in layers:
            layer_member = archive.extractfile(
                "blobs/sha256/" + layer["digest"].removeprefix("sha256:")
            )
            assert layer_member is not None
            expanded = gzip.decompress(layer_member.read())
            expanded_bytes += len(expanded)
            with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as layer_archive:
                layer_members += len(layer_archive.getmembers())
    return {
        "archive_bytes": path.stat().st_size,
        "outer_members": len(outer_members),
        "outer_regular_members": len(regular_members),
        "layers": len(layers),
        "compressed_bytes": sum(layer["size"] for layer in layers),
        "expanded_bytes": expanded_bytes,
        "layer_members": layer_members,
    }


def test_candidate_resource_limits_preserve_calibrated_runner_headroom() -> None:
    assert {
        "archive": candidate.MAX_ARCHIVE_BYTES,
        "members": candidate.MAX_ARCHIVE_MEMBERS,
        "regular_members": candidate.MAX_ARCHIVE_REGULAR_MEMBERS,
        "layers": candidate.MAX_LAYERS,
        "compressed_layer": candidate.MAX_COMPRESSED_LAYER_BYTES,
        "compressed_total": candidate.MAX_TOTAL_COMPRESSED_LAYER_BYTES,
        "expanded_layer": candidate.MAX_EXPANDED_LAYER_BYTES,
        "expanded_total": candidate.MAX_TOTAL_EXPANDED_LAYER_BYTES,
        "layer_members": candidate.MAX_LAYER_MEMBERS,
        "layer_members_total": candidate.MAX_TOTAL_LAYER_MEMBERS,
        "special_header": candidate.MAX_TAR_SPECIAL_HEADER_BYTES,
        "special_headers_total": candidate.MAX_TOTAL_TAR_SPECIAL_HEADER_BYTES,
        "special_header_count": candidate.MAX_TAR_SPECIAL_HEADERS,
        "raw_sbom": candidate.MAX_RAW_SBOM_BYTES,
        "sbom_top_level": candidate.MAX_SBOM_TOP_LEVEL_KEYS,
        "sbom_components": candidate.MAX_SBOM_COMPONENTS,
        "sbom_dependencies": candidate.MAX_SBOM_DEPENDENCIES,
        "sbom_dependency_edges_per_entry": candidate.MAX_SBOM_DEPENDENCY_EDGES_PER_ENTRY,
        "sbom_dependency_edges_total": candidate.MAX_TOTAL_SBOM_DEPENDENCY_EDGES,
        "sbom_properties": candidate.MAX_SBOM_PROPERTIES,
        "sbom_scanners": candidate.MAX_SBOM_SCANNER_COMPONENTS,
    } == {
        "archive": 512 * 1024 * 1024,
        "members": 512,
        "regular_members": 256,
        "layers": 64,
        "compressed_layer": 128 * 1024 * 1024,
        "compressed_total": 512 * 1024 * 1024,
        "expanded_layer": 256 * 1024 * 1024,
        "expanded_total": 1024 * 1024 * 1024,
        "layer_members": 20_000,
        "layer_members_total": 50_000,
        "special_header": 64 * 1024,
        "special_headers_total": 4 * 1024 * 1024,
        "special_header_count": 256,
        "raw_sbom": 128 * 1024 * 1024,
        "sbom_top_level": 64,
        "sbom_components": 100_000,
        "sbom_dependencies": 100_000,
        "sbom_dependency_edges_per_entry": 20_000,
        "sbom_dependency_edges_total": 100_000,
        "sbom_properties": 4_096,
        "sbom_scanners": 64,
    }
    source = (ROOT / "scripts" / "build_verification_candidate.py").read_text(
        encoding="utf-8"
    )
    assert ".getmembers()" not in source


def build_inputs(tmp_path: Path) -> Namespace:
    commit = "a" * 40
    version = f"0.0.0-candidate.{commit[:12]}"
    archive = tmp_path / candidate.ARCHIVE_ASSET
    manifest_digest, _config_digest = write_oci_archive(
        archive,
        commit=commit,
        version=version,
    )
    raw_sbom = tmp_path / "raw.cdx.json"
    raw_sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "metadata": {
                    "tools": {
                        "components": [
                            {
                                "type": "application",
                                "author": "anchore",
                                "name": "syft",
                                "version": "1.34.2",
                            }
                        ]
                    },
                    "properties": [
                        {
                            "name": "syft:image:labels:org.opencontainers.image.source",
                            "value": "https://github.com/ElevenID/marty-ui",
                        },
                        {
                            "name": "syft:image:labels:org.opencontainers.image.revision",
                            "value": commit,
                        },
                        {
                            "name": "syft:image:labels:org.opencontainers.image.version",
                            "value": version,
                        },
                    ],
                    "component": {
                        "bom-ref": "candidate-image",
                        "type": "container",
                        "name": f"oci-archive:{archive}",
                        "version": manifest_digest,
                    },
                },
                "components": [
                    {
                        "bom-ref": "marty-verification-service",
                        "type": "library",
                        "name": "marty-verification-service",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    dockerfile = candidate.ROOT / candidate.DOCKERFILE
    return Namespace(
        repository=candidate.REPOSITORY,
        commit=commit,
        source_ref=candidate.SOURCE_REF,
        workflow=candidate.BUILD_WORKFLOW,
        run_id="123456789",
        run_attempt=2,
        archive=archive,
        raw_sbom=raw_sbom,
        sbom=tmp_path / candidate.SBOM_ASSET,
        dockerfile=dockerfile,
        metadata=tmp_path / candidate.METADATA_ASSET,
        provenance=tmp_path / candidate.PROVENANCE_ASSET,
        pin=tmp_path / "verification-candidate.json",
    )


def test_finalize_binds_every_candidate_asset_and_oci_coordinate(
    tmp_path: Path,
) -> None:
    args = build_inputs(tmp_path)

    pin = candidate.finalize(args)

    assert pin["schema"] == candidate.CANDIDATE_PIN_SCHEMA
    assert pin["state"] == "candidate"
    assert pin["version"] == "0.0.0-candidate." + "a" * 12
    assert pin["image"]["archive_tag"] == "candidate-" + "a" * 40
    assert pin["run"] == {
        "repository": candidate.REPOSITORY,
        "workflow": candidate.BUILD_WORKFLOW,
        "id": "123456789",
        "attempt": 2,
    }
    for label, path in (
        ("archive", args.archive),
        ("sbom", args.sbom),
        ("metadata", args.metadata),
        ("provenance", args.provenance),
    ):
        assert pin[label]["digest"] == candidate.file_digest(path)
    sbom = json.loads(args.sbom.read_text(encoding="utf-8"))
    root = sbom["metadata"]["component"]
    assert {
        "type": root["type"],
        "name": root["name"],
        "version": root["version"],
        "bom-ref": root["bom-ref"],
    } == {
        "type": "container",
        "name": candidate.IMAGE_URI,
        "version": pin["image"]["digest"],
        "bom-ref": "candidate-image",
    }
    metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    assert metadata["image"] == pin["image"]
    assert metadata["build"]["dockerfile_digest"] == candidate.file_digest(
        args.dockerfile
    )
    assert metadata["build"]["arguments"] == {
        "SERVICE_NAME": "verification",
        "MARTY_RELEASE_VERSION": pin["version"],
        "MARTY_UI_SHA": pin["commit"],
    }
    provenance = json.loads(args.provenance.read_text(encoding="utf-8"))
    assert provenance["subjects"] == {
        "archive": pin["archive"],
        "image": pin["image"],
        "sbom": pin["sbom"],
        "metadata": pin["metadata"],
    }
    assert json.loads(args.pin.read_text(encoding="utf-8")) == pin


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"platform": {"architecture": "arm64", "os": "linux"}}, "platform changed"),
        ({"platform": {"architecture": "amd64", "os": "windows"}}, "platform changed"),
        (
            {
                "platform": {
                    "architecture": "amd64",
                    "os": "linux",
                    "variant": "v1",
                }
            },
            "platform changed",
        ),
        ({"omit_platform": True}, "platform changed"),
        ({"index_schema_version": 1}, "index schema changed"),
        ({"index_payload_media_type": "application/json"}, "index media type changed"),
        ({"manifest_media_type": "application/json"}, "not an image manifest"),
        ({"manifest_schema_version": 1}, "manifest schema changed"),
        (
            {"manifest_payload_media_type": "application/json"},
            "manifest media type changed",
        ),
        (
            {"nested_index": True, "nested_index_schema_version": 1},
            "image index schema changed",
        ),
        (
            {
                "nested_index": True,
                "nested_index_payload_media_type": "application/json",
            },
            "image index media type changed",
        ),
        (
            {
                "nested_index": True,
                "top_index_platform": {"architecture": "amd64", "os": "linux"},
            },
            "index descriptor platform changed",
        ),
        (
            {
                "nested_index": True,
                "platform": {
                    "architecture": "amd64",
                    "os": "linux",
                    "variant": "v1",
                },
            },
            "platform changed",
        ),
        ({"nested_index": True, "omit_platform": True}, "platform changed"),
        ({"config_media_type": "application/json"}, "config media type changed"),
        ({"layer_media_type": "application/json"}, "layer media type changed"),
        ({"manifest_size_delta": 1}, "descriptor size does not match"),
        ({"config_size_delta": 1}, "descriptor size does not match"),
        ({"layer_size_delta": 1}, "descriptor size does not match"),
        ({"corrupt_manifest": True}, "descriptor digest does not match"),
        ({"corrupt_config": True}, "descriptor digest does not match"),
        ({"config_architecture": "arm64"}, "config platform changed"),
        ({"config_os": "windows"}, "config platform changed"),
        ({"rootfs_type": "unknown"}, "rootfs changed"),
        (
            {"source_label": "https://attacker.invalid/repository"},
            "source labels changed",
        ),
        ({"revision": "b" * 40}, "source labels changed"),
        ({"version_label": "9.9.9"}, "source labels changed"),
        ({"archive_tag": "attacker-image"}, "archive tag changed"),
        ({"corrupt_layer": True}, "archive member is missing"),
        ({"malformed_compression": True}, "valid gzip"),
        ({"wrong_diff_id": True}, "rootfs diff ID"),
        (
            {
                "environment": [
                    "MARTY_RELEASE_VERSION=0.0.0-candidate.aaaaaaaaaaaa",
                    "MARTY_UI_SHA=" + "a" * 40,
                ]
            },
            "SERVICE_NAME environment binding changed",
        ),
        (
            {
                "environment": [
                    "SERVICE_NAME=verification",
                    "MARTY_RELEASE_VERSION=9.9.9",
                    "MARTY_UI_SHA=" + "a" * 40,
                ]
            },
            "MARTY_RELEASE_VERSION environment binding changed",
        ),
        (
            {
                "environment": [
                    "SERVICE_NAME=verification",
                    "MARTY_RELEASE_VERSION=0.0.0-candidate.aaaaaaaaaaaa",
                    "MARTY_UI_SHA=" + "b" * 40,
                ]
            },
            "MARTY_UI_SHA environment binding changed",
        ),
        (
            {
                "environment": [
                    "SERVICE_NAME=verification",
                    "MARTY_RELEASE_VERSION=0.0.0-candidate.aaaaaaaaaaaa",
                    "MARTY_RELEASE_VERSION=9.9.9",
                    "MARTY_UI_SHA=" + "a" * 40,
                ]
            },
            "MARTY_RELEASE_VERSION environment binding changed",
        ),
        (
            {
                "environment": [
                    "SERVICE_NAME=verification",
                    "MARTY_RELEASE_VERSION=0.0.0-candidate.aaaaaaaaaaaa",
                    "MARTY_UI_SHA=" + "a" * 40,
                    "MARTY_UI_SHA=" + "b" * 40,
                ]
            },
            "MARTY_UI_SHA environment binding changed",
        ),
        (
            {
                "environment": [
                    "SERVICE_NAME=issuance",
                    "MARTY_RELEASE_VERSION=0.0.0-candidate.aaaaaaaaaaaa",
                    "MARTY_UI_SHA=" + "a" * 40,
                ]
            },
            "SERVICE_NAME environment binding changed",
        ),
        (
            {
                "environment": [
                    "SERVICE_NAME=verification",
                    "SERVICE_NAME=issuance",
                    "MARTY_RELEASE_VERSION=0.0.0-candidate.aaaaaaaaaaaa",
                    "MARTY_UI_SHA=" + "a" * 40,
                ]
            },
            "SERVICE_NAME environment binding changed",
        ),
    ],
)
def test_inspection_rejects_rebound_or_incomplete_oci_archives(
    tmp_path: Path,
    mutation: dict[str, object],
    message: str,
) -> None:
    commit = "a" * 40
    version = f"0.0.0-candidate.{commit[:12]}"
    archive = tmp_path / "candidate.tar"
    write_oci_archive(archive, commit=commit, version=version, **mutation)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match=message):
        candidate.inspect_oci_archive(archive, commit=commit, version=version)


@pytest.mark.parametrize(
    "options",
    [
        {"manifest_payload_media_type": None},
        {"index_payload_media_type": candidate.OCI_INDEX},
        {"nested_index": True},
        {"nested_index": True, "nested_index_payload_media_type": None},
    ],
)
def test_inspection_accepts_absent_or_exact_oci_payload_media_types(
    tmp_path: Path,
    options: dict[str, object],
) -> None:
    commit = "a" * 40
    version = f"0.0.0-candidate.{commit[:12]}"
    archive = tmp_path / "candidate.tar"
    write_oci_archive(archive, commit=commit, version=version, **options)  # type: ignore[arg-type]

    candidate.inspect_oci_archive(archive, commit=commit, version=version)


@pytest.mark.parametrize("nested_index", [False, True], ids=["direct", "nested-index"])
@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("variant", "v1"),
        ("variant", None),
        ("os.version", "6.8"),
        ("os.version", ""),
        ("os.features", ["sse4"]),
        ("os.features", []),
    ],
)
def test_inspection_rejects_every_oci_config_platform_qualifier(
    tmp_path: Path,
    nested_index: bool,
    key: str,
    value: object,
) -> None:
    commit = "a" * 40
    version = f"0.0.0-candidate.{commit[:12]}"
    archive = tmp_path / "candidate.tar"
    write_oci_archive(
        archive,
        commit=commit,
        version=version,
        nested_index=nested_index,
        config_platform_qualifiers={key: value},
    )

    with pytest.raises(ValueError, match="config platform changed"):
        candidate.inspect_oci_archive(archive, commit=commit, version=version)


@pytest.mark.parametrize("nested_index", [False, True], ids=["direct", "nested-index"])
def test_inspection_accepts_canonical_unqualified_linux_amd64_config(
    tmp_path: Path,
    nested_index: bool,
) -> None:
    commit = "a" * 40
    version = f"0.0.0-candidate.{commit[:12]}"
    archive = tmp_path / "candidate.tar"
    write_oci_archive(
        archive,
        commit=commit,
        version=version,
        nested_index=nested_index,
    )

    candidate.inspect_oci_archive(archive, commit=commit, version=version)


@pytest.mark.parametrize(
    "extra_members",
    [
        {"blobs/sha256/" + "0" * 64: b"unreferenced blob"},
        {"unreferenced/private-key.pem": b"secret-like unreferenced content"},
    ],
)
def test_inspection_rejects_every_unreferenced_regular_member(
    tmp_path: Path,
    extra_members: dict[str, bytes],
) -> None:
    commit = "a" * 40
    version = f"0.0.0-candidate.{commit[:12]}"
    archive = tmp_path / "candidate.tar"
    write_oci_archive(
        archive,
        commit=commit,
        version=version,
        extra_members=extra_members,
    )

    with pytest.raises(ValueError, match="unreferenced regular member"):
        candidate.inspect_oci_archive(archive, commit=commit, version=version)


def test_inspection_accepts_only_reachable_parent_directories(tmp_path: Path) -> None:
    commit = "a" * 40
    version = f"0.0.0-candidate.{commit[:12]}"
    archive = tmp_path / "candidate.tar"
    write_oci_archive(
        archive,
        commit=commit,
        version=version,
        extra_directories=["blobs", "blobs/sha256"],
    )

    candidate.inspect_oci_archive(archive, commit=commit, version=version)


@pytest.mark.parametrize(
    "extra_directories",
    [["unreferenced-directory"], ["blobs", "blobs"]],
)
def test_inspection_rejects_unreachable_or_duplicate_directories(
    tmp_path: Path,
    extra_directories: list[str],
) -> None:
    commit = "a" * 40
    version = f"0.0.0-candidate.{commit[:12]}"
    archive = tmp_path / "candidate.tar"
    write_oci_archive(
        archive,
        commit=commit,
        version=version,
        extra_directories=extra_directories,
    )

    with pytest.raises(ValueError, match="unreferenced directory|duplicate members"):
        candidate.inspect_oci_archive(archive, commit=commit, version=version)


def test_candidate_archive_accepts_every_resource_limit_at_the_exact_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit = "a" * 40
    version = f"0.0.0-candidate.{commit[:12]}"
    archive = tmp_path / "candidate.tar"
    write_oci_archive(archive, commit=commit, version=version)
    dimensions = archive_resource_dimensions(archive)
    for constant, dimension in (
        ("MAX_ARCHIVE_BYTES", "archive_bytes"),
        ("MAX_ARCHIVE_MEMBERS", "outer_members"),
        ("MAX_ARCHIVE_REGULAR_MEMBERS", "outer_regular_members"),
        ("MAX_LAYERS", "layers"),
        ("MAX_COMPRESSED_LAYER_BYTES", "compressed_bytes"),
        ("MAX_TOTAL_COMPRESSED_LAYER_BYTES", "compressed_bytes"),
        ("MAX_EXPANDED_LAYER_BYTES", "expanded_bytes"),
        ("MAX_TOTAL_EXPANDED_LAYER_BYTES", "expanded_bytes"),
        ("MAX_LAYER_MEMBERS", "layer_members"),
        ("MAX_TOTAL_LAYER_MEMBERS", "layer_members"),
    ):
        monkeypatch.setattr(candidate, constant, dimensions[dimension])

    candidate.inspect_oci_archive(archive, commit=commit, version=version)


@pytest.mark.parametrize(
    ("constant", "dimension", "message"),
    [
        ("MAX_ARCHIVE_BYTES", "archive_bytes", "archive is too large"),
        ("MAX_ARCHIVE_MEMBERS", "outer_members", "too many members"),
        (
            "MAX_ARCHIVE_REGULAR_MEMBERS",
            "outer_regular_members",
            "too many regular members",
        ),
        ("MAX_LAYERS", "layers", "too many layers"),
        (
            "MAX_COMPRESSED_LAYER_BYTES",
            "compressed_bytes",
            "compressed layer is too large",
        ),
        (
            "MAX_TOTAL_COMPRESSED_LAYER_BYTES",
            "compressed_bytes",
            "aggregate compressed layers are too large",
        ),
        (
            "MAX_EXPANDED_LAYER_BYTES",
            "expanded_bytes",
            "expanded layer is too large",
        ),
        (
            "MAX_TOTAL_EXPANDED_LAYER_BYTES",
            "expanded_bytes",
            "aggregate expanded layers are too large",
        ),
        ("MAX_LAYER_MEMBERS", "layer_members", "too many members"),
        (
            "MAX_TOTAL_LAYER_MEMBERS",
            "layer_members",
            "aggregate layer members",
        ),
    ],
)
def test_candidate_archive_rejects_each_resource_just_over_its_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    dimension: str,
    message: str,
) -> None:
    commit = "a" * 40
    version = f"0.0.0-candidate.{commit[:12]}"
    archive = tmp_path / "candidate.tar"
    write_oci_archive(archive, commit=commit, version=version)
    dimensions = archive_resource_dimensions(archive)
    monkeypatch.setattr(candidate, constant, dimensions[dimension] - 1)

    with pytest.raises(ValueError, match=message):
        candidate.inspect_oci_archive(archive, commit=commit, version=version)


def test_candidate_archive_stops_a_compression_bomb_at_streaming_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit = "a" * 40
    version = f"0.0.0-candidate.{commit[:12]}"
    archive = tmp_path / "candidate.tar"
    write_oci_archive(archive, commit=commit, version=version)
    monkeypatch.setattr(candidate, "MAX_EXPANDED_LAYER_BYTES", 1024)

    with pytest.raises(ValueError, match="expanded layer is too large"):
        candidate.inspect_oci_archive(archive, commit=commit, version=version)


@pytest.mark.parametrize(
    "typeflag",
    [
        tarfile.XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.SOLARIS_XHDTYPE,
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_LONGLINK,
    ],
)
def test_tar_scan_rejects_oversized_special_headers_before_payload_read(
    typeflag: bytes,
) -> None:
    content = special_tar_header(
        typeflag,
        candidate.MAX_TAR_SPECIAL_HEADER_BYTES + 1,
    )

    with pytest.raises(ValueError, match="special tar header is too large"):
        candidate._scan_tar_headers(
            io.BytesIO(content),
            stream_bytes=len(content),
            maximum_members=candidate.MAX_ARCHIVE_MEMBERS,
            label="test archive",
        )


def test_tar_scan_accepts_special_header_at_exact_size_boundary() -> None:
    payload = b"x" * candidate.MAX_TAR_SPECIAL_HEADER_BYTES
    content = special_tar_header(
        tarfile.GNUTYPE_LONGNAME,
        len(payload),
        payload,
    )

    candidate._scan_tar_headers(
        io.BytesIO(content),
        stream_bytes=len(content),
        maximum_members=candidate.MAX_ARCHIVE_MEMBERS,
        label="test archive",
    )


def test_tar_scan_enforces_special_header_count_at_exact_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(candidate, "MAX_TAR_SPECIAL_HEADERS", 2)
    record = special_tar_record(tarfile.GNUTYPE_LONGNAME, 1, b"x")
    end = bytes(candidate.TAR_BLOCK_BYTES * 2)
    candidate._scan_tar_headers(
        io.BytesIO(record * 2 + end),
        stream_bytes=len(record * 2 + end),
        maximum_members=candidate.MAX_ARCHIVE_MEMBERS,
        label="test archive",
    )

    with pytest.raises(ValueError, match="too many special tar headers"):
        candidate._scan_tar_headers(
            io.BytesIO(record * 3 + end),
            stream_bytes=len(record * 3 + end),
            maximum_members=candidate.MAX_ARCHIVE_MEMBERS,
            label="test archive",
        )


def test_tar_scan_enforces_aggregate_special_bytes_at_exact_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(candidate, "MAX_TOTAL_TAR_SPECIAL_HEADER_BYTES", 2)
    record = special_tar_record(tarfile.GNUTYPE_LONGLINK, 1, b"x")
    end = bytes(candidate.TAR_BLOCK_BYTES * 2)
    candidate._scan_tar_headers(
        io.BytesIO(record * 2 + end),
        stream_bytes=len(record * 2 + end),
        maximum_members=candidate.MAX_ARCHIVE_MEMBERS,
        label="test archive",
    )

    with pytest.raises(ValueError, match="aggregate special tar headers"):
        candidate._scan_tar_headers(
            io.BytesIO(record * 3 + end),
            stream_bytes=len(record * 3 + end),
            maximum_members=candidate.MAX_ARCHIVE_MEMBERS,
            label="test archive",
        )


def test_tar_scan_rejects_gnu_sparse_header() -> None:
    content = special_tar_header(tarfile.GNUTYPE_SPARSE, 0)

    with pytest.raises(ValueError, match="unsupported GNU sparse metadata"):
        candidate._scan_tar_headers(
            io.BytesIO(content),
            stream_bytes=len(content),
            maximum_members=candidate.MAX_ARCHIVE_MEMBERS,
            label="test archive",
        )


def test_outer_archive_rejects_oversized_special_header_before_tarfile_iteration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = tmp_path / "candidate.oci.tar"
    archive.write_bytes(
        special_tar_header(
            tarfile.XHDTYPE,
            candidate.MAX_TAR_SPECIAL_HEADER_BYTES + 1,
        )
    )
    monkeypatch.setattr(
        candidate.tarfile,
        "open",
        lambda *_args, **_kwargs: pytest.fail(
            "outer tarfile iteration began before the raw scan"
        ),
    )

    with pytest.raises(ValueError, match="special tar header is too large"):
        candidate.inspect_oci_archive(archive, commit="a" * 40, version="candidate")


def test_inner_layer_rejects_oversized_special_header_before_tarfile_iteration(
    tmp_path: Path,
) -> None:
    commit = "a" * 40
    version = f"0.0.0-candidate.{commit[:12]}"
    archive = tmp_path / "candidate.oci.tar"
    write_oci_archive(
        archive,
        commit=commit,
        version=version,
        uncompressed_layer_override=special_tar_header(
            tarfile.GNUTYPE_LONGNAME,
            candidate.MAX_TAR_SPECIAL_HEADER_BYTES + 1,
        ),
    )

    with pytest.raises(ValueError, match="OCI layer special tar header is too large"):
        candidate.inspect_oci_archive(archive, commit=commit, version=version)


def test_tar_scan_rejects_malformed_pax_metadata() -> None:
    payload = b"12 path=bad"
    content = special_tar_header(tarfile.XHDTYPE, len(payload), payload)

    with pytest.raises(ValueError, match="malformed PAX metadata"):
        candidate._scan_tar_headers(
            io.BytesIO(content),
            stream_bytes=len(content),
            maximum_members=candidate.MAX_ARCHIVE_MEMBERS,
            label="test archive",
        )


def test_tar_scan_accepts_bounded_real_pax_long_paths() -> None:
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode="w", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("nested/" + "a" * 150)
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))

    candidate._scan_tar_headers(
        content,
        stream_bytes=len(content.getvalue()),
        maximum_members=candidate.MAX_LAYER_MEMBERS,
        label="test layer",
    )


@pytest.mark.parametrize("zero_blocks", [0, 1])
def test_outer_archive_requires_two_end_of_archive_blocks(
    tmp_path: Path,
    zero_blocks: int,
) -> None:
    commit = "a" * 40
    version = f"0.0.0-candidate.{commit[:12]}"
    archive = tmp_path / "candidate.oci.tar"
    write_oci_archive(archive, commit=commit, version=version)
    archive.write_bytes(trim_tar_end(archive.read_bytes(), zero_blocks))

    with pytest.raises(ValueError, match="missing the canonical tar end-of-archive"):
        candidate.inspect_oci_archive(archive, commit=commit, version=version)


def test_outer_archive_rejects_nonzero_data_after_end_of_archive(
    tmp_path: Path,
) -> None:
    commit = "a" * 40
    version = f"0.0.0-candidate.{commit[:12]}"
    archive = tmp_path / "candidate.oci.tar"
    write_oci_archive(archive, commit=commit, version=version)
    archive.write_bytes(
        archive.read_bytes() + b"x" + bytes(candidate.TAR_BLOCK_BYTES - 1)
    )

    with pytest.raises(ValueError, match="non-zero data after its end-of-archive"):
        candidate.inspect_oci_archive(archive, commit=commit, version=version)


@pytest.mark.parametrize("zero_blocks", [0, 1])
def test_inner_layer_requires_two_end_of_archive_blocks(
    tmp_path: Path,
    zero_blocks: int,
) -> None:
    commit = "a" * 40
    version = f"0.0.0-candidate.{commit[:12]}"
    archive = tmp_path / "candidate.oci.tar"
    write_oci_archive(
        archive,
        commit=commit,
        version=version,
        uncompressed_layer_override=trim_tar_end(minimal_layer_tar(), zero_blocks),
    )

    with pytest.raises(ValueError, match="missing the canonical tar end-of-archive"):
        candidate.inspect_oci_archive(archive, commit=commit, version=version)


def test_inner_layer_rejects_nonzero_data_after_end_of_archive(
    tmp_path: Path,
) -> None:
    commit = "a" * 40
    version = f"0.0.0-candidate.{commit[:12]}"
    archive = tmp_path / "candidate.oci.tar"
    layer = minimal_layer_tar() + b"x" + bytes(candidate.TAR_BLOCK_BYTES - 1)
    write_oci_archive(
        archive,
        commit=commit,
        version=version,
        uncompressed_layer_override=layer,
    )

    with pytest.raises(ValueError, match="non-zero data after its end-of-archive"):
        candidate.inspect_oci_archive(archive, commit=commit, version=version)


def test_candidate_archive_rejects_a_compressed_outer_wrapper(tmp_path: Path) -> None:
    commit = "a" * 40
    version = f"0.0.0-candidate.{commit[:12]}"
    raw = tmp_path / "candidate.oci.tar"
    compressed = tmp_path / "candidate.oci.tar.gz"
    write_oci_archive(raw, commit=commit, version=version)
    compressed.write_bytes(gzip.compress(raw.read_bytes(), mtime=0))

    with pytest.raises(ValueError, match="tar"):
        candidate.inspect_oci_archive(compressed, commit=commit, version=version)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("repository", "attacker/repository", "repository changed"),
        ("source_ref", "refs/pull/1/head", "source ref changed"),
        ("workflow", ".github/workflows/cd.yml", "workflow changed"),
        ("run_id", "0", "run ID"),
        ("run_attempt", 0, "run attempt"),
    ],
)
def test_finalize_rejects_rebound_producer_identity(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    args = build_inputs(tmp_path)
    setattr(args, field, value)

    with pytest.raises(ValueError, match=message):
        candidate.finalize(args)


def test_finalize_rejects_an_unusable_sbom(tmp_path: Path) -> None:
    args = build_inputs(tmp_path)
    args.raw_sbom.write_text(
        '{"bomFormat":"CycloneDX","specVersion":"1.5"}', encoding="utf-8"
    )

    with pytest.raises(ValueError, match="CycloneDX 1.6"):
        candidate.finalize(args)


def test_sbom_size_is_preflighted_before_any_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = build_inputs(tmp_path)
    size = args.raw_sbom.stat().st_size
    monkeypatch.setattr(candidate, "MAX_RAW_SBOM_BYTES", size - 1)
    original_open = Path.open

    def guarded_open(path: Path, *open_args: object, **open_kwargs: object):
        if path == args.raw_sbom:
            pytest.fail("oversized SBOM was opened before its lstat size preflight")
        return original_open(path, *open_args, **open_kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    with pytest.raises(ValueError, match="SBOM is too large"):
        candidate.finalize(args)


def test_sbom_accepts_its_exact_byte_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = build_inputs(tmp_path)
    monkeypatch.setattr(candidate, "MAX_RAW_SBOM_BYTES", args.raw_sbom.stat().st_size)

    candidate.finalize(args)


def test_sbom_rejects_non_regular_input_before_read(tmp_path: Path) -> None:
    args = build_inputs(tmp_path)
    args.raw_sbom.unlink()
    args.raw_sbom.mkdir()

    with pytest.raises(ValueError, match="SBOM is not a regular file"):
        candidate.finalize(args)


@pytest.mark.parametrize(
    ("constant", "path", "message"),
    [
        ("MAX_SBOM_TOP_LEVEL_KEYS", (), "too many top-level fields"),
        ("MAX_SBOM_COMPONENTS", ("components",), "components are missing"),
        (
            "MAX_SBOM_SCANNER_COMPONENTS",
            ("metadata", "tools", "components"),
            "not generated by Syft",
        ),
        ("MAX_SBOM_PROPERTIES", ("metadata", "properties"), "labels are missing"),
    ],
)
def test_sbom_collections_accept_exact_and_reject_over_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    path: tuple[str, ...],
    message: str,
) -> None:
    args = build_inputs(tmp_path)
    value = json.loads(args.raw_sbom.read_text(encoding="utf-8"))
    collection: object = value
    for item in path:
        collection = collection[item]  # type: ignore[index]
    size = len(collection)  # type: ignore[arg-type]
    monkeypatch.setattr(candidate, constant, size)
    candidate.finalize(args)

    monkeypatch.setattr(candidate, constant, size - 1)
    with pytest.raises(ValueError, match=message):
        candidate.finalize(args)


def test_sbom_dependencies_accept_exact_and_reject_over_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = build_inputs(tmp_path)
    value = json.loads(args.raw_sbom.read_text(encoding="utf-8"))
    value["dependencies"] = [{"ref": "candidate-image", "dependsOn": []}]
    args.raw_sbom.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setattr(candidate, "MAX_SBOM_DEPENDENCIES", 1)
    candidate.finalize(args)

    monkeypatch.setattr(candidate, "MAX_SBOM_DEPENDENCIES", 0)
    with pytest.raises(ValueError, match="dependencies changed"):
        candidate.finalize(args)


def test_sbom_dependency_fan_out_accepts_exact_and_rejects_exact_plus_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = build_inputs(tmp_path)
    value = json.loads(args.raw_sbom.read_text(encoding="utf-8"))
    value["dependencies"] = [
        {"ref": "candidate-image", "dependsOn": ["marty-verification-service"]}
    ]
    args.raw_sbom.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setattr(candidate, "MAX_SBOM_DEPENDENCY_EDGES_PER_ENTRY", 1)
    candidate.finalize(args)

    value["dependencies"][0]["dependsOn"].append("candidate-image")
    args.raw_sbom.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="fan-out is too large"):
        candidate.finalize(args)


def test_sbom_aggregate_dependency_edges_accept_exact_and_reject_exact_plus_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = build_inputs(tmp_path)
    value = json.loads(args.raw_sbom.read_text(encoding="utf-8"))
    value["dependencies"] = [
        {"ref": "candidate-image", "dependsOn": ["marty-verification-service"]},
        {"ref": "marty-verification-service", "dependsOn": ["candidate-image"]},
    ]
    args.raw_sbom.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setattr(candidate, "MAX_TOTAL_SBOM_DEPENDENCY_EDGES", 2)
    candidate.finalize(args)

    monkeypatch.setattr(candidate, "MAX_TOTAL_SBOM_DEPENDENCY_EDGES", 1)
    with pytest.raises(ValueError, match="aggregate dependency edges"):
        candidate.finalize(args)


def test_sbom_rejects_duplicate_dependency_edges(tmp_path: Path) -> None:
    args = build_inputs(tmp_path)
    value = json.loads(args.raw_sbom.read_text(encoding="utf-8"))
    value["dependencies"] = [
        {
            "ref": "candidate-image",
            "dependsOn": [
                "marty-verification-service",
                "marty-verification-service",
            ],
        }
    ]
    args.raw_sbom.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match="dependency edge is duplicated"):
        candidate.finalize(args)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update(components=[]), "components are missing"),
        (lambda value: value.update(components=[None]), "component changed"),
        (lambda value: value.update(components=[{}]), "component type changed"),
        (
            lambda value: value["components"].append(value["components"][0].copy()),
            "component reference is duplicated",
        ),
        (
            lambda value: value.update(
                dependencies=[{"ref": "missing", "dependsOn": []}]
            ),
            "dependency reference changed",
        ),
        (
            lambda value: value["metadata"]["component"].update(
                name="oci-archive:/other/image.tar"
            ),
            "source archive changed",
        ),
        (
            lambda value: value["metadata"]["component"].update(
                version="sha256:" + "0" * 64
            ),
            "source digest changed",
        ),
        (
            lambda value: value["metadata"]["component"].update(
                purl="pkg:oci/attacker"
            ),
            "contradictory",
        ),
        (
            lambda value: value["metadata"].update(tools={"components": []}),
            "not generated by Syft",
        ),
        (
            lambda value: value["metadata"]["properties"][0].update(
                value="https://attacker.invalid"
            ),
            "image labels changed",
        ),
    ],
)
def test_finalize_rejects_unbound_or_contradictory_sbom_identity(
    tmp_path: Path,
    mutation: Callable[[dict[str, object]], None],
    message: str,
) -> None:
    args = build_inputs(tmp_path)
    value = json.loads(args.raw_sbom.read_text(encoding="utf-8"))
    mutation(value)
    args.raw_sbom.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        candidate.finalize(args)


def test_finalize_rejects_a_rebound_dockerfile(tmp_path: Path) -> None:
    args = build_inputs(tmp_path)
    args.dockerfile = tmp_path / "Dockerfile"
    args.dockerfile.write_text("FROM scratch\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Dockerfile path changed"):
        candidate.finalize(args)


def test_buildx_archive_is_validated_and_consumed_by_supported_backend(
    tmp_path: Path,
    containerd_buildx_backend: None,
) -> None:
    del containerd_buildx_backend
    commit = hashlib.sha1(
        str(tmp_path).encode("utf-8"), usedforsecurity=False
    ).hexdigest()
    version = f"0.0.0-candidate.{commit[:12]}"
    build_reference = f"{candidate.LOCAL_IMAGE_REPOSITORY}:candidate-{commit}"
    archive_tag = f"candidate-{commit}"
    archive_reference = f"{archive_tag}:latest"
    verified_reference = f"{candidate.LOCAL_IMAGE_REPOSITORY}:verified-{commit}"
    cleanup_references = {
        archive_reference,
        build_reference,
        verified_reference,
    }
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """FROM scratch
ARG MARTY_RELEASE_VERSION
ARG MARTY_UI_SHA
ARG SERVICE_NAME
LABEL org.opencontainers.image.source="https://github.com/ElevenID/marty-ui" \\
      org.opencontainers.image.revision="${MARTY_UI_SHA}" \\
      org.opencontainers.image.version="${MARTY_RELEASE_VERSION}"
ENV SERVICE_NAME=${SERVICE_NAME} \\
    MARTY_RELEASE_VERSION=${MARTY_RELEASE_VERSION} \\
    MARTY_UI_SHA=${MARTY_UI_SHA}
COPY candidate-payload /usr/local/bin/marty-verification-service
""",
        encoding="utf-8",
    )
    (tmp_path / "candidate-payload").write_bytes(b"representative Rust service\n")
    archive = tmp_path / "buildx-candidate.oci.tar"
    try:
        result = subprocess.run(
            [
                "docker",
                "buildx",
                "build",
                "--file",
                str(dockerfile),
                "--tag",
                build_reference,
                "--platform",
                "linux/amd64",
                "--build-arg",
                "SERVICE_NAME=verification",
                "--build-arg",
                f"MARTY_RELEASE_VERSION={version}",
                "--build-arg",
                f"MARTY_UI_SHA={commit}",
                "--provenance=false",
                "--output",
                f"type=oci,dest={archive},compression=gzip,force-compression=true",
                str(tmp_path),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
        image = candidate.inspect_oci_archive(
            archive,
            commit=commit,
            version=version,
        )
        assert image["archive_tag"] == archive_tag
        cleanup_references.update({image["digest"], image["config_digest"]})

        subprocess.run(
            ["docker", "load", "--input", str(archive)],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        inspections = []
        for reference in (
            image["digest"],
            f"{image['archive_tag']}:latest",
            image["config_digest"],
        ):
            result = subprocess.run(
                ["docker", "image", "inspect", reference, "--format", "{{json .}}"],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                inspections.append((reference, json.loads(result.stdout)))
        assert inspections
        resolved_reference, inspected = inspections[0]
        cleanup_references.add(resolved_reference)
        loaded_id = inspected["Id"]
        descriptor = inspected.get("Descriptor")
        assert (
            isinstance(descriptor, dict) and descriptor.get("digest") == image["digest"]
        ) or loaded_id == image["config_digest"]

        subprocess.run(
            ["docker", "image", "tag", resolved_reference, verified_reference],
            check=True,
            timeout=30,
        )
        rebound = json.loads(
            subprocess.run(
                [
                    "docker",
                    "image",
                    "inspect",
                    verified_reference,
                    "--format",
                    "{{json .}}",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            ).stdout
        )
        assert rebound["Id"] == loaded_id
        assert verified_reference.removeprefix("docker.io/") in rebound["RepoTags"]
    finally:
        subprocess.run(
            ["docker", "image", "rm", "--force", *sorted(cleanup_references)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        for reference in cleanup_references:
            result = subprocess.run(
                ["docker", "image", "inspect", reference],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert result.returncode != 0, f"test image remained: {reference}"
