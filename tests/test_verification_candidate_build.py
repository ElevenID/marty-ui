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
def docker_buildx_available() -> bool:
    if os.environ.get("MARTY_RUN_VERIFICATION_CANDIDATE_DOCKER_TESTS") != "1":
        return False
    if shutil.which("docker") is None:
        return False
    for command in (
        ["docker", "info", "--format", "{{.ServerVersion}}"],
        ["docker", "buildx", "version"],
    ):
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if result.returncode != 0:
            return False
    return True


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
    malformed_compression: bool = False,
    wrong_diff_id: bool = False,
    environment: list[str] | None = None,
    archive_tag: str | None = None,
) -> tuple[str, str]:
    layer_tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=layer_tar_buffer, mode="w") as layer_archive:
        content = b"candidate layer"
        member = tarfile.TarInfo("usr/local/bin/marty-verification-service")
        member.size = len(content)
        layer_archive.addfile(member, io.BytesIO(content))
    uncompressed_layer = layer_tar_buffer.getvalue()
    layer = (
        b"not gzip content"
        if malformed_compression
        else gzip.compress(uncompressed_layer, mtime=0)
    )
    diff_id = f"sha256:{hashlib.sha256(uncompressed_layer).hexdigest()}"
    config = candidate.canonical_json(
        {
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {
                "type": "layers",
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
                    "org.opencontainers.image.source": "https://github.com/ElevenID/marty-ui",
                    "org.opencontainers.image.revision": revision or commit,
                    "org.opencontainers.image.version": version,
                },
            },
        }
    )
    config_descriptor = descriptor(config, candidate.OCI_CONFIG)
    layer_descriptor = descriptor(layer, candidate.OCI_GZIP_LAYER)
    if corrupt_layer:
        layer_descriptor["digest"] = "sha256:" + "9" * 64
    manifest = candidate.canonical_json(
        {
            "schemaVersion": 2,
            "mediaType": candidate.OCI_MANIFEST,
            "config": config_descriptor,
            "layers": [layer_descriptor],
        }
    )
    manifest_descriptor = descriptor(
        manifest,
        candidate.OCI_MANIFEST,
        platform=platform or {"architecture": "amd64", "os": "linux"},
        annotations={
            "org.opencontainers.image.ref.name": archive_tag or f"candidate-{commit}"
        },
    )
    index = candidate.canonical_json(
        {"schemaVersion": 2, "manifests": [manifest_descriptor]}
    )
    layout = candidate.canonical_json({"imageLayoutVersion": "1.0.0"})
    members = {
        "oci-layout": layout,
        "index.json": index,
        f"blobs/sha256/{str(config_descriptor['digest']).split(':', 1)[1]}": config,
        f"blobs/sha256/{str(manifest_descriptor['digest']).split(':', 1)[1]}": manifest,
        f"blobs/sha256/{hashlib.sha256(layer).hexdigest()}": layer,
    }
    with tarfile.open(path, "w") as archive:
        for name, content in members.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return str(manifest_descriptor["digest"]), str(config_descriptor["digest"])


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
        ({"revision": "b" * 40}, "source labels changed"),
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


def test_buildx_exports_the_commit_bound_archive_tag(
    tmp_path: Path,
    docker_buildx_available: bool,
) -> None:
    if not docker_buildx_available:
        pytest.skip("Docker daemon or Buildx is unavailable")
    commit = "a" * 40
    build_reference = f"{candidate.LOCAL_IMAGE_REPOSITORY}:candidate-{commit}"
    archive_tag = f"candidate-{commit}"
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\n", encoding="utf-8")
    archive = tmp_path / "buildx-candidate.oci.tar"

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
            "--output",
            f"type=oci,dest={archive}",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    with tarfile.open(archive, "r:*") as exported:
        index_member = exported.extractfile("index.json")
        assert index_member is not None
        index = json.load(index_member)

    assert (
        index["manifests"][0]["annotations"]["org.opencontainers.image.ref.name"]
        == archive_tag
    )


def test_real_oci_archive_loads_and_can_be_bound_to_a_verified_reference(
    tmp_path: Path,
    docker_buildx_available: bool,
) -> None:
    if not docker_buildx_available:
        pytest.skip("Docker daemon or Buildx is unavailable")
    commit = hashlib.sha1(
        str(tmp_path).encode("utf-8"), usedforsecurity=False
    ).hexdigest()
    version = f"0.0.0-candidate.{commit[:12]}"
    archive = tmp_path / "candidate.oci.tar"
    manifest_digest, config_digest = write_oci_archive(
        archive,
        commit=commit,
        version=version,
    )
    archive_reference = f"candidate-{commit}:latest"
    verified_reference = f"{candidate.LOCAL_IMAGE_REPOSITORY}:verified-{commit}"
    try:
        subprocess.run(["docker", "load", "--input", str(archive)], check=True)
        inspections = []
        for reference in (manifest_digest, archive_reference, config_digest):
            result = subprocess.run(
                ["docker", "image", "inspect", reference, "--format", "{{json .}}"],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                inspections.append((reference, json.loads(result.stdout)))
        assert inspections
        resolved_reference, inspected = inspections[0]
        loaded_id = inspected["Id"]
        descriptor = inspected.get("Descriptor")
        assert (
            isinstance(descriptor, dict) and descriptor.get("digest") == manifest_digest
        ) or loaded_id == config_digest

        subprocess.run(
            ["docker", "image", "tag", resolved_reference, verified_reference],
            check=True,
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
            ).stdout
        )
        assert rebound["Id"] == loaded_id
        assert verified_reference.removeprefix("docker.io/") in rebound["RepoTags"]
    finally:
        subprocess.run(
            [
                "docker",
                "image",
                "rm",
                "--force",
                verified_reference,
                archive_reference,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
