"""Unsigned image identity binding; synthetic archives are not runtime qualification."""

from __future__ import annotations

import hashlib
import base64
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_verification_candidate as oci
import prepare_installer_development_signing_image as development

SPEC = importlib.util.spec_from_file_location(
    "verification_oci_test_support", ROOT / "tests/test_verification_candidate_build.py"
)
assert SPEC is not None and SPEC.loader is not None
support = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(support)


def environment(source: str) -> list[str]:
    return [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "SIGNING_KEYS_SERVICE_PORT=8017",
        "RUST_LOG=info",
        f"MARTY_RELEASE_VERSION=unsigned-installer-development-{source}",
        f"MARTY_UI_SHA={source}",
    ]


def write_image(path: Path, source: str, **changes: Any) -> tuple[str, str]:
    options = {
        "environment": environment(source),
        "archive_tag": f"installer-development-signing-keys-{source}",
        "runtime_config": {
            "Entrypoint": ["/usr/local/bin/marty-signing-keys"],
            "User": "10001:10001",
        },
        **changes,
    }
    return support.write_oci_archive(
        path,
        commit=source,
        version=f"unsigned-installer-development-{source}",
        **options,
    )


def inspect(path: Path, source: str) -> dict[str, Any]:
    return oci.inspect_oci_archive(
        path,
        commit=source,
        version=f"unsigned-installer-development-{source}",
        profile=oci.SIGNING_KEYS_DEVELOPMENT_PROFILE,
    )


def metadata(image: dict[str, Any], source: str) -> dict[str, Any]:
    return {
        "buildx.build.ref": "isolated-builder/isolated-node/build-id",
        "containerimage.config.digest": image["config_digest"],
        "containerimage.digest": image["export_digest"],
        "image.name": f"{oci.SIGNING_KEYS_DEVELOPMENT_REPOSITORY}:{image['archive_tag']}",
        "buildx.build.provenance": {
            "buildType": development.BUILD_TYPE,
            "invocation": {
                "configSource": {"entryPoint": development.DOCKERFILE},
                "parameters": {
                    "frontend": "gateway.v0",
                    "args": {
                        "source": "docker/dockerfile:1.7",
                        "cmdline": "docker/dockerfile:1.7",
                        "filename": development.DOCKERFILE,
                        "platform": "linux/amd64",
                        "build-arg:CARGO_BUILD_JOBS": "1",
                        "build-arg:MARTY_UI_SHA": source,
                        "build-arg:MARTY_RELEASE_VERSION": f"unsigned-installer-development-{source}",
                    },
                },
            },
            "metadata": {
                f"{development.BUILD_TYPE}#metadata": {
                    "vcs": {"revision": source},
                    "source": {"infos": [{
                        "filename": "Dockerfile",
                        "data": base64.b64encode((ROOT / development.DOCKERFILE).read_bytes()).decode(),
                    }]},
                },
            },
        },
    }


def git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        [
            "git", "-c", "user.name=Installer Test", "-c",
            "user.email=installer-test@example.invalid", "-C", str(root), *arguments,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    ).stdout.strip()


@pytest.fixture
def inputs(tmp_path: Path) -> dict[str, Any]:
    source = tmp_path / "source"
    path = source / development.DOCKERFILE
    path.parent.mkdir(parents=True)
    path.write_bytes((ROOT / development.DOCKERFILE).read_bytes())
    scripts = source / "scripts"
    scripts.mkdir()
    for name in ("build_verification_candidate.py", "prepare_installer_development_signing_image.py"):
        (scripts / name).write_bytes((ROOT / "scripts" / name).read_bytes())
    (source / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    git(source, "init", "-q")
    git(source, "add", ".")
    git(source, "commit", "--no-gpg-sign", "-qm", "synthetic source identity")
    commit = git(source, "rev-parse", "HEAD")
    archive = tmp_path / "signing.oci.tar"
    write_image(archive, commit)
    build_metadata = tmp_path / "build-metadata.json"
    build_metadata.write_text(json.dumps(metadata(inspect(archive, commit), commit)))
    return {
        "source_root": source,
        "source_sha": commit,
        "archive": archive,
        "build_metadata": build_metadata,
        "output": tmp_path / "development-image-binding.json",
    }


@pytest.mark.parametrize("nested", [False, True])
def test_closed_signing_profile_binds_oci_without_claiming_release_uri(
    tmp_path: Path, nested: bool,
) -> None:
    source = "a" * 40
    archive = tmp_path / "image.tar"
    manifest, config = write_image(archive, source, nested_index=nested)
    image = inspect(archive, source)
    assert image["digest"] == manifest
    assert image["config_digest"] == config
    assert "uri" not in image
    assert (image["export_digest"] != manifest) == nested
    with pytest.raises(ValueError, match="archive tag changed"):
        oci.inspect_oci_archive(archive, commit=source, version="candidate")


@pytest.mark.parametrize(
    "changes",
    [
        {"environment": environment("b" * 40)},
        {"environment": environment("a" * 40) + ["SERVICE_NAME=signing-keys"]},
        {"environment": environment("a" * 40) + ["AWS_ACCESS_KEY_ID=unexpected"]},
        {"environment": environment("a" * 40) + ["MARTY_UI_SHA=" + "a" * 40]},
        {"runtime_config": {"Entrypoint": ["/bin/sh"], "User": "10001:10001"}},
        {"runtime_config": {"Entrypoint": ["/usr/local/bin/marty-signing-keys"], "User": "0"}},
        {"runtime_config": {"Entrypoint": ["/usr/local/bin/marty-signing-keys"], "User": "10001:10001", "Cmd": ["extra"]}},
        {"runtime_config": {"Entrypoint": ["/usr/local/bin/marty-signing-keys"], "User": "10001:10001", "Volumes": {"/unexpected": {}}}},
        {"revision": "b" * 40},
        {"version_label": "release"},
        {"source_label": "https://example.invalid/other"},
        {"archive_tag": "candidate-" + "a" * 40},
        {"platform": {"architecture": "arm64", "os": "linux"}},
        {"config_architecture": "arm64"},
        {"extra_members": {"unreferenced.json": b"{}"}},
        {"image_annotations": {"io.containerd.image.name": "foreign/image:latest"}},
        {"image_annotations": {"unexpected.tag": "foreign"}},
    ],
)
def test_signing_profile_rejects_other_source_runtime_platform_and_extras(
    tmp_path: Path, changes: dict[str, Any],
) -> None:
    archive = tmp_path / "image.tar"
    write_image(archive, "a" * 40, **changes)
    with pytest.raises(ValueError):
        inspect(archive, "a" * 40)


def test_preparation_binds_clean_git_tree_dockerfile_native_build_and_archive(
    inputs: dict[str, Any],
) -> None:
    receipt = development.prepare(**inputs)
    assert json.loads(inputs["output"].read_bytes()) == receipt
    assert set(receipt) == {
        "schema", "role", "source_sha", "source_tree_sha", "dockerfile_sha256",
        "build_metadata_sha256", "archive_sha256", "archive_size", "manifest_digest",
        "config_digest", "platform", "version", "archive_tag",
    }
    assert receipt["schema"] == development.SCHEMA
    assert receipt["role"] == "signing-keys"
    assert receipt["source_tree_sha"] == git(inputs["source_root"], "rev-parse", "HEAD^{tree}")
    for field, path in [
        ("dockerfile_sha256", inputs["source_root"] / development.DOCKERFILE),
        ("build_metadata_sha256", inputs["build_metadata"]),
        ("archive_sha256", inputs["archive"]),
    ]:
        assert receipt[field] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert receipt["archive_size"] == inputs["archive"].stat().st_size
    assert inputs["output"].stat().st_mode & 0o777 == 0o600
    before = inputs["output"].read_bytes()
    with pytest.raises(FileExistsError):
        development.prepare(**inputs)
    assert inputs["output"].read_bytes() == before


def test_signing_profile_allows_only_its_fixed_local_build_name(tmp_path: Path) -> None:
    source = "a" * 40
    archive = tmp_path / "image.tar"
    reference = f"{oci.SIGNING_KEYS_DEVELOPMENT_REPOSITORY}:installer-development-signing-keys-{source}"
    write_image(archive, source, image_annotations={
        "io.containerd.image.name": reference,
        "org.opencontainers.image.created": "2026-10-31T12:00:00Z",
    })
    assert inspect(archive, source)["archive_tag"] == f"installer-development-signing-keys-{source}"


def test_native_basename_is_bound_by_actual_dockerfile_bytes(inputs: dict[str, Any]) -> None:
    value = json.loads(inputs["build_metadata"].read_bytes())
    invocation = value["buildx.build.provenance"]["invocation"]
    invocation["configSource"]["entryPoint"] = "Dockerfile"
    invocation["parameters"]["args"]["filename"] = "Dockerfile"
    inputs["build_metadata"].write_text(json.dumps(value))
    assert development.prepare(**inputs)["source_sha"] == inputs["source_sha"]


@pytest.mark.parametrize("fault", ["source", "tracked", "untracked", "ignored", "dockerfile-symlink"])
def test_preparation_refuses_dirty_or_different_source_without_output(
    inputs: dict[str, Any], fault: str,
) -> None:
    root = inputs["source_root"]
    if fault == "source":
        inputs["source_sha"] = "f" * 40
    elif fault == "tracked":
        (root / development.DOCKERFILE).write_text("FROM scratch\n")
    elif fault in {"untracked", "ignored"}:
        (root / f"{fault}.txt").write_text("unexpected build context")
    else:
        path = root / development.DOCKERFILE
        payload = root / "Dockerfile.payload"
        path.rename(payload)
        path.symlink_to("../../../Dockerfile.payload")
        git(root, "add", ".")
        git(root, "commit", "--no-gpg-sign", "-qm", "symlink source")
        inputs["source_sha"] = git(root, "rev-parse", "HEAD")
    with pytest.raises(ValueError):
        development.prepare(**inputs)
    assert not inputs["output"].exists()


@pytest.mark.parametrize(
    "fault",
    ["config", "image", "source", "version", "jobs", "extra-argument", "filename",
     "platform", "target", "missing-provenance", "foreign-frontend", "foreign-syntax",
     "dirty-build-source", "different-built-dockerfile", "image-name", "extra-field", "duplicate"],
)
def test_preparation_requires_actual_matching_native_build_evidence(
    inputs: dict[str, Any], fault: str,
) -> None:
    path = inputs["build_metadata"]
    value = json.loads(path.read_bytes())
    parameters = value["buildx.build.provenance"]["invocation"]["parameters"]
    arguments = parameters["args"]
    if fault in {"config", "image"}:
        key = "containerimage.config.digest" if fault == "config" else "containerimage.digest"
        value[key] = "sha256:" + "f" * 64
    elif fault in {"source", "version", "jobs", "extra-argument"}:
        key = {"source": "MARTY_UI_SHA", "version": "MARTY_RELEASE_VERSION",
               "jobs": "CARGO_BUILD_JOBS", "extra-argument": "SERVICE_NAME"}[fault]
        arguments[f"build-arg:{key}"] = "unexpected"
    elif fault in {"filename", "platform", "target"}:
        arguments[fault] = "unexpected"
    elif fault == "missing-provenance":
        del value["buildx.build.provenance"]
    elif fault == "foreign-frontend":
        parameters["frontend"] = "unknown.v0"
    elif fault == "foreign-syntax":
        arguments["source"] = "foreign/frontend:latest"
    elif fault == "dirty-build-source":
        value["buildx.build.provenance"]["metadata"][f"{development.BUILD_TYPE}#metadata"]["vcs"]["revision"] += "-dirty"
    elif fault == "different-built-dockerfile":
        value["buildx.build.provenance"]["metadata"][f"{development.BUILD_TYPE}#metadata"]["source"]["infos"][0]["data"] = base64.b64encode(b"FROM scratch\n").decode()
    elif fault == "image-name":
        value["image.name"] = "foreign/image:latest"
    elif fault == "extra-field":
        value["publisher_authenticated"] = True
    else:
        path.write_text('{"containerimage.digest":"a","containerimage.digest":"b"}')
    if fault != "duplicate":
        path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        development.prepare(**inputs)
    assert not inputs["output"].exists()


@pytest.mark.parametrize("fault", ["archive", "metadata", "source"])
def test_preparation_rechecks_inputs_before_writing_authority(
    inputs: dict[str, Any], monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    inspect_original = oci.inspect_oci_archive

    def inspect_then_change(*args: Any, **kwargs: Any) -> dict[str, Any]:
        image = inspect_original(*args, **kwargs)
        if fault == "archive":
            with inputs["archive"].open("ab") as archive:
                archive.write(b"changed")
        elif fault == "metadata":
            inputs["build_metadata"].write_text("{}")
        else:
            (inputs["source_root"] / "unexpected.txt").write_text("changed")
        return image

    monkeypatch.setattr(oci, "inspect_oci_archive", inspect_then_change)
    with pytest.raises(ValueError):
        development.prepare(**inputs)
    assert not inputs["output"].exists()


@pytest.mark.parametrize("fault", ["symlink", "hardlink", "writable"])
def test_preparation_refuses_unsafe_archive_path(inputs: dict[str, Any], fault: str) -> None:
    archive = inputs["archive"]
    if fault == "symlink":
        actual = archive.with_name("actual.tar")
        archive.rename(actual)
        archive.symlink_to(actual)
    elif fault == "hardlink":
        os.link(archive, archive.with_name("alias.tar"))
    else:
        archive.chmod(0o666)
    with pytest.raises(ValueError):
        development.prepare(**inputs)
    assert not inputs["output"].exists()


def test_cli_writes_only_the_explicit_unsigned_binding(inputs: dict[str, Any]) -> None:
    command = [sys.executable, str(inputs["source_root"] / "scripts/prepare_installer_development_signing_image.py")]
    for key, value in inputs.items():
        command.extend(["--" + key.replace("_", "-"), str(value)])
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["classification"] == "UNSIGNED DEVELOPMENT ONLY"
    assert git(inputs["source_root"], "status", "--porcelain=v1", "--ignored=matching") == ""
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert result.returncode == 2
    assert "binding refused" in result.stderr
