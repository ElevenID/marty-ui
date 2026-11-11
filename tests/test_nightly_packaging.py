"""Real child-process selection; synthetic release inputs do not grant admission."""
import json
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import package_nightly_installation as packaging


def executable(path, script):
    path.write_text("#!" + sys.executable + "\n" + script, encoding="utf-8")
    path.chmod(0o700)
    return path


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable transport fixture")
@pytest.mark.parametrize("selection", ["default", "relative", "absolute"])
def test_packaging_binds_both_renders_and_excludes_ambient_settings(tmp_path, monkeypatch, selection):
    source = tmp_path / "source"
    source.mkdir()
    tools = tmp_path / "chosen tools"
    tools.mkdir()
    observed = tmp_path / "packager.json"
    renderer_script = (
        "import json, os, sys\n"
        "keys = ('COMPOSE_FILE', 'COMPOSE_PROFILES', 'POSTGRES_IMAGE', 'HTTP_PROXY', 'SMTP_PASSWORD', "
        "'SELFHOST_IMAGE_PREFIX', 'SELFHOST_IMAGE_TAG', 'MARTY_KEYCLOAK_KMS_IMAGE')\n"
        "print(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd(), "
        "'environment': {key: os.environ[key] for key in keys if key in os.environ}}))\n"
    )
    renderer = executable(tools / "selected compose", renderer_script)
    executable(tools / "docker", renderer_script)
    packager = executable(tools / "selected packager", (
        "import json, pathlib, sys\n"
        f"pathlib.Path({str(observed)!r}).write_text(json.dumps(sys.argv[1:]))\n"
        "archive = sys.argv[sys.argv.index('--archive') + 1]\n"
        "pathlib.Path(archive + '.zip').write_bytes(b'synthetic archive')\n"
    ))
    candidate = {
        "tag": "v1.2.3-nightly.20261029.123", "source_sha": "a" * 40, "build_run_id": "123",
        "images": {"keycloak": {"uri": "ghcr.io/elevenid/keycloak", "digest": "sha256:" + "b" * 64}},
    }
    candidate_path = tmp_path / "candidate.json"
    candidate_path.write_text(json.dumps(candidate))
    monkeypatch.setattr(packaging, "validate_candidate", lambda value: value)
    monkeypatch.setattr(packaging, "pin_external_images", lambda *_: {})
    models = []
    def image_lock(_candidate, model, _source, _external):
        models.append(model)
        return {"synthetic": True}
    monkeypatch.setattr(packaging, "image_lock", image_lock)
    monkeypatch.setattr(packaging, "record", lambda *_: {"synthetic": True})
    monkeypatch.setattr(packaging, "produce", lambda *_: {"synthetic": True})
    monkeypatch.setenv("PATH", str(tools) + os.pathsep + os.environ["PATH"])
    for name in ("COMPOSE_FILE", "COMPOSE_PROFILES", "POSTGRES_IMAGE", "HTTP_PROXY", "SMTP_PASSWORD"):
        monkeypatch.setenv(name, "ambient-value-must-not-reach-renderer")
    monkeypatch.setenv("SELFHOST_IMAGE_PREFIX", "ambient-wrong-images")
    monkeypatch.chdir(tmp_path)
    selected = None if selection == "default" else renderer
    if selection == "relative":
        selected = selected.relative_to(tmp_path)
    output = tmp_path / "output"
    selected_packager = packager.relative_to(tmp_path) if selection == "relative" else packager
    packaging.package(source, candidate_path, selected_packager, output, selected)
    model, = models
    assert model["cwd"] == str(source)
    assert model["argv"][:1] == (["compose"] if selection == "default" else ["--profile"])
    assert "ambient-value-must-not-reach-renderer" not in model["environment"].values()
    assert model["environment"]["SELFHOST_IMAGE_PREFIX"] == "ghcr.io/elevenid/marty-ui"
    assert model["environment"]["SELFHOST_IMAGE_TAG"] == "1.2.3"
    assert model["environment"]["MARTY_KEYCLOAK_KMS_IMAGE"].endswith("@sha256:" + "b" * 64)
    downstream = json.loads(observed.read_text())
    if selection == "default":
        assert "--compose-executable" not in downstream
    else:
        assert downstream[downstream.index("--compose-executable") + 1] == str(renderer)
    assert (output / "SHA256SUMS").is_file()


@pytest.mark.parametrize("missing", ["packager", "renderer"])
def test_missing_explicit_tool_refuses_before_output(tmp_path, monkeypatch, missing):
    source = tmp_path / "source"
    source.mkdir()
    candidate = tmp_path / "candidate.json"
    candidate.write_text("{}")
    monkeypatch.setattr(packaging, "validate_candidate", lambda value: value)
    packager = tmp_path / "packager"
    renderer = tmp_path / "renderer"
    for path in (packager, renderer):
        if path.name != missing:
            path.touch()
    output = tmp_path / "output"
    with pytest.raises(FileNotFoundError):
        packaging.package(source, candidate, packager, output, renderer)
    assert not output.exists()
