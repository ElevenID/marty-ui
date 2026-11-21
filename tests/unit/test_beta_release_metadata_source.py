"""The operator may support two paths, but must still read one exact Git source."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import prepare_beta_release_metadata as metadata
import repair_beta_release_metadata as repair
import operator_demo_catalog as catalog
from scoped_native_runtime import ref


ROOT = Path(__file__).resolve().parents[2]
CURRENT, LEGACY = catalog.DEMO_TEMPLATE_PATHS
TEMPLATE = (ROOT / CURRENT).read_bytes().replace(b"\r\n", b"\n")
# Exact template from signed v1.1.273 source ca58b8bec939f5b26bebecd849edf55b5c4af5ae;
# v1.1.274 source 3ff1328d163f2dca38e369f17bda77b6334808eb carries the same bytes.
HISTORICAL_TEMPLATE = (ROOT / "tests/fixtures/demo-manifests/2026.08.0-nightly273.json").read_bytes().replace(b"\r\n", b"\n")
TEMPLATES = {CURRENT: TEMPLATE, LEGACY: HISTORICAL_TEMPLATE}


def git(repository, *args):
    return subprocess.run(
        ["git", "-C", str(repository), *args],
        capture_output=True,
        check=True,
        timeout=30,
    ).stdout


@pytest.fixture
def repository(tmp_path):
    path = tmp_path / "product"
    path.mkdir()
    git(path, "init", "-q", "--object-format=sha1")
    git(path, "config", "user.name", "Source resolver test")
    git(path, "config", "user.email", "source-resolver@example.invalid")
    git(path, "config", "commit.gpgSign", "false")
    git(path, "config", "core.autocrlf", "false")
    return path


def write(repository, filename, content):
    path = repository / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def commit(repository):
    git(repository, "add", "--all")
    git(repository, "commit", "-qm", "Product source", "--allow-empty")
    return git(repository, "rev-parse", "HEAD").decode().strip()


@pytest.mark.parametrize("filename", [LEGACY, CURRENT])
def test_reads_original_bytes_from_either_pinned_product_layout(repository, filename):
    original = TEMPLATES[filename]
    path = write(repository, filename, original)
    revision = commit(repository)
    # Neither the working copy nor the current branch is the source authority.
    path.write_bytes(b"a newer changed template")
    commit(repository)
    path.write_bytes(b"uncommitted changes")
    assert metadata.source_demo_template(repository, revision) == original
    expected_hash = (
        catalog.OPERATOR_TEMPLATE_SHA256 if filename == CURRENT
        else "3e643f3b471daac620c670aa506c654fb7894b940744c83169775fb643a655f1"
    )
    assert hashlib.sha256(original).hexdigest() == expected_hash


def test_current_path_has_precedence_over_retired_bytes(repository):
    write(repository, CURRENT, TEMPLATE)
    write(repository, LEGACY, b"retired bytes are not the current template")
    assert metadata.source_demo_template(repository, commit(repository)) == TEMPLATE


def test_changed_current_template_cannot_fall_back_to_historical_bytes(repository):
    write(repository, CURRENT, TEMPLATE + b"\n")
    write(repository, LEGACY, HISTORICAL_TEMPLATE)
    with pytest.raises(ValueError, match="SOURCE_DEMO_TEMPLATE_DIGEST_CHANGED"):
        metadata.source_demo_template(repository, commit(repository))


def test_no_reviewed_path_is_an_explicit_failure(repository):
    with pytest.raises(ValueError, match="SOURCE_DEMO_TEMPLATE_MISSING"):
        metadata.source_demo_template(repository, commit(repository))


@pytest.mark.parametrize("kind", ["symlink", "directory", "executable"])
def test_nonregular_current_entry_never_uses_a_valid_legacy_template(repository, kind):
    write(repository, LEGACY, TEMPLATE)
    if kind == "symlink":
        path = repository / CURRENT
        path.parent.mkdir(parents=True)
        path.symlink_to(repository / LEGACY)
    elif kind == "directory":
        write(repository, CURRENT + "/child.json", TEMPLATE)
    else:
        write(repository, CURRENT, TEMPLATE)
        git(repository, "add", CURRENT)
        git(repository, "update-index", "--chmod=+x", CURRENT)
        # Preserve the explicit index mode even on filesystems without chmod.
        git(repository, "config", "core.filemode", "false")
    with pytest.raises(ValueError, match="SOURCE_DEMO_TEMPLATE_ENTRY_INVALID"):
        metadata.source_demo_template(repository, commit(repository))


@pytest.mark.parametrize("revision", ["HEAD", "main", "v1.0.0", "a" * 12, "A" * 40, None])
def test_moving_or_invalid_revision_is_rejected_before_git(repository, monkeypatch, revision):
    def unexpected(*args, **kwargs):
        pytest.fail("Invalid source authority must not reach Git")

    monkeypatch.setattr(catalog.subprocess, "run", unexpected)
    with pytest.raises(ValueError, match="SOURCE_COMMIT_SHA_REQUIRED"):
        metadata.source_demo_template(repository, revision)
    with pytest.raises(ValueError, match="SOURCE_COMMIT_SHA_REQUIRED"):
        metadata.git_blob(repository, revision, "rust/Cargo.lock")


def test_absent_commit_does_not_fall_back_to_checkout(repository):
    write(repository, CURRENT, TEMPLATE)
    commit(repository)
    with pytest.raises(subprocess.CalledProcessError):
        metadata.source_demo_template(repository, "0" * 40)


def test_tree_object_is_not_a_product_commit(repository):
    write(repository, CURRENT, TEMPLATE)
    revision = commit(repository)
    tree = git(repository, "rev-parse", revision + "^{tree}").decode().strip()
    with pytest.raises(ValueError, match="SOURCE_REVISION_NOT_COMMIT"):
        metadata.source_demo_template(repository, tree)


def test_missing_repository_is_not_a_missing_path(tmp_path):
    with pytest.raises(subprocess.CalledProcessError):
        metadata.source_demo_template(tmp_path / "absent", "a" * 40)


@pytest.mark.parametrize("failure", ["auth", "network", "timeout"])
@pytest.mark.parametrize("operation", ["ls-tree", "show"])
def test_git_failure_never_falls_back(repository, monkeypatch, failure, operation):
    write(repository, CURRENT, TEMPLATE)
    write(repository, LEGACY, TEMPLATE)
    revision = commit(repository)
    run = subprocess.run
    attempts = []

    def failing(command, **kwargs):
        attempts.append(command)
        if operation in command:
            if failure == "timeout":
                raise subprocess.TimeoutExpired(command, 30)
            error = b"Authentication failed" if failure == "auth" else b"Could not resolve host"
            raise subprocess.CalledProcessError(128, command, stderr=error)
        return run(command, **kwargs)

    monkeypatch.setattr(catalog.subprocess, "run", failing)
    expected = subprocess.TimeoutExpired if failure == "timeout" else subprocess.CalledProcessError
    with pytest.raises(expected):
        metadata.source_demo_template(repository, revision)
    assert not any(LEGACY in argument for command in attempts for argument in command)


def test_git_replacement_cannot_change_the_pinned_source(repository):
    path = write(repository, CURRENT, TEMPLATE)
    original = commit(repository)
    path.write_bytes(b"replacement source")
    replacement = commit(repository)
    git(repository, "replace", original, replacement)
    assert git(repository, "show", original + ":" + CURRENT) == b"replacement source"
    assert metadata.source_demo_template(repository, original) == TEMPLATE


def preparation_config(repository, tmp_path, monkeypatch, filename):
    template = write(repository, filename, TEMPLATES[filename])
    cargo = write(repository, "rust/Cargo.lock", b"".join(
        (
            '[[package]]\nname = "' + name + '"\nsource = "git+https://github.com/ElevenID/'
            + name + '?rev=' + digit * 40 + '#' + digit * 40 + '"\n'
        ).encode()
        for name, digit in (("marty-core", "a"), ("marty-microservices-framework", "b"))
    ))
    revision = commit(repository)

    def bound(name, value):
        return ref(write(tmp_path, name, json.dumps(value).encode()))

    roles = ["gateway", "ui-prod", *["role-" + str(i) for i in range(20)]]
    image = "registry.invalid/service@sha256:" + "1" * 64
    private = tmp_path / "home/.codex/private"
    private.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    return dict(
        schema="marty.prepare-beta-release-metadata/v1",
        scope="FUNCTIONAL_ONLY", releaseQualified=False, recordingQualified=False,
        releaseLock=bound("signed.json", {
            "release": "marty-ui@1.1.273",
            "services": {("ui" if role == "ui-prod" else role): image for role in roles},
        }),
        productDescriptor=bound("descriptor.json", {"source": {
            "repository": "https://github.com/ElevenID/marty-ui", "commit": revision,
        }}),
        productRepository=str(repository), cargoLock=ref(cargo), template=ref(template),
        runtimeObservation=bound("runtime.json", {"binding": {
            "runtimeKind": "SIGNED_NIGHTLY_IMAGES",
            "roles": [
                {"role": role, "source": revision, "containerId": f"{index:064x}", "reference": image}
                for index, role in enumerate(roles)
            ],
        }}),
        sourceStage=bound("stage.json", {
            "state": "SOURCE_BUNDLES_READY", "product": {"revision": revision},
            "sources": {"recorder": {"revision": "c" * 40}},
        }),
        captureRecorderRevision="c" * 40,
        gatewayModel=bound("gateway.json", {"services": {"gateway": {
            "image": image, "environment": {
                "MARTY_RELEASE_VERSION": "1.1.273", "MARTY_UI_SHA": revision,
                "ELEVENID_COMPONENT_REVISIONS_JSON": "{}", "ELEVENID_IMAGE_DIGESTS_JSON": "{}",
            },
        }}}),
        uiModel=bound("ui.json", {"services": {"ui-prod": {"image": image, "volumes": []}}}),
        outputRoot=str(private / "prepared"),
    )


@pytest.mark.parametrize("filename", [LEGACY, CURRENT])
def test_preparation_binds_actual_product_template_without_qualification(repository, tmp_path, monkeypatch, filename):
    config = preparation_config(repository, tmp_path, monkeypatch, filename)
    result = metadata.prepare(config)
    manifest = metadata.load(result["publicManifest"])
    assert result["state"] == "PREPARED_BETA_METADATA_NOT_SERVED_OR_QUALIFIED"
    assert result["betaMutation"] is False
    assert result["releaseQualified"] is result["recordingQualified"] is False
    assert manifest["demo_application_revision"] == result["source"]
    assert manifest["recorder_revision"]["value"] == "c" * 40
    assert manifest["release_evidence"]["recorded_at"] is None
    assert manifest["release_ready"] is manifest["public_demo_ready"] is False


@pytest.mark.parametrize("filename", [LEGACY, CURRENT])
def test_preparation_rejects_a_hash_bound_file_that_differs_from_the_product(repository, tmp_path, monkeypatch, filename):
    config = preparation_config(repository, tmp_path, monkeypatch, filename)
    config["template"] = ref(write(tmp_path, "other-template.json", TEMPLATE + b"\n"))
    with pytest.raises(ValueError, match="TEMPLATE_NOT_COMMITTED_PRODUCT"):
        metadata.prepare(config)
    assert not Path(config["outputRoot"]).exists()


@pytest.mark.parametrize("filename", [LEGACY, CURRENT])
def test_repair_preserves_pinned_product_template_binding(repository, tmp_path, monkeypatch, filename):
    prepared_config = preparation_config(repository, tmp_path, monkeypatch, filename)
    prepared = metadata.prepare(prepared_config)
    # static_contract reads these transport refs but never imports or executes them.
    transport = ref(write(tmp_path, "transport.py", b"# Read-only fixture; never executed.\n"))
    monkeypatch.setattr(repair, "GUARD_SHA", transport["sha256"])
    source_files = {name: ref(ROOT / "scripts" / name) for name in repair.SOURCE_FILES}
    config = dict(
        schema="marty.beta-release-metadata-repair-input/v1",
        roles=list(repair.ROLES), betaOnly=True,
        runId="00000000-0000-4000-8000-000000000001",
        releaseQualified=False, recordingQualified=False,
        sourceSha256=source_files["repair_beta_release_metadata.py"]["sha256"],
        sourceFiles=source_files, guardSource=transport, dockerExecutable=transport,
        oldModels={"gateway": prepared_config["gatewayModel"], "ui-prod": prepared_config["uiModel"]},
        newModels={"gateway": prepared["gatewayModel"], "ui-prod": prepared["uiModel"]},
        expectedMarker=prepared["expectedMarker"], publicManifest=prepared["publicManifest"],
        sourceManifest=prepared["sourceManifest"], productRevision=prepared["source"],
        oldCids={"gateway": f"{0:064x}", "ui-prod": f"{1:064x}"},
        **{key: prepared_config[key] for key in (
            "productRepository", "productDescriptor", "releaseLock", "runtimeObservation",
            "captureRecorderRevision", "cargoLock", "template",
        )},
    )
    _, _, marker, identities = repair.static_contract(config)
    assert marker["marty_ui_sha"] == prepared["source"]
    assert identities["ui-prod"]["source"] == prepared["source"]
    config["template"] = ref(write(tmp_path, "other-repair-template.json", TEMPLATE + b"\n"))
    with pytest.raises(ValueError, match="TEMPLATE_NOT_COMMITTED_PRODUCT"):
        repair.static_contract(config)
