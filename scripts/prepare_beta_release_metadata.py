"""Prepare current beta demo metadata from signed target assets, never old maps."""

from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from beta_release_metadata import marker_maps, gateway_metadata_model, ui_metadata_model
from bind_deployed_demo_manifest import bind_manifest
from scoped_native_runtime import read_ref, ref, require, save_exclusive


def load(value):
    return json.loads(read_ref(value).read_bytes())


def git_blob(repository, revision, filename):
    result = subprocess.run(
        ["git", "-C", str(repository), "show", revision + ":" + filename],
        capture_output=True,
        timeout=30,
        check=True,
    )
    require(len(result.stdout) <= 4 * 1024 * 1024, "SOURCE_BLOB_TOO_LARGE")
    return result.stdout


def prepare(config):
    require(
        config["schema"] == "marty.prepare-beta-release-metadata/v1", "INPUT_SCHEMA"
    )
    require(
        config["scope"] == "FUNCTIONAL_ONLY"
        and config["releaseQualified"] is False
        and config["recordingQualified"] is False,
        "FUNCTIONAL_ONLY",
    )
    signed = load(config["releaseLock"])
    descriptor = load(config["productDescriptor"])
    require(
        descriptor["source"]["repository"] == "https://github.com/ElevenID/marty-ui",
        "PRODUCT_REPOSITORY_CHANGED",
    )
    source = descriptor["source"]["commit"]
    repository = Path(config["productRepository"])
    cargo = git_blob(repository, source, "rust/Cargo.lock")
    require(
        hashlib.sha256(cargo).hexdigest() == config["cargoLock"]["sha256"]
        and read_ref(config["cargoLock"]).read_bytes() == cargo,
        "CARGO_LOCK_NOT_COMMITTED_PRODUCT",
    )
    template_bytes = git_blob(
        repository, source, "ui/public/demos/manifests/2026.08.0.json"
    )
    require(
        read_ref(config["template"]).read_bytes() == template_bytes,
        "TEMPLATE_NOT_COMMITTED_PRODUCT",
    )
    template = json.loads(template_bytes)
    runtime = load(config["runtimeObservation"])
    stage = load(config["sourceStage"])
    capture = config["captureRecorderRevision"]
    require(
        stage["state"] == "SOURCE_BUNDLES_READY"
        and stage["sources"]["recorder"]["revision"] == capture
        and stage["product"]["revision"] == source,
        "EXACT_CAPTURE_STAGE_REQUIRED",
    )
    components, images = marker_maps(source, cargo, signed, runtime["binding"]["roles"])
    release = signed["release"].removeprefix("marty-ui@")
    marker = dict(
        component="services",
        release_version=release,
        deployment_release_marker=release,
        stack_version=template["stack_version"],
        mip_version=template["mip_version"],
        marty_ui_sha=source,
        component_revisions=components,
        image_digests=images,
    )
    rows = [
        dict(
            component=name,
            repository="https://github.com/ElevenID/" + name,
            revision=revision,
        )
        for name, revision in sorted(components.items())
    ]
    source_manifest = dict(
        schema="marty.signed-nightly-functional-source/v1",
        source_kind="signed-nightly-deployment",
        scope="FUNCTIONAL_ONLY",
        release_version=release,
        mip_version=template["mip_version"],
        marty_ui_sha=source,
        promotion_eligible=False,
        release_ready=False,
        capture_recorder_revision=capture,
        component_revisions=rows,
        repositories={
            row["component"]: dict(
                repository=row["repository"], revision=row["revision"]
            )
            for row in rows
        },
    )
    bound = bind_manifest(template, source_manifest, images)
    gateway = load(config["gatewayModel"])
    ui = load(config["uiModel"])
    require(
        gateway["services"]["gateway"]["image"] == signed["services"]["gateway"]
        and ui["services"]["ui-prod"]["image"] == signed["services"]["ui"],
        "TARGET_MODELS_NOT_SIGNED_IMAGES",
    )
    environment = gateway["services"]["gateway"]["environment"]
    require(
        environment["MARTY_RELEASE_VERSION"] == release
        and environment["MARTY_UI_SHA"] == source,
        "TARGET_GATEWAY_RELEASE_IDENTITY_STALE",
    )
    output = Path(config["outputRoot"])
    private = Path.home() / ".codex/private"
    require(
        output.is_absolute() and output.is_relative_to(private) and not output.exists(),
        "FRESH_PRIVATE_OUTPUT_REQUIRED",
    )
    output.mkdir(mode=0o700)

    def write(name, value):
        save_exclusive(output / name, value)
        return ref(output / name)

    source_ref = write("source-manifest.json", source_manifest)
    manifest_ref = write("deployed-demo-manifest.json", bound)
    deployment = dict(
        schema_version=1,
        release_version=release,
        stack_version=template["stack_version"],
        mip_version=template["mip_version"],
        source_kind="signed-nightly-deployment",
        scope="FUNCTIONAL_ONLY",
        marty_ui_sha=source,
        promotion_eligible=False,
        release_ready=False,
        beta_origin="https://beta.elevenidllc.com",
        compose_project="elevenid-beta",
        ui_compose_project="elevenid-beta-ui",
        component_revisions=components,
        deployed_demo_manifest="deployed-demo-manifest.json",
        deployed_demo_manifest_sha256=manifest_ref["sha256"],
        source_manifest="source-manifest.json",
        source_manifest_sha256=source_ref["sha256"],
        services_marker=marker,
    )
    result = dict(
        state="PREPARED_BETA_METADATA_NOT_SERVED_OR_QUALIFIED",
        sourceManifest=source_ref,
        publicManifest=manifest_ref,
        expectedMarker=write("expected-public-marker.json", marker),
        deployment=write("deployment.json", deployment),
        gatewayModel=write(
            "candidate-gateway.private.json", gateway_metadata_model(gateway, marker)
        ),
        uiModel=write(
            "candidate-ui.private.json", ui_metadata_model(ui, manifest_ref["path"])
        ),
        sourceStage=config["sourceStage"],
        releaseLock=config["releaseLock"],
        productDescriptor=config["productDescriptor"],
        source=source,
        captureRecorderRevision=capture,
        releaseQualified=False,
        recordingQualified=False,
        betaMutation=False,
    )
    write("preparation.json", result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    result = prepare(json.loads(args.input.read_bytes()))
    print(
        json.dumps(
            dict(state=result["state"], source=result["source"], betaMutation=False)
        )
    )


if __name__ == "__main__":
    main()
