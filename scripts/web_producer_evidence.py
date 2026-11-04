#!/usr/bin/env python3
"""Retain and verify hosted producer evidence before uploading fixed receipts."""
from __future__ import annotations

import argparse
from pathlib import Path

import ui_release as ui
import website_provenance as proof
import website_release as web

SUBJECTS = {"website-release.json", "production-web-release.json", "application-web-compatibility.json",
            "production-deployment.json", "production-openbao.zip", "ui.sbom.cdx.json", "ui-build-evidence.json",
            "deployment/production-deployment.json", "deployment/production-openbao.zip",
            "web-composition.json", "web-composition.zip"}


def retain(directory: Path, *, names: list[str], producer: dict, release_provenance: Path,
           gh: Path, cosign: Path, image: dict | None = None, image_provenance: Path | None = None) -> None:
    proof.validate_producer(producer)
    ui.require(names and len(names) == len(set(names)) and set(names).issubset(SUBJECTS), "unexpected producer subjects")
    proof.verifier.local_file(release_provenance, maximum=proof.PROOF_LIMIT)
    held = release_provenance.read_bytes()
    for name in names:
        subject = directory / name
        proof.verifier.local_file(subject, private=True)
        path = subject.with_name(subject.name + ".provenance.jsonl")
        with path.open("xb") as stream:
            stream.write(held)
        path.chmod(0o600)
        proof.verify_subject(subject, producer=producer, gh=gh, cosign=cosign)
    if image is not None:
        ui.require(image_provenance is not None, "image provenance is required")
        proof.verifier.local_file(image_provenance, maximum=proof.PROOF_LIMIT)
        target = directory / "image.provenance.jsonl"
        with target.open("xb") as stream:
            stream.write(image_provenance.read_bytes())
        target.chmod(0o600)
        proof.verify_image(image, target, producer=producer, gh=gh, cosign=cosign)
    else:
        ui.require(image_provenance is None, "unexpected image proof")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--subject", action="append", required=True)
    parser.add_argument("--repository", choices=tuple(web.REPOSITORIES), required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--release-provenance", type=Path, required=True)
    parser.add_argument("--image-provenance", type=Path)
    parser.add_argument("--image")
    parser.add_argument("--image-digest")
    parser.add_argument("--gh", type=Path, required=True)
    parser.add_argument("--cosign", type=Path, required=True)
    args = parser.parse_args()
    producer = {"repository": args.repository, "source_sha": args.source_sha, "ref": web.REF,
                "workflow": ui.WORKFLOW if args.repository == ui.REPOSITORY else ui.COMMERCE_WORKFLOW,
                "run_id": args.run_id, "run_attempt": args.run_attempt}
    image = {"uri": args.image, "digest": args.image_digest, "platform": "linux/amd64"} if args.image else None
    retain(args.assets.absolute(), names=args.subject, producer=producer,
           release_provenance=args.release_provenance.absolute(),
           image=image, image_provenance=args.image_provenance.absolute() if args.image_provenance else None,
           gh=args.gh.absolute(), cosign=args.cosign.absolute())


if __name__ == "__main__":
    main()
