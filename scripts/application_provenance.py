#!/usr/bin/env python3
"""Authenticate the separate package application producer and its fixed evidence.

This explicit entry is separate from the existing combined application and
selfhost deployment bundle. Shared certificate and signature checks retain
their original producer policy.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import application_release as application
import ui_release as ui
import website_provenance as proof


def verify_package_application(directory: Path, *, gh: Path, cosign: Path, source_sha: str | None = None,
                               runner: proof.verifier.Run = proof.verifier.command) -> dict:
    release = application.validate_assets(directory, source_sha=source_sha)
    path = directory / "application-release.json"
    originals = (path, path.with_name(path.name + ".sigstore.json"),
                 path.with_name(path.name + ".provenance.jsonl"), directory / "image.provenance.jsonl")

    def original_digests() -> dict:
        held = {}
        for original in originals:
            proof.verifier.local_file(original, private=True,
                                      maximum=application.JSON_LIMIT if original == path else proof.PROOF_LIMIT)
            held[original.name] = proof.file_digest(original)
        return held

    before = original_digests()
    proof.verify_subject(path, producer=release["producer"], gh=gh, cosign=cosign, runner=runner, role="application")
    proof.verify_image(release["image"], directory / "image.provenance.jsonl", producer=release["producer"],
                       gh=gh, cosign=cosign, runner=runner, role="application")
    ui.require(application.validate_assets(directory, source_sha=source_sha) == release,
               "package application evidence changed after verification")
    ui.require(original_digests() == before, "package application original proofs changed during verification")
    return release


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--gh", type=Path, required=True)
    parser.add_argument("--cosign", type=Path, required=True)
    args = parser.parse_args()
    verify_package_application(args.assets.absolute(), gh=args.gh.absolute(), cosign=args.cosign.absolute(),
                               source_sha=args.source_sha)


if __name__ == "__main__":
    main()
