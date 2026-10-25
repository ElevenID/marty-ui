"""Verify stable installer inputs and export offline producer evidence.

The publisher owns signing, exact release allowlists and immutable publication.
These checks establish artifact identity, never installer acceptance/admission.
Callers must exclude concurrent writers while consuming the verified files.
"""
from __future__ import annotations

import argparse
import shutil
import tempfile
from pathlib import Path

import installer_release as release
import verify_installer_provenance as provenance

WORKFLOW = ".github/workflows/cd.yml"
SUBJECTS = ("install.sh", "marty-deploy-linux-amd64", "prepared-selfhost-bundle.zip",
            "prepared-selfhost-images.json", "installer-inventory.json")
PROVENANCE_LIMIT = 1024 * 1024


def read_inventory(assets: Path) -> dict:
    path = assets / "installer-inventory.json"
    provenance.local_file(path, maximum=65536)
    with path.open("rb") as stream:
        record = release.decode(stream.read(65537))
    release.validate_inventory(record)
    return record


def verify_inputs(assets: Path, *, source_sha: str, tag: str,
                  run_id: int, run_attempt: int) -> dict:
    release.require(release.classify_release_tag(tag)[0] == "stable", "stable release required")
    for name in SUBJECTS:
        provenance.local_file(assets / name)
    return release.verify_inventory_assets(assets, source_sha=source_sha, release_tag=tag,
                                           build_run_id=run_id, build_run_attempt=run_attempt)


def proof_bytes(path: Path) -> bytes:
    provenance.local_file(path, maximum=PROVENANCE_LIMIT)
    with path.open("rb") as stream:
        raw = stream.read(PROVENANCE_LIMIT + 1)
    release.require(0 < len(raw) <= PROVENANCE_LIMIT, "installer provenance exceeds transport limit")
    return raw


def verify_copies(assets: Path, proofs: dict[str, bytes], *, gh: Path,
                  source_sha: str, tag: str, run_id: int, run_attempt: int) -> None:
    """Verify private held copies, then ensure the original inputs still match."""
    before = (assets / "installer-inventory.json").read_bytes()
    with tempfile.TemporaryDirectory(prefix="stable-installer-proof-") as temporary:
        staged = Path(temporary).resolve()
        for name in SUBJECTS:
            shutil.copyfile(assets / name, staged / name)
        verify_inputs(staged, source_sha=source_sha, tag=tag,
                      run_id=run_id, run_attempt=run_attempt)
        release.require((staged / "installer-inventory.json").read_bytes() == before,
                        "installer inventory changed during verification")
        for name in SUBJECTS:
            bundle = staged / (name + ".provenance.jsonl")
            bundle.write_bytes(proofs[name])
            provenance.verify_subject(staged / name, bundle, gh=gh, workflow=WORKFLOW,
                                      source_sha=source_sha, run_id=run_id, run_attempt=run_attempt)
    verify_inputs(assets, source_sha=source_sha, tag=tag,
                  run_id=run_id, run_attempt=run_attempt)
    release.require((assets / "installer-inventory.json").read_bytes() == before,
                    "installer inventory changed during verification")


def export_provenance(assets: Path, *, source_sha: str, tag: str, run_id: int,
                      run_attempt: int, bundle: Path, gh: Path) -> None:
    verify_inputs(assets, source_sha=source_sha, tag=tag, run_id=run_id, run_attempt=run_attempt)
    raw = proof_bytes(bundle)
    verify_copies(assets, dict.fromkeys(SUBJECTS, raw), gh=gh, source_sha=source_sha,
                  tag=tag, run_id=run_id, run_attempt=run_attempt)
    # Never replace earlier proof files or partially publish an authentication
    # failure. I/O failure may leave partial local evidence; final allowlist and
    # crypto verification still gate publication.
    release.require(all(not (assets / (name + ".provenance.jsonl")).exists()
                        and not (assets / (name + ".provenance.jsonl")).is_symlink()
                        for name in SUBJECTS), "installer provenance already exists")
    for name in SUBJECTS:
        with (assets / (name + ".provenance.jsonl")).open("xb") as output:
            output.write(raw)


def verify_published(assets: Path, *, source_sha: str, tag: str, gh: Path) -> None:
    # The inventory's claimed producer is not trusted until its own certificate
    # and all four payload certificates authenticate that same original run.
    # A resumed publisher must not relabel an immutable prior release.
    inventory = read_inventory(assets)
    run_id, attempt = inventory["build_run_id"], inventory["build_run_attempt"]
    verify_inputs(assets, source_sha=source_sha, tag=tag, run_id=run_id, run_attempt=attempt)
    proofs = {name: proof_bytes(assets / (name + ".provenance.jsonl")) for name in SUBJECTS}
    verify_copies(assets, proofs, gh=gh, source_sha=source_sha, tag=tag,
                  run_id=run_id, run_attempt=attempt)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("verify-inputs", "export-provenance", "verify-published"), required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--run-attempt", type=int)
    parser.add_argument("--provenance-bundle", type=Path)
    parser.add_argument("--gh", type=Path)
    args = parser.parse_args()
    common = dict(source_sha=args.source_sha, tag=args.tag)
    if args.phase == "verify-published":
        release.require(args.gh is not None and args.run_id is None and args.run_attempt is None
                        and args.provenance_bundle is None, "published verification uses original producer")
        verify_published(args.assets.absolute(), gh=args.gh.absolute(), **common)
        return
    release.positive(args.run_id)
    release.positive(args.run_attempt)
    common.update(run_id=args.run_id, run_attempt=args.run_attempt)
    if args.phase == "verify-inputs":
        release.require(args.gh is None and args.provenance_bundle is None, "unexpected verifier inputs")
        verify_inputs(args.assets.absolute(), **common)
    else:
        release.require(args.gh is not None and args.provenance_bundle is not None, "missing provenance verifier inputs")
        export_provenance(args.assets.absolute(), bundle=args.provenance_bundle.absolute(),
                          gh=args.gh.absolute(), **common)


if __name__ == "__main__":
    main()
