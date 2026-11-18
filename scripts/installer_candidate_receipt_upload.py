"""Upload one already-durable controller consumption to its owned GitHub draft.

This transports an unsigned ledger record. It does not consume a nonce, sign a
receipt, dispatch a guest, or attest that the guest was installed. An uncertain
POST burns the exclusive intent and requires manual reconciliation of the draft.
"""
from __future__ import annotations
import argparse
import fcntl
import os
from pathlib import Path
import time

import installer_candidate_rendezvous as transport
import installer_promote as promotion
import installer_release as release
import installer_candidate_dispatch as dispatch
import verify_installer_provenance as provenance
from installer_candidate_authorize import read_record, write_exclusive


def authenticate(authorization, inventory, assets, gh, cosign, *, runner=provenance.command):
    """Verify original build inputs and the acceptance-run authorization."""
    release.require(authorization.name == "candidate-authorization.json"
                    and inventory == assets / "installer-inventory.json",
                    "candidate input layout differs")
    expected = {name + suffix for name in dispatch.SUBJECTS for suffix in dispatch.SUFFIXES}
    release.require({path.name for path in assets.iterdir()} == expected,
                    "candidate asset closure differs")
    paths = {}
    for name in dispatch.SUBJECTS:
        for suffix in dispatch.SUFFIXES:
            maximum = 1048576 if suffix else (65536 if name == "installer-inventory.json"
                                            else release.ARTIFACT_MAX_BYTES[name])
            path = assets / (name + suffix)
            paths[path] = dispatch.private_file(path, maximum)
    for suffix in dispatch.SUFFIXES:
        path = authorization.parent / (authorization.name + suffix)
        paths[path] = dispatch.private_file(path, 1048576 if suffix else 65536)
    for name, path in (("gh", gh), ("cosign", cosign)):
        actual = dispatch.private_file(path, dispatch.TOOLS[name][1], executable=True)
        release.require(actual == dispatch.TOOLS[name], "verifier trust anchor differs")
        paths[path] = actual
    a, i = read_record(authorization), read_record(inventory)
    grant = release.decode(a)
    provenance.verify_subject(authorization, authorization.parent / (authorization.name + ".provenance.jsonl"),
        gh=gh, cosign=cosign, signature_bundle=authorization.parent / (authorization.name + ".sigstore.json"),
        workflow=release.acceptance.WORKFLOW, source_sha=grant["harness_source_sha"],
        run_id=grant["run_id"], run_attempt=grant["run_attempt"], runner=runner)
    build = {key: grant[key] for key in ("source_sha", "release_tag", "build_run_id", "build_run_attempt")}
    snapshot = release.verify_inventory_assets(assets, **build)
    tier, _ = release.classify_release_tag(grant["release_tag"])
    workflow = ".github/workflows/nightly-release.yml" if tier == "nightly" else ".github/workflows/cd.yml"
    for name in dispatch.SUBJECTS:
        provenance.verify_subject(assets / name, assets / (name + ".provenance.jsonl"),
            gh=gh, cosign=cosign, signature_bundle=assets / (name + ".sigstore.json"),
            workflow=workflow, source_sha=grant["source_sha"], run_id=grant["build_run_id"],
            run_attempt=grant["build_run_attempt"], runner=runner)
    release.require(release.verify_inventory_assets(assets, **build) == snapshot,
                    "candidate assets changed")
    for path, expected in paths.items():
        release.require(dispatch.private_file(path, expected[1], executable=path in (gh, cosign)) == expected,
                        "verified candidate input changed")
    release.require(read_record(authorization) == a and read_record(inventory) == i,
                    "verified candidate record changed")
    return a, i


def write_registry_intent(held, name, raw):
    release.require(name.endswith(".upload-intent.json") and "/" not in name and ".." not in name,
                    "invalid controller intent name")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=held)
    try:
        os.fsync(held)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
        os.fsync(held)
    finally:
        os.close(fd)


def upload(*, client, authorization: Path, inventory: Path, assets: Path, gh: Path, cosign: Path,
           descriptor: Path, ledger: Path, output: Path, harness_source_sha: str, run_id: int,
           run_attempt: int, controller_user_id: int, clock=time.time,
           verifier=provenance.command):
    release.require(os.name == "posix", "Linux controller required")
    parent = dispatch._directory(ledger.parent)
    owner = os.getpid()
    try:
        fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        dispatch.registry_unchanged(parent, ledger.parent)
        return _upload_locked(client=client, authorization=authorization, inventory=inventory,
            assets=assets, gh=gh, cosign=cosign, descriptor=descriptor, ledger=ledger,
            output=output, harness_source_sha=harness_source_sha, run_id=run_id,
            run_attempt=run_attempt, controller_user_id=controller_user_id,
            clock=clock, verifier=verifier, held=parent)
    finally:
        try:
            if os.getpid() == owner:
                while True:
                    try:
                        fcntl.flock(parent, fcntl.LOCK_UN)
                        break
                    except InterruptedError:
                        continue
        finally:
            os.close(parent)


def _upload_locked(*, client, authorization, inventory, assets, gh, cosign, descriptor,
                   ledger, output, harness_source_sha, run_id, run_attempt,
                   controller_user_id, clock, verifier, held):
    verified_a, verified_i = authenticate(authorization, inventory, assets, gh, cosign, runner=verifier)
    a, i, context, grant = transport.inputs(
        authorization, inventory, harness_source_sha=harness_source_sha,
        run_id=run_id, run_attempt=run_attempt, now=int(clock()))
    release.require((a, i) == (verified_a, verified_i), "authenticated candidate changed")
    approved = transport.controller_id(controller_user_id)
    release.require(grant["expires_at"] - int(clock()) > transport.RESERVE,
                    "grant expires too soon")
    owned = transport.bound_descriptor(descriptor, a, i, context, grant, approved)
    raw = read_record(ledger)
    receipt = release.decode(raw)
    release.require(ledger.name == receipt.get("nonce", "") + ".json",
                    "ledger filename differs from nonce")
    release.bind_controller_consumption(raw, a, i, expected=context,
                                        expected_engine=receipt.get("engine_id"), now=int(clock()))
    release.require(len(raw) <= transport.MAX_BYTES, "controller ledger exceeds transport bound")
    actor = client.whoami()
    release.require(isinstance(actor, dict) and type(actor.get("id")) is int
                    and actor["id"] == approved and actor.get("type") == "User"
                    and isinstance(actor.get("login"), str) and actor["login"]
                    and actor["login"] != "github-actions[bot]", "GitHub controller identity differs")
    api = client.request("GET", transport.REPO + "/actions/runs/" + str(run_id))
    promotion.check_run(api, run_id=run_id, attempt=run_attempt,
                        workflow=release.acceptance.WORKFLOW,
                        source=harness_source_sha, active=True)
    endpoint = transport.REPO + "/releases/" + str(owned["id"])
    transport.check_release(client.request("GET", endpoint), owned)
    release.require(client.request("GET", endpoint + "/assets?per_page=100") == [],
                    "draft transport already has assets")
    base = dict(schema="elevenid.installer-controller-upload/v1", release_id=owned["id"],
                controller_user_id=approved, nonce=receipt["nonce"], run_id=run_id,
                run_attempt=run_attempt, authorization_sha256=release.digest(a),
                inventory_sha256=release.digest(i), context_sha256=release.candidate_context_sha256(context),
                receipt_sha256=release.digest(raw), receipt_size=len(raw))
    # The intent must survive even if GitHub accepts the upload but the response
    # is lost. No retry or clobber is safe after this point.
    dispatch.registry_unchanged(held, ledger.parent)
    write_registry_intent(held, receipt["nonce"] + ".upload-intent.json", release.encode(base))
    dispatch.registry_unchanged(held, ledger.parent)
    release.require(read_record(ledger) == raw and read_record(authorization) == a
                    and read_record(inventory) == i, "controller upload input changed")
    transport.check_release(client.request("GET", endpoint), owned)
    release.require(client.request("GET", endpoint + "/assets?per_page=100") == [],
                    "draft transport changed before upload")
    fresh = int(clock())
    release.require(grant["expires_at"] - fresh > transport.RESERVE,
                    "grant expired before controller upload")
    release.bind_controller_consumption(raw, a, i, expected=context,
                                        expected_engine=receipt["engine_id"], now=fresh)
    promotion.check_run(client.request("GET", transport.REPO + "/actions/runs/" + str(run_id)),
                        run_id=run_id, attempt=run_attempt, workflow=release.acceptance.WORKFLOW,
                        source=harness_source_sha, active=True)
    release.require(grant["expires_at"] - int(clock()) > transport.RESERVE,
                    "grant expired before controller upload")
    dispatch.registry_unchanged(held, ledger.parent)
    posted = transport.receipt_asset([client.upload_receipt(owned["id"], raw)], approved)
    release.require(posted["size"] == len(raw) and posted["digest"] == "sha256:" + release.digest(raw),
                    "uploaded receipt metadata differs")
    transport.check_release(client.request("GET", endpoint), owned)
    observed = transport.receipt_asset(client.request("GET", endpoint + "/assets?per_page=100"), approved)
    release.require(observed == posted, "uploaded receipt changed")
    downloaded = client.download(posted["id"], posted["size"])
    release.require(downloaded == raw, "uploaded receipt bytes differ")
    transport.check_release(client.request("GET", endpoint), owned)
    release.require(transport.receipt_asset(client.request("GET", endpoint + "/assets?per_page=100"), approved)
                    == posted, "uploaded receipt changed during verification")
    release.require(read_record(ledger) == raw and int(clock()) < grant["expires_at"] - transport.RESERVE,
                    "controller upload expired or ledger changed")
    evidence = dict(base, asset={key: posted[key] for key in
                                ("id", "name", "state", "size", "digest", "created_at", "updated_at")},
                    verified_at=int(clock()))
    write_exclusive(output, release.encode(evidence))
    return evidence


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("authorization", "inventory", "assets", "gh", "cosign", "descriptor", "ledger", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--harness-source-sha", required=True)
    for name in ("run-id", "run-attempt", "controller-user-id"):
        parser.add_argument("--" + name, type=int, required=True)
    args = vars(parser.parse_args(argv))
    try:
        upload(**args, client=transport.Client(os.environ.get("GH_TOKEN")))
    except (ValueError, OSError, TypeError, KeyError):
        parser.exit(1, "Controller upload refused or uncertain; preserve ledger, intent and draft.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
