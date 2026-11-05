#!/usr/bin/env python3
"""Publish a newly authenticated v2 candidate without rebuilding its artifacts.

The workflow serializes every supported publisher by release tag. Each mutation
also rechecks protected main, original successful qualification, candidate/policy
identity, and the bounded authorization. Foreign or unknown partial state is an
incident; it is never adopted, deleted, overwritten, or silently retried here.
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import release_review_main as review
import release_tag_handoff as h
import release_transaction as transaction
import stable_publication_candidate as c
import stable_publication_checkpoint as cp
import push_promoted_release_tag as operator
import verify_installer_provenance as provenance

ROOT = Path(__file__).resolve().parents[1]
OWNER_TYPE = "https://elevenidllc.com/attestations/stable-publication-owner/v2"
OWNER_SCHEMA = "elevenid.stable-publication-owner/v2"
OWNER_PREFIX = "Verified Marty stable publication ownership (v2).\n\n```json\n"
OWNER_SUFFIX = "\n```\n"
OWNER_FIELDS = {"schema", "repository", "release_id", "tag", "candidate_id", "policy_sha256",
                "original_run_id", "publisher_run_id", "publisher_source_sha", "publisher_run_attempt"}


def publisher_context(environment: dict[str, str]) -> tuple[int, str]:
    run, source = environment.get("GITHUB_RUN_ID", ""), environment.get("GITHUB_SHA", "")
    h.require(environment.get("GITHUB_REPOSITORY") == h.REPOSITORY
              and environment.get("GITHUB_REF") == "refs/heads/main"
              and environment.get("GITHUB_EVENT_NAME") in {"workflow_dispatch", "workflow_run"}
              and environment.get("GITHUB_WORKFLOW_REF") == f"{h.REPOSITORY}/{c.PUBLISHER_WORKFLOW}@refs/heads/main"
              and environment.get("GITHUB_RUN_ATTEMPT") == "1"
              and isinstance(run, str) and cp.RUN.fullmatch(run) and h.positive(int(run))
              and isinstance(source, str) and h.SHA.fullmatch(source),
              "publication requires a fresh first-attempt main publisher invocation")
    return int(run), source


def publisher_run(github: h.GitHub, run_id: int, source: str, *, current: bool = False) -> dict:
    h.require(h.positive(run_id) and isinstance(source, str) and h.SHA.fullmatch(source), "publisher identity invalid")
    run = github.json(f"repos/{h.REPOSITORY}/actions/runs/{run_id}")
    h.require(type(run) is dict and type(run.get("id")) is int and run["id"] == run_id
              and run.get("path") == c.PUBLISHER_WORKFLOW
              and run.get("event") in {"workflow_dispatch", "workflow_run"}
              and run.get("head_branch") == "main" and run.get("head_sha") == source
              and type(run.get("run_attempt")) is int and run["run_attempt"] == 1
              and run.get("repository", {}).get("id") == h.REPOSITORY_ID
              and run.get("repository", {}).get("full_name") == h.REPOSITORY,
              "publisher API invocation differs from its original identity")
    h.require(not current or run.get("status") == "in_progress", "publisher is no longer running")
    return run


def original_success(github: h.GitHub, candidate: dict) -> dict:
    run = github.run(candidate["run_id"], h.CD_WORKFLOW, candidate["source_sha"])
    h.require(run.get("status") == "completed" and run.get("conclusion") == "success",
              "original CD qualification is not successful")
    return run


class Proof:
    """Production proof adapters; tests substitute explicit synthetic adapters."""
    def __init__(self, gh: Path, cosign: Path, root: Path = ROOT):
        self.gh, self.cosign, self.root = gh, cosign, root

    def source(self, request: dict, deadline: datetime) -> None:
        main = request["protected_main_commit"]
        h.require(h.git("rev-parse", "HEAD^{commit}", repository=self.root, deadline=deadline) == main,
                  "publisher checkout is not the admitted protected main")
        h.git("diff", "--exit-code", "HEAD", "--", repository=self.root, deadline=deadline)
        h.git("fetch", "--no-tags", "origin", main, repository=self.root, deadline=deadline)
        authority = request["authority"]
        review.require_review_only_history(request["source_sha"], main, request["run_id"], 1,
            authority["review_required"], record_sha256=authority["record_sha256"],
            repository=self.root, timeout_seconds=h.remaining(deadline, 30))

    def assets(self, directory: Path, request: dict, deadline: datetime, observations: list) -> None:
        operator.verify_crypto(directory / "checkpoint/assets", request, self.gh, self.cosign, deadline, observations)
        claim = h.decode(h.bounded_file(directory / "checkpoint/assets/release-transaction.json", 65536))
        operator.promoted_digests(claim, deadline)


def authorize(github: h.GitHub, directory: Path, artifact: dict, *, proof: Proof,
              environment: dict[str, str] | None = None, now: datetime | None = None) -> dict:
    candidate, request, admission = c.load_candidate(directory, now=now)
    issued = c.utc(now)
    deadline = min(issued + timedelta(seconds=c.POLICY["authorization_lifetime_seconds"]),
                   h.timestamp(candidate["not_after"]))
    github.deadline = deadline
    context = os.environ if environment is None else environment
    run_id, source = publisher_context(context)
    h.require(source == request["protected_main_commit"], "publisher source differs from original qualification authority")
    h.require(github.main()["commit"]["sha"] == source, "protected main has changed")
    live = publisher_run(github, run_id, source, current=True)
    h.require(live["event"] == context["GITHUB_EVENT_NAME"], "publisher event differs")
    original_success(github, candidate)
    _, actual_artifact = c.find_artifact(github, candidate["run_id"])
    h.require(actual_artifact == artifact, "candidate artifact changed before authorization")
    h.require(c.policy_digest(proof.root) == candidate["policy_sha256"], "publication policy changed")
    proof.source(request, deadline)
    claim = h.decode(h.bounded_file(directory / "checkpoint/assets/release-transaction.json", 65536))
    lock_bytes = h.bounded_file(proof.root / "release/stack-lock.json")
    lock = h.decode(lock_bytes)
    h.require(h.sha256(lock_bytes) == claim["stack_lock_sha256"] and lock.get("release_state") == "eligible"
              and lock.get("release") == "marty-ui@" + candidate["tag"][1:], "candidate source lock is no longer eligible")
    original_checkpoint = github.artifact(candidate["run_id"], f"stack-release-publication-inputs-{candidate['run_id']}-1",
                                          candidate["source_sha"])
    request_sha = candidate["files"]["checkpoint/request.json"]["sha256"]
    intent = h.owned_intent(github, request, request_sha, original_checkpoint, admission["operator_run_id"],
                            expected_sha=admission["intent_object_sha"])
    h.require(admission["intent_tag"] == h.release_intent_tag(candidate["tag"]), "operator intent coordinate differs")
    tag = h.annotated_tag(github, candidate["tag"])
    h.require(tag is not None and tag["sha"] == admission["tag_object_sha"]
              and tag["object"]["sha"] == candidate["source_sha"]
              and tag.get("message", "").rstrip("\n") == h.tag_message(request, request_sha, original_checkpoint,
                    admission["operator_run_id"], intent_object_sha=intent["sha"]).rstrip("\n"),
              "qualified tag does not authenticate the original candidate")
    with tempfile.TemporaryDirectory(prefix="marty-publication-handoff-") as temporary:
        observed = h.successful_result(github, admission["operator_run_id"], request, request_sha,
                                      original_checkpoint, tag, Path(temporary))
    h.require(observed == admission, "successful operator admission differs")
    proof.assets(directory, request, deadline, github.crypto)
    # Re-read candidate custody after all original signature/attestation checks.
    h.require(c.load_candidate(directory, now=now) == (candidate, request, admission), "candidate changed during authorization")
    h.require(github.main()["commit"]["sha"] == source and c.utc(now) < deadline,
              "protected main or publication deadline changed during authorization")
    original_success(github, candidate)
    return {"schema": "elevenid.stable-publication-authorization/v2", "candidate_id": candidate["candidate_id"],
            "policy_sha256": candidate["policy_sha256"], "publisher_run_id": run_id,
            "publisher_source_sha": source, "publisher_run_attempt": 1,
            "created_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"), "not_after": deadline.strftime("%Y-%m-%dT%H:%M:%SZ")}


class GitHub(h.GitHub):
    def release_at_tag(self, tag: str) -> dict | None:
        h.require(isinstance(tag, str) and h.TAG.fullmatch(tag), "release tag invalid")
        found = []
        seen = set()
        # Releases include assets: 100 full records can exceed the transport's
        # 4 MiB cap. Smaller complete pages retain duplicate-coordinate detection.
        for page in range(1, 251):
            rows = self.json(f"repos/{h.REPOSITORY}/releases?per_page=20&page={page}")
            h.require(type(rows) is list and len(rows) <= 20, "release listing malformed")
            for row in rows:
                h.require(type(row) is dict and h.positive(row.get("id")) and row["id"] not in seen,
                          "release listing has invalid or duplicate IDs")
                seen.add(row["id"])
                if row.get("tag_name") == tag:
                    found.append(row)
            h.require(len(found) <= 1, "multiple releases own the coordinate")
            if len(rows) < 20:
                return found[0] if found else None
        raise h.HandoffError("release listing exceeds complete pagination bound")

    def upload(self, release_id: int, name: str, source: Path, metadata: dict) -> None:
        h.require(h.positive(release_id) and name in cp.ASSET_NAMES, "asset upload identity invalid")
        h.require(h.file_digest(source) == metadata["sha256"] and source.stat().st_size == metadata["size"],
                  "asset changed before upload")
        url = f"https://uploads.github.com/repos/{h.REPOSITORY}/releases/{release_id}/assets?name={quote(name, safe='')}"
        observation = {"method": "POST", "endpoint": url, "sha256": metadata["sha256"], "outcome": "unknown"}
        self.mutations.append(observation)
        code, raw = h.command([self.executable, "api", "--hostname", "github.com", url, "--method", "POST",
                               "-H", "Content-Type: application/octet-stream",
                               "-H", "X-GitHub-Api-Version: 2026-03-10", "--input", str(source)],
                              timeout=h.remaining(self.deadline))
        h.require(code == 0, "asset upload outcome is unknown or refused; no automatic retry")
        value = h.decode(raw)
        h.require(type(value) is dict and value.get("name") == name and h.positive(value.get("id")),
                  "asset upload response differs")
        observation.update(outcome="response_received", asset_id=value["id"])

    def verify_asset(self, asset: dict, expected: dict) -> None:
        h.require(type(asset) is dict and h.positive(asset.get("id")) and asset.get("state") == "uploaded"
                  and type(asset.get("size")) is int and asset["size"] == expected["size"]
                  and asset.get("digest") == expected["sha256"], "remote asset metadata differs")
        with tempfile.TemporaryDirectory(prefix="marty-release-readback-") as temporary:
            path = Path(temporary) / "asset"
            code, _ = h.command([self.executable, "api", "--hostname", "github.com",
                f"repos/{h.REPOSITORY}/releases/assets/{asset['id']}", "-H", "Accept: application/octet-stream"],
                destination=path, maximum=expected["size"], timeout=h.remaining(self.deadline))
            h.require(code == 0 and path.stat().st_size == expected["size"]
                      and h.file_digest(path) == expected["sha256"], "remote asset bytes differ")


def owner_receipt(candidate: dict, authorization: dict, release_id: int) -> dict:
    return {"schema": OWNER_SCHEMA, "repository": h.REPOSITORY, "release_id": release_id,
            "tag": candidate["tag"], "candidate_id": candidate["candidate_id"],
            "policy_sha256": candidate["policy_sha256"], "original_run_id": candidate["run_id"],
            **{key: authorization[key] for key in ("publisher_run_id", "publisher_source_sha", "publisher_run_attempt")}}


class Ownership:
    """An exact-run keyless attestation authenticates the draft owner receipt."""
    def __init__(self, gh: Path, cosign: Path, github: GitHub):
        self.gh, self.cosign, self.github = gh, cosign, github

    def verify(self, receipt: dict, bundle: dict) -> None:
        publisher_run(self.github, receipt["publisher_run_id"], receipt["publisher_source_sha"])
        with tempfile.TemporaryDirectory(prefix="marty-publication-owner-") as temporary:
            root = Path(temporary)
            subject, proof = root / "owner.json", root / "owner.sigstore.json"
            subject.write_bytes(h.encoded(receipt)); proof.write_bytes(h.encoded(bundle))
            code, raw = h.command([str(self.gh), "attestation", "verify", str(subject), "--bundle", str(proof),
                "--repo", h.REPOSITORY, "--signer-workflow", h.REPOSITORY + "/" + c.PUBLISHER_WORKFLOW,
                "--source-ref", "refs/heads/main", "--source-digest", receipt["publisher_source_sha"],
                "--deny-self-hosted-runners", "--predicate-type", OWNER_TYPE, "--format", "json"],
                timeout=h.remaining(self.github.deadline))
            h.require(code == 0, "draft ownership attestation failed")
            provenance.verified_certificate(raw.decode(), workflow=c.PUBLISHER_WORKFLOW,
                source_sha=receipt["publisher_source_sha"], run_id=receipt["publisher_run_id"], run_attempt=1)

    def sign(self, receipt: dict) -> dict:
        with tempfile.TemporaryDirectory(prefix="marty-publication-owner-") as temporary:
            root = Path(temporary); subject, proof = root / "owner.json", root / "owner.sigstore.json"
            subject.write_bytes(h.encoded(receipt))
            code, _ = h.command([str(self.cosign), "attest-blob", "--yes", "--predicate", str(subject),
                "--type", OWNER_TYPE, "--bundle", str(proof), str(subject)], timeout=h.remaining(self.github.deadline))
            h.require(code == 0, "draft ownership signing failed; unowned draft needs incident reconciliation")
            bundle = h.decode(h.bounded_file(proof, 49152))
            self.verify(receipt, bundle)
            return bundle


def ownership_body(receipt: dict, bundle: dict) -> str:
    body = OWNER_PREFIX + h.encoded({"receipt": receipt, "bundle": bundle}).decode().rstrip("\n") + OWNER_SUFFIX
    h.require(len(body.encode()) <= 60000, "ownership body exceeds its bound")
    return body


def read_owner(body: str, candidate: dict, request: dict, release_id: int, verifier: Ownership) -> None:
    h.require(isinstance(body, str) and len(body.encode()) <= 60000 and body.startswith(OWNER_PREFIX)
              and body.endswith(OWNER_SUFFIX), "release has no authenticated v2 owner")
    value = h.decode(body[len(OWNER_PREFIX):-len(OWNER_SUFFIX)].encode())
    h.require(type(value) is dict and set(value) == {"receipt", "bundle"}, "ownership envelope differs")
    receipt = value["receipt"]
    h.require(type(receipt) is dict and set(receipt) == OWNER_FIELDS and receipt.get("schema") == OWNER_SCHEMA
              and receipt.get("repository") == h.REPOSITORY and type(receipt.get("release_id")) is int
              and receipt["release_id"] == release_id and receipt.get("tag") == candidate["tag"]
              and receipt.get("candidate_id") == candidate["candidate_id"]
              and receipt.get("policy_sha256") == candidate["policy_sha256"]
              and type(receipt.get("original_run_id")) is int and receipt["original_run_id"] == candidate["run_id"]
              and h.positive(receipt.get("publisher_run_id")) and type(receipt.get("publisher_run_attempt")) is int
              and receipt["publisher_run_attempt"] == 1
              and receipt.get("publisher_source_sha") == request["protected_main_commit"],
              "release ownership is foreign to this candidate and coordinate")
    h.require(type(value["bundle"]) is dict and body == ownership_body(receipt, value["bundle"]),
              "ownership envelope is noncanonical")
    verifier.verify(receipt, value["bundle"])


class Publisher:
    def __init__(self, github: GitHub, directory: Path, authorization: dict, ownership: Ownership,
                 *, root: Path = ROOT, clock=lambda: datetime.now(timezone.utc)):
        self.github, self.directory, self.authorization, self.ownership = github, directory, authorization, ownership
        self.root, self.clock = root, clock
        self.candidate, self.request, self.admission = c.load_candidate(directory, now=clock())
        self.deadline = h.timestamp(authorization["not_after"])
        self.github.deadline = self.deadline
        h.require(authorization["candidate_id"] == self.candidate["candidate_id"]
                  and authorization["policy_sha256"] == self.candidate["policy_sha256"]
                  and authorization["publisher_source_sha"] == self.request["protected_main_commit"]
                  and h.timestamp(authorization["created_at"]) < self.deadline
                  <= min(h.timestamp(authorization["created_at"]) + timedelta(seconds=900),
                         h.timestamp(self.candidate["not_after"])), "publication authorization differs")
        self.release_id = None
        self.body = None

    def guard(self) -> None:
        h.require(c.utc(self.clock()) < self.deadline, "publication authorization expired")
        c.validate_manifest(self.candidate, now=self.clock())
        h.require(c.policy_digest(self.root) == self.candidate["policy_sha256"], "publication policy changed")
        h.require(self.github.main()["commit"]["sha"] == self.request["protected_main_commit"], "protected main changed")
        original_success(self.github, self.candidate)
        publisher_run(self.github, self.authorization["publisher_run_id"],
                      self.authorization["publisher_source_sha"], current=True)
        tag = h.annotated_tag(self.github, self.candidate["tag"])
        h.require(tag is not None and tag["sha"] == self.admission["tag_object_sha"]
                  and tag["object"]["sha"] == self.candidate["source_sha"], "qualified tag changed")
        h.require(self.admission["intent_tag"] == h.release_intent_tag(self.candidate["tag"]),
                  "retained intent coordinate changed")
        intent = h.annotated_tag(self.github, self.admission["intent_tag"])
        h.require(intent is not None and intent["sha"] == self.admission["intent_object_sha"]
                  and intent["object"]["sha"] == self.candidate["source_sha"], "retained original operator intent changed")
        h.require(c.utc(self.clock()) < self.deadline, "publication authorization expired during revalidation")

    def release(self, *, fresh: bool = False, owned: bool = True) -> dict:
        self.guard()
        value = (self.github.release_at_tag(self.candidate["tag"]) if fresh else
                 self.github.json(f"repos/{h.REPOSITORY}/releases/{self.release_id}"))
        h.require(type(value) is dict and h.positive(value.get("id")) and value["id"] == self.release_id
                  and value.get("tag_name") == self.candidate["tag"]
                  and value.get("target_commitish") == self.candidate["source_sha"]
                  and type(value.get("draft")) is bool and value.get("prerelease") is False,
                  "release coordinate or identity changed")
        h.require(not owned or value.get("body") == self.body, "authenticated release ownership changed")
        return value

    def assets(self, release: dict, *, complete: bool = False) -> dict:
        rows = release.get("assets")
        h.require(type(rows) is list and all(type(row) is dict and isinstance(row.get("name"), str)
                  and h.positive(row.get("id")) for row in rows), "release asset listing malformed")
        names = [row["name"] for row in rows]
        h.require(len(names) == len(set(names)) and len({row["id"] for row in rows}) == len(rows)
                  and set(names) <= cp.ASSET_NAMES, "foreign or duplicate release assets")
        h.require(not complete or set(names) == cp.ASSET_NAMES, "release asset set incomplete")
        for row in rows:
            expected = self.request["assets"][row["name"]]
            h.require(row.get("state") == "uploaded" and type(row.get("size")) is int
                      and row["size"] == expected["size"] and row.get("digest") == expected["sha256"],
                      "release contains conflicting or incomplete asset state")
        return {row["name"]: row for row in rows}

    def publish(self) -> dict:
        self.guard()
        current = self.github.release_at_tag(self.candidate["tag"])
        if current is None:
            self.guard()
            status, raw = self.github.response(f"repos/{h.REPOSITORY}/releases", method="POST", payload={
                "tag_name": self.candidate["tag"], "target_commitish": self.candidate["source_sha"],
                "name": self.candidate["tag"], "body": "", "draft": True, "prerelease": False,
                "make_latest": "false"})
            h.require(status == 201, "draft creation failed; unknown state must be reconciled")
            current = h.decode(raw)
            h.require(type(current) is dict and h.positive(current.get("id")), "draft creation response invalid")
            self.release_id = current["id"]
            current = self.release(fresh=True, owned=False)
            h.require(current["draft"] is True and current.get("body") in {None, ""}
                      and current.get("assets") == [], "new draft is no longer unclaimed")
            receipt = owner_receipt(self.candidate, self.authorization, self.release_id)
            bundle = self.ownership.sign(receipt)
            body = ownership_body(receipt, bundle)
            current = self.release(fresh=True, owned=False)
            h.require(current["draft"] is True and current.get("body") in {None, ""}
                      and current.get("assets") == [], "new draft changed before ownership attachment")
            self.guard()
            status, _ = self.github.response(f"repos/{h.REPOSITORY}/releases/{self.release_id}", method="PATCH", payload={"body": body})
            h.require(status == 200, "ownership attachment failed; do not claim an unknown draft")
            self.body = body
            current = self.release(fresh=True)
        else:
            h.require(h.positive(current.get("id")), "release identity invalid")
            self.release_id = current["id"]
            read_owner(current.get("body"), self.candidate, self.request, self.release_id, self.ownership)
            self.body = current["body"]
            current = self.release(fresh=True)
        existing = self.assets(current, complete=not current["draft"])
        for name, row in existing.items():
            self.github.verify_asset(row, self.request["assets"][name])
        if current["draft"]:
            for name in sorted(cp.ASSET_NAMES - set(existing)):
                current = self.release()
                h.require(current["draft"] is True, "draft was published before completion")
                rows = self.assets(current)
                # A concurrent writer must never cause an overwrite or a blind
                # accept. Authenticate matching bytes or reject the conflict.
                if name not in rows:
                    self.guard()
                    path = self.directory / "checkpoint/assets" / name
                    with cp._Directory(path.parent) as assets:
                        metadata, _ = assets.read(name, cp.MAX_FILE_BYTES["assets/" + name], capture=False)
                        h.require(metadata == self.request["assets"][name], "local upload bytes changed")
                    self.github.upload(self.release_id, name, path, metadata)
                    rows = self.assets(self.release())
                h.require(name in rows, "upload did not produce the admitted asset")
                self.github.verify_asset(rows[name], self.request["assets"][name])
            current = self.release(fresh=True)
            self.assets(current, complete=True)
            h.require(c.load_candidate(self.directory, now=self.clock()) == (self.candidate, self.request, self.admission),
                      "candidate custody changed before final publication")
            self.guard()
            status, _ = self.github.response(f"repos/{h.REPOSITORY}/releases/{self.release_id}",
                                              method="PATCH", payload={"draft": False, "make_latest": "true"})
            h.require(status == 200, "publication outcome is unknown; use a fresh admitted retry")
        current = self.release(fresh=True)
        h.require(current["draft"] is False, "release was not published")
        for name, row in self.assets(current, complete=True).items():
            self.github.verify_asset(row, self.request["assets"][name])
        self.guard()
        return {"schema": "elevenid.stable-publication-result/v2", "candidate_id": self.candidate["candidate_id"],
                "tag": self.candidate["tag"], "release_id": self.release_id,
                "original_run_id": self.candidate["run_id"], "publisher_run_id": self.authorization["publisher_run_id"],
                "authorization": self.authorization, "status": "published"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-run-id", required=True, type=int)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--gh", required=True, type=Path)
    parser.add_argument("--cosign", required=True, type=Path)
    args = parser.parse_args()
    github = GitHub(str(args.gh.resolve(strict=True)))
    try:
        publisher_context(dict(os.environ))
        directory = args.work.absolute()
        _, _, _, artifact = c.fetch(github, args.candidate_run_id, directory)
        gh, cosign = args.gh.resolve(strict=True), args.cosign.resolve(strict=True)
        authorization = authorize(github, directory, artifact, proof=Proof(gh, cosign))
        publisher = Publisher(github, directory, authorization, Ownership(gh, cosign, github))
        result = publisher.publish()
        args.output.write_bytes(h.encoded(result))
        claim = h.decode(h.bounded_file(directory / "checkpoint/assets/release-transaction.json", 65536))
        final = transaction.publish(claim, release_id=str(result["release_id"]),
            manifest_sha256=publisher.request["manifest_sha256"], publication_run_id=str(result["publisher_run_id"]))
        args.output.with_name("published-release-transaction.json").write_bytes(h.encoded(final))
        return 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"Stable publication refused: {error}", file=__import__("sys").stderr)
        return 1
    finally:
        args.output.with_name("publication-observations.json").write_bytes(h.encoded({"mutations": github.mutations, "crypto": github.crypto}))


if __name__ == "__main__":
    raise SystemExit(main())
