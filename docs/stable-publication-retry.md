# Stable publication after successful qualification

`Stack release` dispatches default to `publication_contract=v1`, preserving the
existing publisher while the new path is qualified. Select
`publication_contract=v2` explicitly for an approved rollout. The original run
still builds, qualifies, signs, promotes the exact image digests, and completes
the bounded annotated-tag handoff. For v2 it then seals a data-only candidate
containing the original checkpoint, signed assets, operator admission, policy
digest, and a closed inventory of file hashes. It must finish successfully before
publication.

The tag handoff uses `marty.create-only-annotated-tag/v1`. Its v2 checkpoint,
operator result and typed admission bind a create-only annotated-tag reservation
and before/after main observations. Publication policy v3 explicitly binds that
contract; the selected publication pipeline and candidate remain v2. Older atomic
handoff records cannot be silently reinterpreted under the new policy. A reserved
tag alone is not an admitted candidate or permission to retry a failed original
CD. See the [reservation contract](release-tag-reservation-contract.md) for the
precise guarantee change and explicit approval before activation.

`Publish stable candidate` starts from that successful completion. The publisher
uses reviewed code from protected `main`, authenticates the original CD run and
artifact through GitHub, and verifies the original signatures, provenance,
qualification, tag admission, lock, and promoted digests again. It never rebuilds
the candidate or executes code from the candidate archive.

## Retry a publication failure

1. Open the failed `Publish stable candidate` run and its
   `stable-publication-result-v2-<publisher-run-id>-1` artifact. Read the failure
   and mutation observations. Identify the original successful `Stack release`
   run, not the failed publisher run.
2. If the candidate is still within its fixed 24-hour lifetime, protected main
   and the policy remain unchanged, and the release has no conflicting state,
   start a **new manual dispatch** of `Publish stable candidate` on `main` with
   `candidate_run_id` set to the original successful CD run ID.
3. The new dispatch reauthenticates the candidate and creates a fresh in-memory
   authorization for at most 15 minutes, capped by candidate expiry. It continues
   only an owned draft whose existing assets match the original bytes. A complete
   matching published release succeeds without another mutation.

Do not use the GitHub rerun button, rerun the original CD workflow, edit a
checkpoint, supply historical resume inputs, or renew the candidate timestamp.
The new publisher accepts only attempt 1 of a new invocation. The original v1
15-minute authority is never extended or replayed by the v2 reader.

## Conflicting or unknown state

Publication creates an empty draft and attaches an exact-run keyless ownership
attestation before uploading assets. The receipt binds the release ID, tag,
candidate ID, original run, publisher run, policy, and protected-main source.
Every upload uses the original allowlisted name and exact bytes; existing assets
are checked by size, digest, and downloaded bytes. All 32 core assets must be
present before the final draft-to-published transition.

An unowned draft, foreign receipt, duplicate coordinate or name, incomplete
`starter` asset, changed digest, unknown upload outcome, changed protected main,
failed original CD run, or expired authorization stops publication. The tool
does not delete assets, replace bytes, adopt an unknown draft, or hide the error.
Preserve the observations and the remote state for explicit incident review.
An empty draft left by a failed signing or ownership step also requires that
review; a retry cannot claim it merely because its name matches.

Both supported core publishers use the same per-tag concurrency group. The
publisher checks candidate custody, protected main, original run success,
publisher identity, qualified tag, policy, and deadline around mutations and
again after final readback. The release listing is fully paginated with bounded
20-record pages so full asset inventories fit the transport bound.

## Compatibility and rollout

`publication_contract=v1` keeps the original one-attempt publisher and its
existing deadline. Historical v1 runs cannot be promoted into v2 candidates.
Automatic completion events from successful v1 runs simply have no v2 work;
manual v2 retry requests against those runs fail closed.

The optional Cloudflare add-on remains available with v1. Selecting it with v2
is rejected before builds because the v2 publication inventory is closed to the
core release assets. All downstream original-CD success requirements remain in
place. Staged installed-journey acceptance, anonymous clean-host replay, installer
admission, and signed channel promotion are still required for stable installer
activation; publication alone grants none of those approvals.

Merge readiness and runtime activation are separate gates:

1. Before merge, require the source and workflow reviews, local contract tests,
   and required pull-request/merge-queue checks. Keep v1 as the default. The
   trusted producer and publisher require protected-main code, so their exact
   live OIDC path cannot be qualified by dispatching the draft branch.
2. After merge, review the `stack-release` environment protection and obtain
   approval for the first live v2 release. Select `publication_contract=v2`
   explicitly and use the ordinary admitted release claim and qualified source.
   Verify the original CD result, candidate, signatures, publisher ownership,
   exact release assets, and downstream installer gates before routine v2 use.
3. A later reviewed change may make v2 the default after that evidence is accepted.
   Until then, ordinary dispatches continue to use v1.

There is no sandbox or dry-run target in the v2 publisher. A live invocation
creates or completes a stable release in `ElevenID/marty-ui` and marks it latest.
Treat that invocation as a release operation; do not use an ordinary dispatch as
an isolated rehearsal or bypass source/repository checks to simulate one.

Local failure-injection tests exercise custody, authority, conflicts, deadline
checks, partial upload recovery, and workflow wiring using explicitly synthetic
proof adapters. They do not claim to have produced or accepted a live release
signature. Website activation and production deployment keep their own runtime
qualification gates.
