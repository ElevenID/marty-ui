# Stable publication after successful qualification

New `Stack release` dispatches default to `publication_contract=v2`. The original
run still builds, qualifies, signs, promotes the exact image digests, and completes
the bounded annotated-tag handoff. It then seals a data-only candidate containing
the original checkpoint, signed assets, operator admission, policy digest, and a
closed inventory of file hashes. It must finish successfully before publication.

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

Before enabling v2 in normal operations, review the `stack-release` environment
protection and run an approved non-production rehearsal with real GitHub OIDC,
attestation verification, and release permissions. Local failure-injection tests
exercise custody, authority, conflicts, deadline checks, partial upload recovery,
and workflow wiring using explicitly synthetic proof adapters. They do not claim
to have produced or accepted a live release signature.
