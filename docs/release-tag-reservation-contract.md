# Create-only tag reservation and authenticated release admission

This contract revision addresses an observed incompatibility between the earlier
atomic main/tag handoff and GitHub's protected-main rules. It requires explicit
owner approval and normal protected integration before activation. A draft PR or
local test is not live capability or release qualification.

## Evidence and decision

[Original capability run 41943309794, attempt 1](https://github.com/ElevenID/marty-ui/actions/runs/41943309794)
ran on accepted source `c3dea5ed8982f674bbdb96a462ea21520de4633f`.
Both its stale-main negative request and current-main positive request received
GitHub's GH013 requirement for a merge queue and pull request. The positive
request explicitly sent current main to the same current main; GitHub still
rejected the branch command and atomically rejected the tag command. Both
original response bodies have SHA256
`823d21cc0eba765769a5df2d88142c80db2f1c5a2598ca03dc2610700d5e16bb`.

The result ZIP is artifact `13378080002`, 385 bytes, SHA256
`db99e46fe12dbdd36aaf60284dac2b15265aa58289932e510e872cd4e5f44040`.
The observations ZIP is artifact `13377590831`, 33,803 bytes, SHA256
`35ab82f795062e621a6443e06ea71b1f2e733890babc147e66786b086dc82bee`.
The verifier parsed the actual responses correctly and refused at
`capability_positive`. The original failure remains a failure. An annotated tag
object was created, but independent readback found no audit tag ref and unchanged
main. Neither a parser relaxation nor another identical run supplies success.

The decision changes one guarantee:

| Property | Earlier atomic contract | Reservation contract |
| --- | --- | --- |
| Candidate source | Exact originally qualified commit | Exact originally qualified commit |
| Tag creation | Absent-to-annotated object in a two-ref transaction | Create-only absent-to-annotated object |
| Main at tag-write instant | Required atomic main comparison | No atomic main comparison is claimed |
| Main and review authority | Checked before and after handoff and publication | Same checks retained |
| Release authority | Successful bound operator and publisher evidence | Successful bound operator and publisher evidence |
| Concurrent main advance | Transaction or subsequent admission fails | Observed advance fails admission; an unused tag may remain |
| Failed or unknown tag write | Preserve evidence; no automatic retry or cleanup | Same, including no adoption or version reuse |

The release operator retains its existing ref permissions and never updates
main. The publisher has job-scoped `actions: write` permission to dispatch that
operator automatically. Rulesets, branch protection, merge queues, and required
checks remain unchanged.

## Admission sequence

1. Qualify the exact source with the required original full CI, claim, candidate,
   official evidence and the v2 automated verifier assessment. Preserve the
   existing original-attempt requirements. Protected main remains the candidate
   source; no per-release review commit or human review window is required.
2. Seal the original 32 publication assets, official gate authority, and
   exact candidate identity in a versioned checkpoint. The tag handoff retains
   its fixed 15-minute deadline.
3. The publisher dispatches the independent operator once using its scoped
   `GITHUB_TOKEN` with `actions: write`, after persisting a dispatch receipt.
   Require GitHub API version `2026-03-10` to return HTTP 200 with the exact run
   ID and canonical URLs. A lost or ambiguous response stops without another
   dispatch. On protected main, the operator authenticates the waiting publisher, its claim,
   checkpoint ZIP, visible rules, source/review authority, image digests, and all
   cryptographic proofs. Recheck current main immediately before the tag action.
4. Acquire the per-version annotated ownership tag
   `v-release-intent-<major>.<minor>.<patch>`. Its exact message binds the contract,
   production tag, original CD/claim/checkpoint, source, admitted main and one
   original operator run. Require HTTP 201 and exact object/ref readback before
   a production-tag mutation is eligible. Any existing ownership is a collision,
   including an apparently identical owner.
5. Create and verify the production annotated object pointing to the original
   source and binding the ownership ref/object. Persist its ref-creation intent,
   then make one REST create-reference request for the absent production tag.
   Require HTTP 201 and the exact annotated-object response. Never use an update
   endpoint, force operation, lightweight intermediate tag, or overwrite fallback.
6. Read back both exact refs, objects and messages, main, context, and visible rules.
   Emit a versioned successful operator result only if every required check
   succeeds within the original deadline.
7. The original publisher authenticates the successful operator workflow and
   result artifact, then independently checks the tag, main, review authority,
   original checkpoint, assets, and live run. A tag alone cannot admit a release.
   The separate v2 publisher continues authenticating original CD success and
   rechecking its policy, authority, ownership, and exact asset bytes around
   publication operations.

The repository's
[REST create-reference API](https://docs.github.com/en/rest/git/refs#create-a-reference)
has a ref and target object, not a precondition on a second branch. Before/after
main observations therefore cannot prove what main was at the tag-write instant.
This is an explicit contract change. It does not turn separate Git, registry,
workflow, and release operations into one global transaction.
Observations also cannot detect a main or visible-policy change that is restored
between reads. Existing branch protection reduces which changes are permitted;
it does not make the observations an atomic comparison.

The supported Marty publisher and installer require their authenticated evidence
beyond a tag. A public semver reservation is still visible to third-party tag
watchers and source downloaders, which may apply their own release semantics.
A reserved tag can therefore exist without a published or installer-admitted
Marty release; external consumers must not infer that admission from its name.

## Failure and collision handling

A failed, cancelled, expired, foreign, or unknown operator result cannot authorize
publication even if a tag exists. Any observed main or review-authority change
stops admission. An existing tag is a collision, even if its object appears to
match. A lost create response cannot be repaired by adopting the subsequent
readback. Once an intent is consumed, a caught exception cannot cause another
mutation.

Confirmed per-version ownership persists across invocations. A later operator
cannot take over that version even when the production tag is absent. The
successful result, typed admission and publisher checks bind and re-read the
same ownership tag and object. Do not delete the owner to make a later dispatch
eligible.

If the initial ownership request is unconfirmed and no ownership ref exists, a
later invocation may acquire that still-absent ownership. This is a new ownership
acquisition, not a replay of a production-tag write: the earlier invocation could
not have reached production without confirmed ownership creation and readback.
An ownership ref that does exist always blocks another acquisition. This is the
enforced boundary; a process-local consumed-intent set alone cannot provide it.

A race or lost response can leave an immutable tag without a qualified release.
Retain the original receipts and remote state for incident review. Do not delete
or retarget the tag, renew the claim, rerun the original producer, or reuse the
consumed version. A later release requires a fresh unused coordinate and its own
qualification. The existing separately bounded v2 publication retry may resume
only an already admitted successful original candidate under its own unchanged
ownership and expiry rules.

## Version separation and qualification

The contract is `marty.create-only-annotated-tag/v1`, with
`ref_creation_scope=absent_tag_only`,
`main_check_scope=before_after_observation`, and
`tag_alone_authorizes_publication=false`. Capability is
`marty.release-tag-capability/v5`, the successful operator result is
`marty.release-tag-handoff-result/v2`, observations are
`marty.release-tag-operator-observations/v3`, the checkpoint is
`elevenid.stable-publication-checkpoint/v2`, admission is
`marty.release-tag-admission/v2`, and publication policy is
`elevenid.stable-publication-policy/v3`. The checkpoint, result, admission and
policy bind the same explicit tag contract. Earlier atomic receipts cannot be
relabeled or silently accepted under it. The externally selected publication
pipeline and candidate remain v2; their lifetimes are unchanged.

The capability experiment retains a genuine native negative protected-main
request and its original packet evidence. That proves only its exact recorded
protection or stale-ref refusal. The positive operation separately proves one
create-only annotated owner `v-release-capability-intent-<run>-1`, its bound audit
tag, and all required before/after observations.
Neither operation claims the old atomic main/tag capability. Preserve both tags
and require fresh original live evidence after approved protected integration.

Local tests must retain the original GH013 refusal and exercise collisions,
malformed responses, lost responses, main changes before and after creation,
failed operators, stale or mixed contract versions, wrong candidate/source/review
bindings, and deadline expiry. They cannot establish the live GitHub capability
of an unmerged branch.

## Supported-route assessment

The earlier GraphQL route is recorded as rejecting the annotated target. Its
[documented multi-ref atomic preconditions](https://docs.github.com/en/graphql/reference/git#updaterefs)
alone do not demonstrate this exact operation works. Ordinary Git send-pack
omits a no-op main update. The custom native request did send that update, and
the actual GH013 response rejected it. Git's
[wire protocol](https://git-scm.com/docs/gitprotocol-pack) does not offer a separate
remote verify-only command that exempts the branch from the server's update
policy. No examined route has demonstrated the earlier combination under the
current protections. This revision changes the contract explicitly instead of
reclassifying that failure or expanding the credential's authority.
