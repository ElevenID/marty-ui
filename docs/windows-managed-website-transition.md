# Managed Windows website transition plan and journal contract

## Scope

`scripts/selfhost_windows_website_plan.py` and
`scripts/selfhost_windows_website_journal.py` define an inert first-cutover
contract for the existing managed Windows generation owner. They construct and
validate Python objects and canonical record bytes in memory. They do not create
files, hold the owner's lease, write guard markers, inspect Docker, change
containers, publish a successor, or authorize production activation.

The current owner does not consume these records. Do not place them in its active
selection journal: the owner's closed namespace and ancestry rules remain in
force. This milestone introduces no second record owner and does not change the
[renewal activation](windows-renewal-activation.md) or
[Compose recovery](windows-compose-recovery.md) entry points.

The first operation is deliberately bounded: retain the selected combined
application and its full audience, add `website-a`, then attach the website route
directory to the existing edge. Later website upgrades, previous-slot promotion,
and `website-b`/`website-c` allocation need a separate contract using the existing
three-slot vocabulary.

## Plan inputs and identities

A plan binds the original full-audience standalone website release, the selected
web composition, its route contract, and hashes of all six original outer proof
files:

- `web-composition.json`
- `web-composition.json.sigstore.json`
- `web-composition.json.provenance.jsonl`
- `web-composition.zip`
- `web-composition.zip.sigstore.json`
- `web-composition.zip.provenance.jsonl`

The website must use the full standalone release schema. The retained application
and composition must identify the private commerce producer and full audience.
The composition manifest hash must match its original canonical bytes. These are
structural and identity checks; the plan never verifies a signature, downloads an
artifact, or authenticates a producer. A future caller must use the existing
verified-package boundary and original proof bytes.

The owner anchor binds project, Docker engine and named pipe, local Windows root,
current selection sequence, cumulative generation sequence, binding, journal,
raw configuration, retained model, selected credentials, selection record,
native custody, historical TLS initializer, and complete data snapshot. Segment
sequence and cumulative generation sequence remain distinct; a selected sequence
of nine can belong to cumulative generation 33.

`validate_plan` reconstructs the complete declaration from those original held
inputs and requires exact equality. `validate_envelope` checks record integrity
and the immutable contract shape; neither the envelope nor a self-consistent
SHA256 can authenticate its own inputs. Journal parsing uses envelope integrity
and still requires the future caller to reconstruct the plan under the existing
owner.

## Allowed model and data changes

The baseline service set must be exactly the composition's product roles plus the
integrated OpenBao roles. Immutable product and provider image references must
match. An existing website slot or any build definition refuses this initial
operation.

| State | Compose source proposal | Complete data snapshot | Website route bytes |
| --- | --- | --- | --- |
| `combined` | Exact retained model | Exact retained snapshot | Empty |
| `staged` | Add `website-a` only | Add candidate image config ID, with no non-secret mounts | Empty |
| `split` | Add the read-only edge route-directory bind to the staged proposal | Add the exact declared edge bind to the staged snapshot | Existing website renderer output |

The contract reuses the ordinary website renderer's pure service and route
definitions. The intermediate rendering object is never persisted as an ordinary
website owner. Only the allowed public environment and analytics/site-verification
secret mounts can enter the new slot. The candidate gets no published ports or
product dependencies. The edge must use an explicit, nonempty set of declared
shared networks; host/container network modes, aliases, and fixed network
addresses refuse the initial plan.

All existing application, backend, provider, historical initializer, credential,
port, environment, volume, and network declarations survive exactly. Only the edge
can acquire the declared route bind. Removing that bind and the newly declared
slot from the proposal reproduces the retained model.

The proposal hashes identify the exact in-memory **Compose source objects**.
The added service uses source-form settings from `compose_overlay`, so a fresh
`docker compose config --format json` rendering may normalize values and add
defaults. Its output is a separate identity. `check_models` accepts the exact
source proposals after full plan reconstruction; it does not compare a normalized
runtime model to a source hash. A future owner must bind both the retained source
proposal and the normalized configuration used for execution.

The data snapshots follow existing `renewal.data_mounts` semantics: image config
IDs and every non-secret runtime mount, including read-only mounts. Adding a
candidate and adding a read-only edge mount therefore produce three different
whole-project hashes. The plan does not redefine the original data hash or claim
it stays unchanged. Subtracting precisely the declared additions reproduces every
original data row and mount. A future successor must accept the explicit
`data_after` baseline while retaining the original selected-credential identity.

The candidate image config ID and declared bind are proposed inputs, not observed
image or mount evidence. Image metadata, unexpected image-declared volumes, real
mounts, and the live service closure still need qualification.

## Edge template and route baseline

The owner-root template bind at
`/etc/nginx/conf.d/default.conf.template` must be read-only in both the retained
model and supplied runtime snapshot. The local or recognized Docker Desktop
bridge source must identify the same retained path. The plan binds the exact
runtime mount record, supplied template byte length, and supplied template digest.

The supplied template must contain one uncommented website include and an
independent `/edge-healthz` location. The existing edge healthcheck must use that
endpoint and have no product dependency. The retained model and runtime snapshot
must contain no existing website route mount, ancestor mount, or nested route
mount. The new route directory is confined to an attempt directly below the same
Windows owner root.

These checks make the declared baseline coherent. They do not read the installed
template, establish file custody, test Nginx syntax, prove Docker path identity, or
prove that the running edge loaded those bytes. Those qualification fields remain
false.

## Journal phases, interruption, and backout

The journal contract uses canonical sorted JSON with a trailing newline,
consecutive filenames and sequence numbers, a fixed plan digest, and a parent
digest for every record after intent. Record and evidence-key inventories are
closed. A separately held expected tail digest is mandatory; an intact shorter
prefix cannot masquerade as the currently retained history.

The phase graph is:

| Path | Ordered phases | Resulting declared state |
| --- | --- | --- |
| Forward | `stage-candidate` → `route-website` → `verify-website` → `seal-forward` | `split` |
| Combined backout | `restore-combined` → `verify-combined` → `retire-candidate` | `combined` |
| Failed initial stage | `stage-candidate.started` → `stage-candidate.reconciled-abort` | `combined` |

A successful phase has a started record followed by a completed record. Start records bind
owner-lease, native-custody, foreign-storage, and runtime-before evidence digests.
Completion records bind the exact phase-specific runtime, image, template,
configuration, ingress, application-handoff, or successor-candidate evidence
digests. These are **references**: the parser does not verify receipt contents.

After any completed staging, routing, or website-verification boundary, the next
record can take the backout path. Backout first removes the route mount and
restores combined routing while keeping the candidate staged. It then verifies
the combined application fallback and application handoffs. Only after that
verification can it retire the candidate and return to the exact combined model
and data snapshot. No existing application or provider image changes.

An uncompleted started phase always yields `reconciliation-required` with no
permitted new phase and `automatic_replay_allowed: false`. The reported model state
is the last completed declared boundary, not an assertion about a partly changed
runtime. A future owner must reconcile actual observations before recording a
completion or choosing any recovery action. This contract does not guess whether
a Docker action happened or replay it.

### Failed initial-stage reconciliation

An initial candidate may never be created, or may be created but fail startup or
health checks. Neither outcome can honestly produce a successful
`stage-candidate.completed` record just to reach the ordinary backout path.
The dedicated `reconciled_abort` constructor can instead record a terminal
`stage-candidate.reconciled-abort` after independently held observations establish
the exact combined baseline and candidate absence.

This exception applies only to the first pending stage, with no completed phases.
The separately supplied closed `marty.windows-website-initial-stage-abort/v1`
receipt binds the original plan, exact started-record digest, owner binding,
selected credentials, and exact combined model/data/empty-route state. Its closed
observation inventory references owner lease, native and foreign-storage custody,
runtime, normalized model, retained product, mounted template, edge configuration,
combined public routes, application handoffs, selected credentials, and candidate
absence. The observed outcome is either `never-created` or
`created-then-compensated`; the latter additionally requires a compensation
receipt reference. Both require an independent candidate-absence observation.

The terminal journal record binds this receipt's digest. Parsing requires the
receipt as a separate held input; an embedded claim or a receipt supplied without
the terminal record cannot close the pending phase. The completed-phase list
remains empty. No forward phase, ordinary backout, or repeated abort can follow it.

Receipt structure and hashes do not establish freshness, execution order, actual
absence, or custody. The future owner must verify those observations under its
held lease, prove that any compensation changed only the declared candidate, and
confirm that all retained product/provider/data/credential identities still
match. The constructor executes no compensation and clears no real guard. A
candidate still present or a changed baseline remains unresolved. Other
interrupted phases retain `reconciliation-required` until independently qualified
evidence supports their proper completion; their compensation paths remain future
integration work.

`forward-evidence-complete`, `combined-backout-evidence-complete`, and
`abort-evidence-complete` describe
record structure only. They do not mean a durable successor was published.
`seal-forward` binds a successor candidate receipt; publication, immutability,
ancestor closure, and selected-owner reseeding remain outside this module.

## Required integration before activation

The next runtime milestone must join the existing owner rather than introduce an
independent deployer. It must supply all of the following before admitting host
mutation:

1. Existing exclusive lease, native ancestry, namespace and product-guard rules,
   including renewal and reboot refusal while a website transition is pending.
2. Durable immutable records with flush and publication ordering, a retained tail
   anchor, and recovery of interruptions without inventing completion evidence.
3. Original authenticated full composition and proofs, installed website image
   identity and metadata, source and normalized model qualification, actual edge
   template bytes, and native/foreign-storage custody.
4. Live staged and split service closure, candidate and edge readiness, public
   routes, callback/login/application handoffs, and verified combined fallback.
5. Explicit acceptance of the changed full data snapshot and website secret
   consumers in renewal and recovery, with selected credentials and all retained
   product/provider/data identities preserved.
6. Windows/NTFS and Docker Desktop qualification of the integrated writer,
   interrupted phases, backout, renewal, and reboot behavior.

Until then, every plan qualification field is literally false, and journal
inspection reports `receipt_contents_verified`, `owner_publication_supported`,
`activation_supported`, and `production_admission` as false.

## Validation scope

The focused tests build synthetic full compositions and runtime observations,
exercise source/model/data preservation and refusal cases, and cover forward,
backout, interrupted, failed initial-stage abort, tampered, and truncated record
chains. A real Compose
renderer checks that normalization preserves the same bounded additions.

The package-proof fixture uses synthetic proof bytes and mocked verification
transport. These tests do not authenticate a real private release, run containers,
exercise Windows file custody, complete live application journeys, or provide
production activation evidence.
