# Managed Windows website transition plan and journal contract

## Scope

`scripts/selfhost_windows_website_plan.py` and
`scripts/selfhost_windows_website_journal.py` define an inert first-cutover
contract for the existing managed Windows generation owner. They construct and
validate Python objects and canonical record bytes in memory. They do not create
files, hold the owner's lease, write guard markers, inspect Docker, change
containers, publish a successor, or authorize production activation.

The managed owner keeps these records in an attempt directory and an independently
pinned tail namespace. The existing selection journal retains its closed namespace
and ancestry rules. [Renewal activation](windows-renewal-activation.md) and
[Compose recovery](windows-compose-recovery.md) still use that selection.

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
and requires a live caller to reconstruct the plan under the existing owner.
The [managed check-only invocation](windows-managed-website-preflight.md#reconstruct-the-first-cutover-plan)
can make that reconstruction from the held selection, composition and cached
image and report its hashes before a transition is attempted.

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

The plan checks these declaration inputs in memory. The [managed website
preflight](windows-managed-website-preflight.md) separately checks a compatible
full v4 composition against the installed bind and holds the Windows template
bytes through owner exit. Running Nginx configuration and route behavior require
transition qualification.

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

### Durable storage

The bundled `selfhost_windows_website_store.py` uses the selected owner's private
NTFS writer. The transition caller must hold the existing project lock and
provide the reconstructed plan. It allocates a private `journal` directory
below the planned attempt and a separate `.<project>.website-tail-<cycle>`
directory directly under the owner root.

The store flushes the canonical phase record and verifies its held bytes before
creating the corresponding immutable tail record. Each tail binds the exact
phase record, plan and previous tail. The caller retains the accepted tail
digest independently. Reads require that pin and check exact membership and
the complete chain, including the separately stored initial-stage abort
receipt when present.

A partial write or an advancement past the retained pin requires
reconciliation. The caller can re-anchor a fully written next phase record
after independently verifying that record and its observations. This operation
accepts the retained prior pin and exact verified record digest and writes only
the missing tail. A durable started record still requires runtime
reconciliation before any new operation.

### Shared owner guard

The managed selection lease can begin a website attempt after reconstructing
the full plan under held inputs, matching the operator's expected plan digest,
and passing existing current readiness, native authority and storage custody
checks. It reserves the existing project product-transition guard before
creating the attempt and initial journal. The guard binds the selected owner,
exact plan, attempt and initial tail. The existing guard blocks ordinary
renewal, recovery and other product transitions during a website attempt.

A pending website read requires the exact guard and retained tail digests,
replays the original selected generation and verifies the typed guard against
that owner before opening the journal. This read returns phase status. The
runtime executor must reconcile the actual workload and provide its evidence
before advancing a pending phase or retiring the guard.

### First workload phase

The selection owner can stage the website from the initial guard and tail.
It re-authenticates the original composition, reconstructs the sealed plan,
and renders a one-service Compose overlay against the retained source.
The entire normalized combined model must survive unchanged once the new slot
is subtracted. Fresh current readiness, native custody and storage checks
precede the durable `stage-candidate.started` boundary.

Only the new `website-a` service is started, with the cached image, no
dependencies and no published ports. The foreign-storage observer also
compares protected existing containers, checks the selected secret mounts and
verifies the new image, networks and declared data snapshot. Completion
requires a healthy candidate with zero restarts. A failed command or
postcheck leaves the guard and started record for reconciliation, and the
combined edge stays on its retained routing.

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

The owner verifies the observation preimages, the exact selected runtime and
candidate absence. A separate dispatch authorization distinguishes a stage that
never dispatched from one with an uncertain outcome. Completed compensation
binds the original candidate and the removal result. Unknown command outcomes
remain `reconciliation-required`.

### Restore the combined owner after a terminal stage abort

Use the selected owner with the private canonical plan, the original composition
proofs, the original guard digest and the current terminal tail anchor digest.

```powershell
python -B scripts/selfhost_windows_website.py --release-abort `
  --selection-file $selectionFile --plan-file $planFile `
  --composition-dir $compositionDir --gh $pinnedGh --cosign $pinnedCosign `
  --registry-config $registryConfig --guard-sha256 $guardSha256 `
  --expected-anchor-sha256 $terminalAnchorSha256
```

`--authority-file` can select an existing native authority file when the current
owner requires it. The owner reauthenticates the signed composition and refreshes
readiness, native and foreign storage custody, combined Nginx configuration,
public routes and application handoffs. It holds the original selected generation
and writes the abort release evidence before a no-overwrite same-handle archive
of the guard. The exclusive project lock stays held across the rename. The
archived guard, terminal records and all observations remain available for review.
Ordinary renewal can then enter the combined selection and must perform its own
current checks. Repeating the command with the same pins reads the historical
release if the archive is already present.

### Complete a verified combined backout

After `restore-combined` and `verify-combined` are anchored, use the same private
plan, composition and guard inputs with `--retire-candidate` in place of
`--release-abort`. Use the tail anchor for `verify-combined` on the first call.
The owner requalifies the combined runtime and removes only the candidate whose
ID and Compose inputs match the staged and verification records. The guard and
any retained, unmounted route files stay available for evidence.

After the removal result is anchored, combined public routing and application
handoff are qualified again. If qualification fails, the `retirement-returned`
tail can resume verification with the same operation. An authorized removal
without a recorded CLI return requires reconciliation before proceeding.

Use `--release-backout` with the `retire-candidate.completed` tail to archive
the exact guard and return to the original combined generation. This path
refreshes the same combined custody and ingress proof and keeps the backout
history. An already archived guard supports historical readback with the same
pins.

`forward-evidence-complete`, `combined-backout-evidence-complete`, and
`abort-evidence-complete` describe the terminal record structure. A stage abort
returns to the original combined selection through the separate archive step.
### Prepare the forward successor

After `verify-website`, run `--prepare-forward` with the original guards and
composition inputs, the verified split tail, and a private Playwright
`--session-state-file` from the authorized acceptance browser. Supply the
independently recorded `--expected-account-sha256` and
`--expected-organization-sha256`, each computed from the UTF-8 bytes of the
exact expected identifier. Use the application session export shape with an
empty `origins` list. Keep the live session file outside Git and the attempt.

The owner repeats the signed split, edge, public and OAuth handoff checks. It
uses the scoped session cookie over canonical HTTPS for `/v1/auth/me` and
`/v1/organizations/mine`, and retains the independently supplied identifier digests, confirmed checks,
and TLS observations. Perform the required interactive sign-in in the acceptance
browser. Use a session exported from that qualification for this operation.

Preparation also renders one persistent split Compose file with both retained
credential environments. Its normalized model and configuration hashes must
match the admitted multi-file layouts. The candidate retains the original
combined model, selected credential identity, signed proofs and empty future
activation outputs. Use the returned candidate and qualification digests when
reviewing the proposed publication. The journal stays at `verify-website` so
combined rollback remains available during preparation.

### Seal and publish the guarded successor

Run `--seal-forward` with the same plan, guard, signed composition and
authenticated session inputs. Pass the last verified journal anchor via
`--expected-anchor-sha256`, and the preparation result via
`--candidate-sha256` and `--qualification-sha256`. The owner repeats live
verification, including the account and organization checks, and records the
unchanged running split in the phase journal. An anchored seal that started
before an interruption can be completed with its exact started anchor and
the same qualified candidate. Before publication begins, the original owner
can still run `restore-combined` from the sealed anchor.

Run `--publish-forward` with the same candidate and qualification digests,
the sealed anchor via `--expected-anchor-sha256`, and current signed
composition and authenticated session inputs. The publisher repeats the
live checks with the same independently pinned identity. The
publisher checks the retained combined configuration and verification prefix,
revalidates the native generation, and prepares a successor using the split
Compose source. Its local sequence starts at one. The overall credential
generation, selected inputs and native custody stay the same.

The decision becomes visible through an atomic rename under the project lock.
Reconciliation requires the exact `--intent-sha256` and repeats the proofs
before continuing. A partial publication fences the predecessor. The existing product
guard stays active after the rename, including while the original entrypoint
resolves the successor for inspection.

Complete the rehearsed postpublication backout, guard release, and scheduled
renewal and reboot qualification before admitting production cutover.

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
