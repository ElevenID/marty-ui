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

### Restore combined runtime after publication

While the publication guard is active, use
`--backout-published --backout-phase restore-combined` with the original
selection file, plan, signed composition inputs, and guard. Use the
publication result's `intent_sha256` as `--intent-sha256` and the sealed
anchor as `--expected-anchor-sha256`. The owner checks that the split decision
is committed and that its exact selection is still current before changing
edge routing.

Run the same command with `--backout-phase verify-combined`, then
`--backout-phase retire-candidate`. Supply the fresh anchor returned by each
prior step. Restored routing, public and application handoff, and exact
candidate removal have their own observations. The reverse records retain the
original published selection and forward seal. The guard continues to fence
scheduled renewal and reboot throughout.

After retirement, run `--select-combined` with the original selection
file, plan, guard, and signed composition. Supply the retirement anchor as
`--expected-anchor-sha256` and the original split publication intent as
`--forward-intent-sha256`. The owner refreshes the combined runtime, native
custody and ingress before selecting the original Compose model in a new
journal segment. The selected credential generation and both prior segments
stay intact. An interrupted selection resumes with the new combined
`--intent-sha256`. The existing guard remains active after selection.

### Release the selected owner

After qualifying scheduled renewal and reboot in rehearsal, run
`--release-forward` for a committed split or `--release-combined` for a
committed restoration. Use the original selection file, plan, guard, signed
composition inputs, and the exact `--intent-sha256` from the applicable
selection result. Use the sealed anchor for forward release and the final
retirement anchor for combined release. Forward release also requires the
private browser session and both independently pinned identity digests.

The live operation proves the exact committed selection again, refreshes
its runtime, native and application checks, then writes a release receipt
and archives the original guard under the project lock. The receipt pins the
decision, selected journal and terminal evidence. If the archive already
exists, the same operation verifies the receipt and ancestry without
repeating runtime actions.

Complete the scheduled renewal and reboot rehearsal and verify a usable
combined backout before opening the production cutover. The guarded
`--backout-published` sequence applies while the website guard is active.

### Readmit rollback after forward guard release

Run `--readmit-backout` with the original selection file, signed composition,
plan and guard. Supply the committed forward `--intent-sha256`, the sealed
`--expected-anchor-sha256`, and `--release-sha256` from the forward release
result. The owner holds the exact split selection, requalifies its live
configuration and native generation, and records the current runtime and
mounts. This handles restarted containers when the admitted configuration
and selected inputs still agree, including an unhealthy website candidate
with the protected application ready. The existing project lock fences the
same-handle move of the archived guard back into service.

Use the returned `readmission_sha256` as `--readmission-sha256` for the
first `--backout-published --backout-phase restore-combined` call. Later
backout phases use each new terminal anchor and the recorded readmission.
When an ordinary renewal or model repair has advanced the split owner, a
new plan against the current selection is required before restoring.

After an ordinary renewal, run `--plan-current-backout` with the same
selection file, signed composition, forward plan, guard, sealed anchor,
forward intent and release digests used for readmission. It verifies the
archived release, traces the selected split through credential renewal and
ordinary journal continuation, and renders the original combined source
and retained overlays under both current credential environments. It checks
the live split's mounts, edge configuration, ingress and native credentials.
Retain the returned plan and its digest with the observed generation.
Generate a fresh v2 plan before edge restoration. In rehearsal, supply its
digest as `--current-plan-sha256` to `--restore-current-edge`, along with the
same forward evidence and inputs. The owner rechecks the selected generation,
records the plan and installs the shared guard before recreating only the
edge with the retained staged overlay and current credentials. A successful
receipt identifies the replacement edge, restored routing configuration,
ingress and unchanged protected runtime.

Use `--reconcile-current-edge` with the same inputs after an interrupted
readback. It requires a durable successful Compose return and freshly verifies
the running edge. A missing or failed return requires operator reconciliation.

After the restore receipt, run `--backout-published --backout-phase verify-combined`
with the current plan digest and the same historical evidence. Supply the
private `--session-state-file`, `--expected-account-sha256` and
`--expected-organization-sha256`. The owner tests the original application
marker, console, gateway, OIDC and browser handoff, verifies combined routes
over public HTTPS and the installed loopback edge, and exercises the account
and organization endpoints with the scoped session. It binds the result to
the restored edge, the candidate container ID and the other running services.
Save the returned `qualification_sha256`.

For `--backout-phase retire-candidate`, keep those inputs and pass that digest
as `--qualification-sha256`. The owner repeats the live checks before writing
the retirement intent. It stops and removes the exact candidate, records the
returned result, and checks the combined runtime and authenticated endpoints
again. After a recorded successful removal, the same invocation can finish an
interrupted readback. A retirement intent without a successful return requires
operator reconciliation even when the container is absent. Keep the returned
retirement receipt digest. With the same account, organization, session and
current plan, pass it as `--retired-receipt-sha256` to
`--backout-phase verify-retirement` in place of the qualification digest.
This read-only phase checks the completed removal, surviving services and live
authenticated combined routes while the guard is held.

Use `--select-combined` with the current plan, retirement receipt and original
forward release pins. Supply the original forward publication as
`--forward-intent-sha256`. Keep the original guard and sealed anchor pins.
The owner rechecks the live combined deployment, then publishes the restored
Compose configuration with the selected renewed credentials. If publication
was interrupted after its intent was recorded, verify the existing combined
intent and supply its digest as `--intent-sha256` for reconciliation.

Use `--release-combined` with the same inputs and the committed combined
intent digest. The owner requires the exact selected destination and fresh
authenticated evidence before archiving the guard. After the archive, the
same release pins can replay the recorded outcome without a session, including
after a later ordinary renewal or journal continuation. Keep the prior forward
release, both selection journals and the archived guard for recovery.

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
