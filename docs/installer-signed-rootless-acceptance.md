# Signed rootless acceptance on an existing host

The signed acceptance entry can use an independently prepared Linux amd64 AWS
host through the existing pinned SSH controller path. It requires an already
running rootless Docker daemon for the exact nonroot installation user. It does
not require a nested VM, install packages, configure the daemon, or change host
network routing. The [optional disposable QEMU path](selfhost-disposable-rootless-vm.md)
is a separate producer of guest identity evidence.

The implementation connects authenticated hosting input, rootless storage
admission and a distinct five-case startup observer. That observer invokes the
installed signed operator and a pinned real browser; it emits a startup report
only when their observations agree. Source and fixture tests do **not** establish
that an AWS installation or public browser run has succeeded. The full functional
and recovery contract, release admission, and normal `Ready` completion remain
closed until their independent installed assertion owners are available and run.

## Authenticated hosting input

A new acceptance authorization can bind the same configured DNS identity and
explicit IP landing-page alias used by the normal hosting owner. The narrow
signed interface supports `direct` hosting with Marty keyless termination and
`managed-ca` or `acme`. The broader normal hosting schema is documented in
[installer hosting](installer-hosting.md); it is not widened by an acceptance
parameter or arbitrary guest command-line flag.

The controller supplies an exact private `hosting-input.json` file, at most
8,192 bytes. In `installer-acceptance.yml`, the `hosting_input` text input is
written as those exact UTF-8 bytes before authorization. The authorizer's local
interface is `--hosting-input ABSOLUTE_PATH`. Unknown or duplicate JSON fields,
wrong types, noncanonical origins and unsupported combinations are refused.
Reformatting otherwise equivalent JSON changes its binding.

Authorization and controller-consumption schemas are v2 only when this file is
present. Each signed record and the shared context digest contain the same
closed hosting summary:

| Field | Meaning |
| --- | --- |
| `input_sha256`, `input_size_bytes` | Digest and size of the exact input bytes |
| `public_origin` | Stable canonical HTTPS DNS origin |
| `public_entry_origin` | One exact HTTPS IP alias, or null |
| `certificate_source` | `managed-ca` or `acme` |
| `acme_environment` | `staging`, `production`, or null for managed CA |
| `acme_terms_url` | Exact configured terms document, or null for managed CA |
| `staging_trust` | Exact root-bundle digest/size for ACME staging, otherwise null |

For ACME, the input must already contain explicit `terms_agreed: true`; no
controller or worker supplies agreement automatically. The ACME owner still
compares the terms URL with its directory response. Artifact phase `staged` or
`published` is separate from ACME environment `staging` or `production`.

ACME staging additionally requires the private fixed file
`acme-staging-roots.pem`, at most 65,536 bytes. The workflow accepts its exact
text through `acme_staging_roots`; the local authorizer uses
`--acme-staging-roots ABSOLUTE_PATH`. Its digest and size are included in both
signed summaries and the context. The normal native staging-root validator
checks the bundle, and the installation retains it under the existing
`staging-acme-roots.pem` basename. Staging roots are refused for production or
managed CA. A staging certificate never becomes production trust evidence.

Both grant archives and the fixed SSH transfer include only these additional
filenames when the signed version requires them. Native entry holds private
owner-only files and directory identities, checks exact bytes around external
signature verification and evidence persistence, and rechecks the installed
selection. v1 grants retain their original interpretation and reject any added
hosting file or field; mixed v1/v2 grant pairs are refused. Neither schema grants
an origin migration, arbitrary command execution, or another installation UUID.

## Rootless execution and retained authentication

The remote command applies `setpriv --no-new-privs`. Native admission requires
matching nonzero real/effective/saved UID and GID, no effective capabilities,
and the exact user's private `/run/user/<uid>/docker.sock`. The Docker identity,
rootless profile and kernel resource controls are checked before owned resources
are created. The existing canary and native ownership rules remain in force;
unrelated containers, networks or volumes are not adopted.

A new acceptance scope pins all nine authenticated files: the authorization,
controller consumption and inventory, each with its signature and offline
provenance proof. It retains their exact SHA-256 digests in
`authenticated_evidence_sha256`. Historical verification compares those original
bytes, including the controller's guest, disk, consumption time and proof
attachments. It verifies that consumption occurred while the grant was valid;
an expired grant does not invalidate historical readback or authorize dispatch
again. Legacy scopes without this map remain readable but cannot obtain the
new signed rootless canary/preparation authority.

`AcceptanceOnly` and `CandidateTest` remain different authorities. The former's
ACME preparation requires the exact 13 completed canary records and nine pinned
authenticated files. Candidate-test evidence cannot substitute for that set.
The production-public/IP acceptance path can return a typed
`SignedStartupObserved` result after real native startup validation. It remains
`AcceptanceOnly`, with journal phase `Provisioning` and `installation_ready=false`.
Candidate-test trial completion, staging certificates, managed/private trust,
canary completion and setup success cannot produce that result or grant `Ready`.

## Resource profiles and an existing AWS guest

The generic SSH controller defaults to `rootless-startup-8gib` and accepts an
explicit `--resource-profile`. Both new profiles use measured guest-visible and
Docker RAM, allowing the kernel reservation on a nominal 8 GiB instance:

| Profile | Memory admission | Docker filesystem | Evidence scope |
| --- | --- | --- | --- |
| `rootless-startup-8gib` | Guest and Docker each at least 7 GiB | At least 20 GiB free | Startup path only; cannot promote |
| `rootless-functional-recovery-8gib` | Same measured floors | Same free-space floor | Full functional/recovery contract; every required installed assertion must pass |
| `qualification-32gib` | Historical 32 GiB policy | Historical 20 GiB floor | Unchanged legacy v1 interpretation |

The new resource gate allows the full contract to be exercised on the intended
8 GiB host; it is not a measurement that the full contract has passed there.
Neither profile establishes throughput, concurrency, or load capacity. The
older `startup-8gib` and engineering profiles retain their previous meanings.

The v2 host observer records the actual resource census, image cache, runtime
socket, filesystem device, credential-file presence and development-tool
presence. Existing image caches or neighboring stacks are permitted and remain
visible. This does not claim a fresh guest or exhaustive source/credential
absence. The tested installation must still use the exact signed artifact,
verified provenance and pinned images without source checkout or runtime
patching. Full qualification additionally requires independent before/after
neighbor preservation and owned isolation evidence.

No QEMU provisioning receipt is required by the generic SSH runner. Its
independent signed controller target still binds guest ID, disk identity,
Docker Engine and installation UUID. The optional QEMU producer binds its
explicit profile through seed, launch, measured readiness, consumed intent,
exchange and each dispatch preflight; it cannot relabel a legacy guest as v2 or
switch profiles after consumption.

## Real startup observation

The workflow's `execution_result` choice defaults to `incomplete-checkpoint`.
Select `startup-observation` with `execute=true` to request the distinct startup
path. It requires authenticated v2 hosting with an exact canonical DNS origin,
one IP alias, ACME **production**, explicit terms agreement, and no staging root
bundle. The original artifact phase can still be `staged` or `published`.

Prepare the separate controller browser runtime using the exact local archives
and instructions in [the browser runtime guide](installer-startup-browser-runtime.md).
The fixed runtime is Node 24.22.1, Playwright Core 1.62.1, and full Chromium
151.0.7922.34/revision 1234. Admission checks the code-bound manifest and every
file in the private runtime tree. The browser runs as an ordinary nonroot user
with Chromium's sandbox enabled; there is no browser download, package install,
custom root import, proxy override or TLS-error bypass in the observation path.

Add these options to the existing authenticated SSH controller invocation of
`scripts/installer_acceptance_runner.py`:

```sh
--resource-profile rootless-startup-8gib \
--browser-runtime /absolute/private/browser-runtime
```

The runner still needs the original private assets, grants and proof files,
context, four-field controller target, consumed nonce ledger, pinned verifier
binaries, SSH identity and pinned known-hosts file. The controller's approved
GitHub identity must be able to observe the exact active workflow run. It never
copies a source checkout, browser runtime or controller credentials into the
customer installation. Existing AWS SSH qualification remains independent of
the optional QEMU producer.

The five cases have distinct real owners:

| Startup case | Required observations |
| --- | --- |
| Artifact verification | Inventory plus all four payload digests, signatures and exact build provenance; both acceptance grants authenticated to the exact harness invocation |
| Isolated install | Exact signed installation UUID, rootless storage canary, retained native identities and image pins, and no adoption of resources present in the initial host census |
| Startup runtime | Current selected initial or successor generation, expected live native service states, bound local HTTPS, actual landing document and shipped asset fingerprints |
| IP browser entry | Actual browser HTTPS navigation to the configured IP, visible landing heading and branding, loaded images, actual response bodies matching the native asset fingerprints, raw IP URL retained, and no IP session request, credential header or cookie |
| Canonical origin routing | Actual clicks on the existing sign-in action and the visible public-entry-only Console link, with their first document requests going to `/v1/auth/login` and `/console` on the configured canonical DNS origin |

The routing case does not log in, submit credentials, require a registration
action or change signup policy. A registration URL helper is component coverage
only. Canonical redirects remain on the configured origin. Both native public
chain validation and the browser's normal HTTPS verification are required, and
the observed browser leaf must match the native-bound public leaf.

The installed operator exposes a fixed read-only command:

```sh
/absolute/installation/marty-deploy startup-observe \
  --install-dir /absolute/installation --docker-bin /usr/bin/docker \
  --observation-id CANONICAL_UUID_V4 --challenge LOWERCASE_64_HEX_DIGITS
```

The controller supplies fresh request challenges, observes the native owner
before and after the browser, and requires the exact current selection, resource
identities, public leaf, hosting and page fingerprints to remain the same.
Initial selection binds its four real retained records; a public successor binds
the exact ten-record sequence/attempt closure. Rollback-only evidence and an
empty selection map cannot qualify. These bounded observations are explicitly
not an atomic snapshot or a continuing availability guarantee.

Browser execution has an isolated Linux supervisor. It retains ownership of the
browser process tree with subreaping and PID identity checks, including Chromium
children that start their own process groups. Timeout or cancellation requires
bounded cleanup. A stalled cleanup or a remaining descendant is a failure and
cannot produce a successful startup report.

### Pending ACME issuance

Initial ACME issuance is asynchronous. **There is no installed systemd lifecycle
owner before application startup completes**: lifecycle export happens after
the application and native validation succeed. A zero exit with an ACME-pending
record therefore does not mean startup was observed.

With the browser startup mode selected, the controller can continue only a
typed, known pending order returned by the exact signed operator. It invokes:

```sh
/absolute/installation/marty-deploy acme continue \
  --install-dir /absolute/installation --docker-bin /usr/bin/docker
```

The command and paths are fixed from the original target. Before every automatic
invocation, the controller rechecks the original unexpired signed grant, exact
active workflow invocation and retained input custody. It honors the later of
the native poll and retry deadlines, limits this continuation window to 900
monotonic seconds and at most 180 invocations, and records an intent before each
SSH operation. It does not repeat installation or manufacture a new ACME order.

Unknown order outcomes, terminal/replacement results, unsafe phase holds,
expired authorization and a lost response stop automatic mutation. The retained
native owner still enforces its own durable ACME protocol rules. The customer
may use the explicit local continuation command against the retained state
after the controller grant expires; that does not extend the workflow grant or
authorize another controller dispatch. A timed-out qualification invocation is
not resurrected by a later local recovery. Read-only startup observation never
infers success from a failed or ambiguous command response.

### Returning a startup report

After all owners pass, the runner writes the bounded private file
`installer-startup-observation.json` using
`elevenid.installer-acceptance/v2` and profile `rootless-startup-8gib`. It embeds
the exact public native/browser owner records and their digests. Failed runs
retain the ordinary incomplete checkpoint and available partial observations;
they do not create a passed startup report.

The approved controller uploads this fixed subject to the original owned draft
using `scripts/installer_acceptance_return.py upload-startup-payload`. Supply
`--report`, the original `--authorization`, `--receipt`, `--inventory`,
`--assets`, `--descriptor`, consumed `--ledger`, pinned `--gh` and `--cosign`,
`--harness-source-sha`, `--run-id`, `--run-attempt`, approved
`--controller-user-id`, and a fresh private `--output` receipt path. It holds the
controller registry, verifies the exact active invocation and original receipt
asset, and persists an exclusive upload intent before its only POST. A lost
upload response leaves that intent and prohibits blind replay or overwrite.

The workflow uses `receive-startup-payload` to independently reverify the
inventory, all four original payloads, both grants and their exact proof bytes.
It checks the approved uploader, original draft/receipt, exact active run and
closed owner records before signing. Files, parent identity and content remain
bound across external verifier calls. The workflow signs and attests the
distinct subject and archives `installer-startup-observation-RUN-ATTEMPT`.

After that exact workflow invocation has completed successfully, a consumer
uses the separate final reader:

```sh
python scripts/installer_acceptance_return.py verify-startup-return \
  --report /private/return/installer-startup-observation.json \
  --signature-bundle /private/return/installer-startup-observation.json.sigstore.json \
  --provenance /private/return/installer-startup-observation.json.provenance.jsonl \
  --inventory /private/assets/installer-inventory.json \
  --gh /private/tools/gh --cosign /private/tools/cosign
```

The inventory's signature and provenance sidecars must also be present. This
reader obtains the authoritative completed-success run, verifies the inventory
and signed report against the exact invocation, and returns startup-only facts.
An active, failed, mismatched or different-attempt run cannot satisfy it. There
is no `allow-active` option on the final consumer.

## Checkpoints, full qualification and promotion

The running controller emits `elevenid.installer-acceptance-checkpoint/v5` for
the new profiles. It binds signed hosting, the nine source digests, actual host
runtime and resource-census digest, exact invocation and target, and retained
status/trust/TLS observations. Readback requires the native scope's exact source
map and observed UID/socket. Hosting readback checks the canonical origin, raw
input digest, certificate source and CA environment; production public metadata
must contain the exact configured IP SAN. Local HTTPS success does not prove
that the public IP page rendered in a browser.

Only implemented cryptographic artifact verification is marked passed in this
incomplete checkpoint. Every remaining installed assertion stays blocked.
`acceptance`, `installation_ready`, `functional_recovery_qualified` and
`load_characterized` stay false. The same-invocation return path rechecks the
original files and context before signing a distinct incomplete-checkpoint
artifact, then fails installed acceptance explicitly. It never retries dispatch.

The separate `elevenid.installer-acceptance/v2` contract has five startup cases
and 37 full cases. The full set preserves all 23 historical functional/negative
controls and adds real IP-page/browser routing, static-seal reboot, expired
OpenBao TLS recovery, independent HTTP-01, long-downtime credentials, successive
generations, crash publication, paused/sealed reboot, installed backup/restore,
independent root retirement and neighboring-state preservation.

Each case has distinct checks and named native evidence owners. Required
installation, Engine, operator, context, generation selection and clock bindings
cannot be replaced by a generic `passed` record. Five startup owners now have
the dedicated collector and closed adapters above. The other 32 cases remain
listed by `missing_writers(rootless-functional-recovery-8gib)`; full report
production remains blocked. The generic caller-supplied case-JSON emitter cannot
produce even a startup report. Detached official-Bao proofs, synthetic fixtures,
self-hashed JSON and an incomplete checkpoint cannot stand in for the installed
exercise or its protected owner outputs.

The promotion validator recognizes the separate schema but requires the full
profile and real installed proof owners. Startup reports cannot promote. The
v1 report limits, original 23 cases, historical 32 GiB policy and existing signed
publication/provenance gates are unchanged. No release, channel or AWS deployment
was published or qualified by these source and fixture tests.

## Published guest acquisition component

The signed controller runner can additionally use
`--observe-published-acquisition` for an original **published** rootless candidate
invocation. The flag is opt-in on `scripts/installer_acceptance_runner.py`; it
requires the original signed dispatch to return and its original workflow and
grant to remain active. It does not dispatch, retry, download again or extend the
grant. Staged candidates are refused before guest action.

Run the collector from the protected Git checkout at the exact signed harness
source, with the complete source closure required by `HarnessSources`. An
extracted selfhost bundle does not supply that protected harness environment.

The controller invokes the exact signed bootstrap operator's
`published-acquisition-observe --install-dir <original-installation>
--observation-id <fresh-uuid> --challenge <fresh-hex>` command. The native owner
is executed through the source-pinned guest bootstrap's explicit read-only mode.
That mode hashes and rebinds an open operator descriptor, then executes that
descriptor without reopening its pathname. It skips the normal bootstrap,
permission changes, download and install path. The native owner
uses the fixed dispatch directory for that account and installation. It rebinds
the retained `AcceptanceOnly` scope, the original bootstrap records, all 15
native download receipts and the corresponding input bytes. Bootstrap inventory
and executable bytes and sidecars are checked separately. Held descriptors,
private ownership, inode and parent identities, link counts and metadata prevent
replaced or changed inputs from becoming evidence. Only public identities,
hashes and bounded records are exported; credentials are not read into this
component.

New native acquisitions write a version 2 completion with the exact intent hash
and actual start/completion times. Historical version 1 completion records remain
historical and cannot produce this observation. Partial or uncertain acquisitions
retain their existing intent and bytes; no completion is inferred and no replay
is authorized.

The controller validates the fresh challenge, original source/operator/build and
workflow attempts, target guest/disk/engine/installation, unexpired grant, and
every receipt against its independently verified candidate files. It retains
`installer-published-acquisition-observation.json` exclusively under private file
custody. A repeated output name is refused. Without the separate startup observer,
the runner still returns an incomplete checkpoint and its existing incomplete
exit status; this additional file is a component observation only.

This feature advances the published `anonymous-download` evidence owner. It does
not establish staged anonymous acquisition, add a sixth startup case, change the
full 37-case profile, mark a global writer implemented, grant `Ready`, create
accepted admission or authorize a retained operator upgrade. Source and synthetic
public-fixture tests do not demonstrate a live guest download. That result needs
the actual freshly signed published invocation and its protected owner output.
