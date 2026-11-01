# Signed rootless acceptance on an existing host

The signed acceptance entry can use an independently prepared Linux amd64 AWS
host through the existing pinned SSH controller path. It requires an already
running rootless Docker daemon for the exact nonroot installation user. It does
not require a nested VM, install packages, configure the daemon, or change host
network routing. The [optional disposable QEMU path](selfhost-disposable-rootless-vm.md)
is a separate producer of guest identity evidence.

This checkpoint connects authenticated hosting input, rootless storage admission,
controller observations and versioned evidence. It does **not** establish a real
signed installation, public browser success, reboot/restore qualification, release
admission, or normal `Ready` completion. The installed assertion writers described
below remain explicit blockers.

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
The acceptance path provisions with incomplete completion policy and does not
turn canary or setup success into `Ready`.

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

## Checkpoints, qualification and promotion

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
cannot be replaced by a generic `passed` record. **No installed case writer or
native proof adapter is registered yet.** `missing_writers(profile)` lists the
exact missing cases, and both report production and case admission refuse while
those owners are unavailable. Detached official-Bao proofs, synthetic fixtures,
self-hashed JSON, and an incomplete checkpoint cannot satisfy them. Implementing
an adapter requires its actual protected output reader and real installed
exercise; adding a name to the registry is not sufficient.

The promotion validator recognizes the separate schema but requires the full
profile and real installed proof owners. Startup reports cannot promote. The
v1 report limits, original 23 cases, historical 32 GiB policy and existing signed
publication/provenance gates are unchanged. No release, channel or AWS deployment
was published or qualified by these source and fixture tests.
