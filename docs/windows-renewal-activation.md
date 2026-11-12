# Windows candidate credential renewal adapter

`scripts/selfhost_windows_renewal.py` implements an isolated candidate transaction
using the existing Compose, rootless-migration, readiness and secret-mount owners.
The POSIX activator's platform/project checks are unchanged. This is a library;
there is no operator CLI, unattended task, production admission or reboot claim.
Signed release verification and publication/cutover approvals remain separate.

The managed candidate must have the complete declared service closure. Both KMS
initializers remain absent and opt-in. Managed OpenBao, its unseal helper and the
successful completed TLS initializer remain unchanged. Only roles that mount
generation secrets are recreated, with `--no-deps --no-build --pull never`.
Images must be digest pinned, published ports must be loopback only, and active
tunnel connectors, host networking and privileged roles are refused. Writable
storage overlap with any other Compose consumer, including read-only consumers,
is refused. Known Docker/WSL Windows-drive spellings are resolved through real
Windows identities (including junction targets and ancestor identities). Only
default-root local Docker volumes without driver options have a native volume
identity, including legacy inspect records whose Source is the volume name. A bind
of the exact volume root shares that identity. Native bind subpaths require fresh
kernel mount metadata from a trusted network-disabled helper sharing the existing
container's verified private/default PID namespace. It reads only filtered declared
destinations and their mount ancestors from `/proc/1/mountinfo`, with no data
volumes mounted and no added capabilities. Exact container/start identity, unique
destinations, visible parent chains without ancestor overmounts, decoded normalized roots, a pinned Docker Desktop VM root prefix,
ext4 filesystem type and a device number anchored by an ordinary named-volume
mount are required. Whole-volume classification is conservative. A same-project
zero-exit historical job with the exact same Source may reuse that live witness
as a metadata inference; this never authorizes restarting it. Unknown evidence,
inaccessible metadata, other filesystems or ambiguous mounts remain refused.

The caller supplies a private configuration with the exact retained Compose hash,
current/renewed env and generation paths, local Docker pipe/engine identity and
the already release-verified Linux operator identity. The transport rechecks its
digest and embedded source/tag identity while holding the NTFS binary and CA.
The scoped renewal control volume is mounted read-only. Native authority,
generation, orphan token, certificate/key/chain and lifetime checks are mandatory.
Both native mirrors must match the held Windows bytes exactly. Native checks then
use private mode0700/0600 snapshots materialized from those held bytes in isolated
tmpfs, so later changes to shared staging mirrors cannot change the checked data.

`selfhost_windows_renewal_native.export_generation(config, mirror)` provides the
read-only byte transport needed by the recurring producer/export path. The caller
holds the existing selected-generation lease and supplies its retained transaction
configuration and a normalized generation-directory URI below `/control`.
The adapter holds and hashes the Compose model and derives the exact inventory
from its secret declarations. It checks the existing project control volume,
then uses the pinned helper with network disabled and the volume mounted read-only.
Its Docker log driver is disabled so private chunks are not retained as daemon logs.
It neither mounts the Bao/database volumes nor exports enrollment/session files.

The helper checks private root/file modes, root ownership, regular single-link
files, no-follow opens and stable file identities. Data must be bounded UTF-8,
with empty files preserved. Held no-follow ancestor directory descriptors anchor
all relative file opens; all files stay open through the final identity and
namespace rechecks. Its manifest and each 12,000-byte chunk bind the same
whole-payload hash. Responses stay below the existing owned runner's bounded
output tail; the Windows caller checks exact indices, lengths, inventory and the
final payload hash before returning any byte map. The limit is 512 files of at
most64KiB each and8MiB for the complete encoded payload. A ten-minute fetch budget
is checked again after final decoding and held-input exit. Engine inspection and
the owned runner's separate bounded cleanup remain existing dependencies; this
is not a newly qualified hard whole-call or unattended timing guarantee. Failed
owned-process failures become fresh fixed-message uncertainty exceptions carrying
only the process-cleanup flag and empty tails; their original private chunk frames
and exception chains do not propagate. Parser/UTF-8 failures likewise become a
fixed refusal without retaining private exception payloads.

Export returns private bytes to its caller, never host stdout. It writes no
Windows files, mints no credentials, selects no generation and grants no native
admission. A producer must retain its durable attempt evidence, materialize the
result under the existing private Windows input owner, and pass the unchanged
native generation/token/certificate checks before registered activation. This
transport alone does not implement producer scheduling or expired-leaf recovery.

The private project lock and output files must already exist. The lock is named
`.<project>.renewal.lock` beside the generation directories. `intent`, `result`,
`new_log` and `rollback_log` must be distinct empty private files in one separate
output directory. The transaction does not create files, weaken ACLs, overwrite
a prior receipt or modify either generation/env file. Existing intent makes an
ambiguous or interrupted transaction an operator recovery case, not a blind retry.

The adapter holds the lock, retained Compose/env files and both complete secret
generations through native checks, durable intent, recreation and mount/readiness
verification. Writable Windows data-source names are also held while their normal
application writes remain permitted. Data mounts and image identities must remain
unchanged. Running roles must match retained Compose config hashes; the preserved
zero-exit historical TLS initializer requires an exact container/image/hash receipt.
Ancestor names cannot be replaced while held. Protected candidate container
identities, state, restarts and mounts must remain unchanged. The complete
candidate role closure, data mounts and image identities remain fixed; before
intent, every candidate observation must still match the initial census.

Independent Docker projects may create, remove or restart containers during
activation. Immediately before intent, before each new or rollback layer, and
during final verification, the Windows adapter collects the entire container and
volume inventory, refreshes native kernel mount witnesses and Windows path
identities, and proves writable candidate storage disjoint from all foreign
mounts, including read-only consumers and containers without Compose labels.
A surviving foreign ID cannot change its creation identity, image, complete mount
metadata or project/service identity. A closing volume inventory and container
census must match the proof inputs; candidate drift is never retried. Foreign
inventory drift allows at most three read-only attempts within one fixed
three-minute acceptance budget. Full Windows/WSL mount witnesses and NTFS identity
passes can legitimately exceed one minute on shared engines. Opening and closing
inventories, fresh witnesses, identity checks and late-result rejection remain
mandatory; no proof is cached across writes. Container inspections use batches of
at most256 validated hexadecimal IDs, keeping even full-ID Windows commands below
17KiB. The independent ten-minute activation-phase budget remains unchanged.
These are acceptance deadlines, not a hard process wall-time guarantee. No
workload mutation is retried by this check.

Accepted context changes add proof hashes, counts and bounded ID samples to the
private activation result. Recent proof samples have an aggregate eight-KiB bound;
the total count and hash chain cover all accepted changes without exhausting the
existing result size limit. Unknown storage, missing witnesses, overlap, candidate
drift or exhausted observation budget forbids further writes, including automatic
rollback. Diagnostic-write failure preserves that classification. Docker has no
cross-client transaction lock: this qualification cannot prevent another client
from changing the engine after its closing census.

Selected-generation native admission, read-only configuration checks, staging and
materialized-stage reconciliation use the same context proof with no changing
candidate roles. Every candidate observation must therefore stay fixed across
those operations. Staging rechecks before allocating its operation and before
credential production. Finalization still requires all producer helper IDs,
names and cycle labels absent, including helpers appearing during native proof;
a disjoint helper is not treated as unrelated activity. Existing phase receipts,
guard transfer, held-input exits and atomic publication remain mandatory.
Existing-ID start/recovery, model repair and journal continuation retain their
strict census policy. These changes do not qualify unattended recovery or
periodic renewal without actual runtime tests.

An ordinary failure in a freshly qualified context
recreates the prior generation and verifies it. Failure of rollback, held-input
exit checks or final receipt writing preserves the intent and requires recovery.
An activation result is written only after the held-input exit checks pass.

Qualification must include real NTFS locking and sharing, native preflights,
isolated Docker activation/rollback, then the owned application's authentication
and KMS journeys. A successful return establishes candidate readiness and mounts;
it does not establish production release admission, credential retirement,
continuous availability or automatic engine/logon/host recovery.

Returned Compose invocations that leave a role in `created`, paused or another
nonprogressing state fail promptly rather than polling for a first start that
Docker will not perform. A mutating CLI timeout is an uncertain outcome: preserve
its bounded diagnostics and intent, and do not launch automatic rollback. The
Windows mutation runner uses an unnamed noninheritable kill-on-close Job Object
with no breakaway flags. Its isolated Python helper waits for an input gate before
launching Docker; job assignment precedes every command byte. Output drains into
bounded tails. Normal completion requires zero active job processes and bounded
reader completion. Timeout, surviving descendants or containment failure preserve
uncertainty even after owned-process termination. Synthetic Windows tests cover
nonzero exits, large output, gate-assignment failure, timeouts and surviving
grandchildren. Dependency-layer and real Docker containment qualification remain
blockers to exposing a CLI or unattended lifecycle. Job termination does not prove
Docker daemon operation quiescence. See [Microsoft Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

Before intent, the entire active dependency graph is validated for normalized
conditions, required closure, health/completion contracts and cycles. Selected
roles are recreated in dependency layers. Each role appears in one invocation;
the preserved foundation and completed layers must be ready before advancing.
Ordering is projected from the full active graph, preserving paths through
unchanged roles. Dependency restart cascades are refused before intent.
A transient health failure therefore cannot leave all downstream layers created
by an earlier bulk invocation. Readiness/completion is refused after the600-second
phase deadline, including when a status read or receipt flush crosses it. The
shared read-only Compose status transport has its separate60-second inspection
timeout; this is not a hard600-second process wall-clock guarantee.

The caller must preallocate `step_receipts`, one object per computed layer, with
exact keys `new_started`, `new_completed`, `rollback_started`, `rollback_completed`.
Each value names a distinct existing empty private file beside the four main
outputs. The durable intent retains the layer plan and receipt paths. A started
receipt is flushed before each mutating invocation, and a completed receipt only
after readiness. Rollback uses the same validated ordering with the old env.
Never replay an interrupted layer from these records without reconciliation.

The generation-selection owner can call `preflight_current` for a read-only
current-custody and minimum-one-hour lifetime check. It verifies both native
mirrors against held bytes, materializes private snapshots and delegates scoped
authority, orphan-token and certificate/key/chain/lifetime decisions to the signed
native operator. This separate entry point does not verify a changing-generation
transition. `preflight` still requires distinct mirrors and changed renewable
inputs, including the native generation verifier.

Native requests now use the existing owned Win32 job runner's bounded binary
stdin pipe. Private payloads are absent from command arguments. Command arguments,
private input, encoded gate request and output tails each have separate bounds;
every owned command inherits a private pipe or DEVNULL rather than the gate stdin.
Durable selection/reconciliation and recovery integration remain separate work.

`selfhost_windows_selection.py` adds a candidate selection journal beside its
generations, at `.<project>.generation-selection`. It uses the same existing
exclusive project lock, private NTFS proofs and immutable model/engine/operator
binding. Records are append-only, sequence/parent-linked and bounded; secret
values are never stored in them. Original transaction configs, intents and results
remain unchanged.

The library exposes these bounded operations:

- `adopt(config_path)` proves an existing successful activation, then selects its
  renewed inputs. Interrupted initial metadata adoption can resume after proof.
- `prepare(next_config_path)` proves the selected current inputs and writes the
  pending intent before activation. An initialized owner makes unregistered or
  changed activation requests fail before mutation.
- `complete(config_path)` verifies the durable activation/rollback result and
  current runtime before appending selection. `reconcile=True` never replays
  Docker: an empty original intent permits only the unchanged old selection;
  otherwise the terminal phase needs every durable started/completed boundary.
  A distinct pre-command case permits only the old selection when the full
  retained intent/model/layer/path closure is valid, every phase receipt is empty,
  the rollback log is empty, and the new log is exactly the empty-tail diagnostic
  header. The writer flushes each started receipt before invoking Docker, so this
  case cannot have reached a workload command. Original container IDs, images and
  data mounts must still match the intent both before and after fresh native,
  readiness and data proof. The project lock excludes a concurrent writer and all
  original records stay held and unchanged. A single nonempty started/completed
  marker uses the existing terminal-phase rules; no partial layer is replayed.
  Incomplete or uncertain commands remain operator recovery cases even when a
  snapshot looks healthy. Original empty result files stay empty.
- `status(config_path)` reports journal state, not live readiness. Pending,
  malformed, partial or extra records never silently fall back to older inputs.
- `selected_inputs(config_path)` holds the project lock, selected metadata,
  model/env and complete generations for a recovery consumer. Its immutable lease
  exposes paths and a current-proof callback, no secret bytes; the callback refuses
  use after the context closes.

Read-only proofs may use a fresh scoped authority token file without rewriting
historical configs. Native authority/lifetime decisions remain mandatory. Existing
Linux generation owners and Windows Compose/native validators are reused; this
library starts no services and installs no task. PowerShell startup integration,
producer scheduling, expired-credential recovery and engine/logon/host-reboot
qualification remain required before unattended operation. Process-interruption
controls do not claim power-loss durability qualification.

The legacy Windows recovery wrapper refuses a default-active `openbao-tls-init`
in either its product or OpenBao Compose inventory before any service mutation,
including in check-only mode. Combined `up` and dependency traversal can replay
that completed job. A retained managed candidate therefore needs the selected-
generation recovery integration; passing paths to the legacy wrapper is unsafe.
Existing standalone shapes without that initializer retain their recovery path.

The selected-input lease now offers `recover_existing(output_dir, authority_file)`
as a library callback. It holds the same project lock, original receipts and
complete generations throughout recovery. The output directory must already be
empty/private and named `windows-recovery-*` beside the generations. Missing,
paused, invalid or failed completed jobs refuse before mutation. Only existing
IDs may start; completed migrations and the TLS initializer never start again.
Bao and its unseal helper start as a foundation group, then the native owner must
admit the selected credentials before application roles start in dependency order.
The full final readiness, storage, identity and native proof remains mandatory.

A shared recovery marker blocks renewal, selection changes and new recovery after
an interrupted/uncertain attempt. No failure path clears it or rolls back daemon
operations. Preserve the marker, attempt receipts and generations for operator
reconciliation. The callback returns a provisional result; only a clean exit from
the entire selected-input context publishes success and clears the exact marker.
Receipt tampering, a caller exception or a failed held-input exit leaves the marker.
The marker remains authoritative even if a result file was written before a final
publication-lock exit failure. Never interpret that result independently. Admission
uses no-follow namespace checks: dangling marker/selection links and metadata errors
must not fall back to an installation without an owner.
The existing PowerShell wrapper can dispatch the managed CLI with an explicitly
supplied trusted interpreter; see [managed configuration](windows-compose-recovery.md#retained-managed-openbao-candidate).
It installs no scheduled task and never automatically removes an uncertain marker.
Producer scheduling and broader interruption recovery remain required before
unattended recovery is qualified.

An explicitly coordinated planned stop may retain a separate
`.<project>.recovery-preparation.json` marker. It blocks every new admission just
like the recovery marker, including dangling entries. Only the already-held lease
can call `recover_existing(..., preparation_sha256=...)` to hand it off. The
private completion receipt must bind the exact preparation hash, returned stop
CLI, all stopped IDs and retained completed-job IDs. Model/engine/selection/data
identity, actual stopped state and protected observations are rechecked. Unknown,
incomplete, mismatched or changed stop records never authorize startup.

The owner flushes the normal recovery intent and marker before unlinking the
preparation marker. Both exist during transfer; interruption leaves at least one
authoritative marker. The original preparation and completion evidence remains
linked by hashes in the recovery intent. This supports controlled planned-stop
handoff; it does not automatically reconcile an uncertain stop or interrupted start.

`reconcile_existing(config_path, authority_file=...)` is a separate read-only
terminal operation. Use it only after verifying the original recovery owner has
finished. It requires the exact guarded intent, registered selection, model-derived
layers, current IDs, all matching started/completed command boundaries, and fresh
native readiness/custody/lifetime proof. Missing or uncertain boundaries refuse
even when containers appear healthy. A preparation marker also refuses this path.
No workload command is issued. Original result bytes remain unchanged, including
an empty original result; a separate deterministic `reconciliation.json` records
the current proof. All original receipts and directory membership are rechecked
before the marker clears, after lease and publication-lock exit checks. A prior
valid reconciliation record can be retained during a fresh proof after publication
interruption. This does not resume an unfinished start, prepared stop or expired
generation, and it is not automatic logon recovery.

`renew_once(config_path, logical_project)` performs one explicit online candidate
renewal through the existing selected-input lease, scoped AppRole authority,
signed native producers, private export, activation and selection journal. The
logical TLS namespace must match the existing enrollment. This API requires an
already healthy, unexpired generation; it does not install a timer, qualify
expired-credential recovery or admit images for production.

Before minting, the owner reserves a private `windows-renewal-<uuid>` operation
directory, separate generation directory, exact next configuration and durable
`.<project>.renewal-staging.json` guard. Phase receipts bind named helper IDs,
images and the cycle. Helpers have logging disabled; only confirmed successful
helpers are removed, without volumes or force. Unknown helpers and failed phases
remain recorded. Keycloak responses, including partial timeout output, are
flushed to the private control volume before interpreting success or refusal.

All held-input and publication checks must finish before a final Windows
no-overwrite rename creates `publication.json`. A result file without this seal
is provisional and cannot authorize activation. Admission rechecks the seal,
all phase/helper relationships, exact inventory, native proof and current data.
The staging guard remains until a durable pending activation intent takes over;
an interrupted transfer therefore retains at least one admission blocker. Neither
another renewal nor recovery automatically clears an uncertain operation. Keep
its configuration, receipts, helper identities and old generations for operator
reconciliation. Known completed rollback is recorded through the existing
selection owner; unknown activation is never replayed.

## Explicit signed product transition

Image adoption is distinct from credential rotation. From accepted trusted
tooling that includes the product journal reader, run one explicit attempt:

```powershell
python scripts/selfhost_windows_product_deploy.py `
  --config C:/Marty/private/activation/config.private.json `
  --assets C:/Marty/private/verified-composition `
  --gh C:/Marty/private/tools/gh.exe `
  --cosign C:/Marty/private/tools/cosign.exe `
  --registry-config C:/Marty/private/registry/config.json
```

The assets directory must contain the original six composition subjects. The
existing composition verifier authenticates outer and embedded subjects and OCI
evidence again. Images must already be cached by their exact digest, on
linux/amd64. This command never pulls images or changes registry credentials.
PostgreSQL and Redis image pins stay fixed; new implicit volume targets refuse.
All writable storage and credentials remain bound to the selected installation.
Only the four recognized read-only local UI code mounts may be replaced by the
authenticated application image. Other ports, networks and configuration stay
unchanged. Initializers and the historical TLS initialization container never run.

The existing Windows process owner recreates only changed roles in dependency
order. Complete intent/guard records precede fresh scoped AppRole authority and
Compose writes. Native custody is proved before/after; schema/ledger and provider
observations must remain equal. This narrow path does not admit a database-format
upgrade, changed migration ledger or reversible database rollback. An error or
uncertain outcome leaves the guard and receipts; never retry the deployment to
repair it. A returned callback result is provisional until the entire selected
lease exits and the new product selection is published.

For every candidate source, an additional read-only check requires the reviewed
three-migration baseline before any product
intent, fresh authority or recreation. Ledger/relation presence is only an
early negative check: it grants no schema-transition authority and does not
replace the unchanged catalog/ledger, custody and runtime proofs. A populated
installation missing those migrations still needs a separately qualified exact
schema transition; do not preapply SQL or relax the equality check to proceed.
The earlier source-specific check was insufficient: descendants carry the same
migrations. A new SHA cannot skip this check, and an older candidate cannot use
this image-only path against a pre-baseline database. This is a minimum refusal
gate, not a promise that a future source has no additional migrations.

If execution completed but metadata publication was interrupted, an operator may
use `--config ... --reconcile --authority-file /control/recovery-session-<uuid>/token`
with existing valid scoped authority. This validates every retained phase and
fresh native/schema/provider/runtime proof before completing derived metadata.
It never repeats authentication, Compose, migrations or credential minting.
Missing completion boundaries, expired authority, unexpected files and live
drift refuse. Preserve incomplete attempts for explicit operator recovery.

The product successor retains the credential identity and cumulative credential
generation; later ordinary renewal and recovery resolve its new model binding.
Install the accepted product-aware operator source in every recovery consumer
before adoption. Older operator code cannot read the product records. No task,
logon hook, release publication, public route or reboot is installed or performed
by this command. Installed-runtime/recovery and end-to-end application acceptance
remain separate requirements.

## Expired current proof before credential production

The existing Python recovery owner exposes explicit `--expired-current` phases
for one narrow stopped renewal: authority completed, current proof started but
not completed, every producer/activation receipt empty. Inspection preserves the
failed attempt and its guard. It does not admit retry, expired TLS, or rollback.

Use `scripts/selfhost_windows_recovery.py --configuration <managed.json>` with:

| Phase | Additional arguments | Effect |
| --- | --- | --- |
| `--expired-current inspect` | none | Read-only failed-attempt evidence |
| `--expired-current stage` | `--attempt-directory <empty-private-windows-renewal-uuid> --logical-project <marty-selfhost-name>` | Guarded fresh credentials through existing producers |
| `--expired-current publish` | `--attempt-directory <attempt>` | Fresh candidate proof and metadata publication |
| `--expired-current activate` | `--attempt-directory <attempt>` | Recreate the existing owned dependency layers once; no expired rollback |
| `--expired-current select` | `--attempt-directory <attempt> --source-journal <predecessor>` | Fresh running-generation proof, sealed successor selection; guards retained |
| `--expired-current finalize` | `--attempt-directory <attempt> --source-journal <predecessor>` | Repeat complete-chain/operator/current proof, archive exact guards without deleting evidence |

These explicit phases cannot be combined with ordinary renewal, check-only or
engine-wait arguments. They do not install a task or alter public routing.
The pinned operator must implement `operator recovery-contract`. When a separately
published successor is needed, supply `--operator-successor-file <private.json>`
on each mutation phase. That file identifies `assets`, `expected` (source SHA,
release tag, run ID/attempt, binary SHA256), `gh`, `cosign`, and trusted
`verifier_sha256` pins. The owner repeats release/run, signature/provenance,
binary identity and capability verification; local metadata is insufficient.
Historical runtime, model, images, CA and storage bindings stay unchanged.

The next ordinary renewal uses a newly staged configuration with the selected
operator. Resolution replays the complete stored-owner chain before admitting
that caller identity. Older entrypoints must match a recorded historical
configuration; newly staged transactions must match the selected owner. Neither
an uncommitted recovery marker nor a stale operator grants mutation authority.

Never replay an interrupted producer or activation. Preserve its receipts for
operator reconciliation. Selection can complete missing or exactly empty target
seed files after fresh proof; partial/empty source intent or decision files
remain refused. Finalization can resume after one guard was archived, repeating
all proofs and checking the exact archived bytes. A failed check after a rename
is an uncertain outcome, not an undone rename. Normal later operations still
perform their own native current admission. Local tests or a signed binary alone
do not replace protected source integration and release/deployment approval.


The opt-in `tests/test_windows_product_native_startup.py` regression exercises
real Credential Template and Trust Profile startup plus the Issuance migration
CLI against fresh synthetic tmpfs PostgreSQL. It checks both the expected
membership-only refusal after one old startup and limited witness agreement
after old startup reconciliation; neither grants full retained-data or deployment
admission. It uses an isolated internal network, no host ports/binds, and
identity-checked cleanup, including uncertain creation acknowledgements.

Set `MARTY_RUN_PRODUCT_NATIVE_STARTUP_TEST=1`,
`MARTY_PRODUCT_SCHEMA_TEST_ENGINE_ID`, `MARTY_PRODUCT_NATIVE_TEST_CONTEXT`, and
the `MARTY_PRODUCT_NATIVE_TEST_OLD_IMAGE`, `NEW_IMAGE`, `OLD_SOURCE`, and
`NEW_SOURCE` variables (each with the `MARTY_PRODUCT_NATIVE_TEST_` prefix).
Images must already be cached immutable services references; source values must
match their revision labels. Run only with disposable test state. This test
never selects or deploys those images in production.

The fixture also starts the old and new Organization servers against its own
Redis instance, using the cached immutable Redis pin from
`release/external-images.json`. Redis uses only tmpfs storage on the same
internal test network. A reserved synthetic administrator and an explicitly
asserted active synthetic member must survive startup. All eight exact default
system-role IDs retain their payloads; only their `updated_at` timestamps may
change, within the observed database-clock window. Other exercised table rows
remain in the full opaque comparison. This is retained synthetic data evidence,
not authenticated console or production transition admission.

Deployment Profile is also started with both native images. Its exact default
tenant/profile row must retain every payload field except `updated_at`, bounded
by database time. Flow uses the old native `migrate` command and the new native
`verify-owned-schema` command; this exercises retained schema and tenant checks,
not Flow's full provider startup. Both new binaries must reject a different
configured tenant without changing any retained rows in the exercised schemas.
The fixture includes Flow and Deployment tables in its opaque row inventory,
and receipts record source revisions, image references/config IDs, engine ID
and the executed fixture hash. These remain synthetic execution evidence,
without production or release admission.

The isolated PostgreSQL fixture requires a per-attempt synthetic password;
ordinary native clients receive a correctly encoded URI. New Issuance instead
receives only `MARTY_DB_PASSWORD_FILE` and `DATABASE_URL_TEMPLATE`, then runs
`/bin/sh` with `set -e`, the image's `/app/load-secrets-env.sh`, and an explicit
`exec /usr/local/bin/marty-issuance-service migrate`. Its normal service
entrypoint does not forward the migration argument. The synthetic password
contains reserved URI bytes to check the loader's encoding. Old Issuance keeps
the direct encoded URI: the historical loader does not encode those bytes and
fails this input. This qualifies the new native command and secret transport;
it does not qualify Compose one-off ownership, durable migration receipts, or
the complete deployment transition.

The existing deploy module's `issuance_migration_command` now prepares that
fixed shell body through the existing `Docker.compose` binding. It accepts only
the native Issuance role, an immutable official services image, its supported
wrapper/default command, selected absolute env/Compose paths and an attempt
identifier. It overrides both entrypoint and command, disables dependency starts,
pulls, TTY and interactive input, and retains the named container for later
receipted ownership checks. The fixture executes the same shell constant; unit
tests verify command preparation and refusals. This constructor does not read or
authenticate the files, execute Compose, check helper identity, or grant any
authority. The complete schema owner must bind the matching verified model and
source, write durable intent before execution, and retain uncertain outcomes.

The opt-in real Compose lifecycle test deliberately substitutes `exit 0` for
the separately qualified native migration body. Even with `restart: always`
and a declared dependency, the named one-off must have restart policy `no`,
exit once and leave the dependency unstarted. It uses a new internal network,
tmpfs only, and no database, host ports, bind mounts or volumes. An fsynced
intent precedes creation; uncertain acknowledgements retain resources. Cleanup
rechecks exact container/image/project/service/nonce identity, removes only the
acknowledged helper, then verifies its owned network is empty before removal.
This is flags/lifecycle evidence, not end-to-end migration or product admission.

The product context can now qualify one acknowledged transient Issuance helper.
Preparation rechecks candidate role configuration hashes and the cached image,
then binds the resolved environment, selected mounts, networks and security
settings. Only the producer's definite full container ID may be acknowledged;
name-based adoption is refused. The exact fixed command, nonce label, image,
environment and storage must match before excluding that helper from the
ordinary workload role closure. Its observations still reach the inherited
foreign-storage checks. An explicit fresh completed/zero witness must precede
removal acknowledgement, which must be followed by absence. A generic
observation grants no cleanup phase. Creation/start identity, running PID and
terminal outcome are retained to reject same-CID manual restarts even when
Docker's restart counter stays zero. The helper observation digest is included
in its witness. Shape tests replace the full storage transport; they do not
qualify quiescence, journal receipts or a complete mutation owner. No production
call site invokes this helper support yet.

The existing deploy module also contains an internal, bounded helper producer.
It writes private creation intent before sending the one Compose command, accepts
only its definite full container ID, waits for that exact helper and retains the
same fresh inspection that proves a zero exit. The full inspection can contain
resolved secrets and stays in the private journal; the minimal completed receipt
binds its digest. Cleanup intent and a fresh completed proof precede normal
removal by ID. An uncertain create, wait, removal or failed receipt write never
causes retry, name adoption or error-path cleanup. The existing Windows owned
CLI containment applies to every mutation, with a fixed total command budget.
This component has no CLI or production call site: the full schema owner must
still supply its guarded, versioned journal, held inputs and writer quiescence.


`selfhost_windows_product_startup.py` adds a read-only timestamp witness for the
ten built-in wallets, four built-in delivery destinations and the configured
tenant's Marty issuer, eight UUIDv5 system roles and exact default deployment.
The v2 receipt requires all five cohorts and refuses the older three-cohort
receipt. Role IDs derive from the configured organization; roles must also have
that organization and `is_system=true`. The deployment must have both the exact
default ID and configured organization. It masks only those existing rows' `updated_at`, requires
exact row identities/counts and database-time bounds, and retains every other
physical field and customer row in the opaque comparison. The native fixture
also fingerprints all tables in its exercised schemas and tests customer-data
tampering. This remains evidence for the full startup transition, not permission
to run migrations or bypass product admission; the deployment owner does not
consume this fragment yet.

`retained_rows_snapshot` in the existing product probe now inventories all user
tables, partitions, materialized views and sequences in the application database.
One repeatable-read, read-only PostgreSQL transaction computes complete physical
row hashes and counts, returning no ordinary values. Composite SQL text under
canonical output settings preserves array bounds and raw JSON representation;
JSON conversion alone would lose those distinctions. It has no caller-controlled
exclusions and refuses foreign tables, large objects, custom column output
types, more than 256 relations, more than 2048
rows per relation, or incomplete/ambiguous output. The native fixture uses this
same probe for its complete retained-row comparison. This supplies inventory
evidence; it does not select permissible changes, cover other databases, stop
application writers, or admit a product transition. Sequence state is not MVCC;
the execution owner must qualify quiescence rather than infer it from transaction
isolation. The deployment owner still
needs to bind and validate the narrow migration witnesses with this inventory.

The schema probe has a separate v3 detailed form retaining every reviewed
ledger digest and its aggregate from the same database transaction. The existing
v2 snapshot and image-only journal keep their original shape. The membership
ledger witness is now v2: it uses the complete probe's canonical full-row order
and refuses old v1 receipts instead of reinterpreting their hashes. Its profile
comparison binds each of the three expected additions to the narrow before/after
witness, requires every other application ledger unchanged, and retains the
entire Keycloak and applicants catalog/ledger profiles. It checks inventory and
aggregate integrity. This ledger comparison does not qualify application
catalog changes, ordinary rows, writer quiescence or product/native admission.

`quiescence_snapshot` separately refuses any other PostgreSQL client session
in the cluster, including idle clients and connections to the default database,
as well as prepared transactions, configured subscriptions and replication
sessions. Logical apply, parallel and unknown extension backend types are
refused; only reviewed built-in maintenance types are exempt. Two fresh read-only
observations require a primary server and the exact database inventory. Only
counts, database names and clocks are returned. The enclosing owner must also
prove its runtime writer cohort remains stopped and repeat this check before
schema write boundaries. These observations do not block future external
connections, disconnect clients, authorize SQL or replace runtime ownership.
