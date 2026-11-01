# Recurring public generation maintenance

The installation lifecycle calls one generation owner under the existing
installation lock. That owner coordinates public certificate renewal and
workload credential refresh, publishes immutable successor directories, and
retains enough native Compose evidence to inspect an interrupted replacement.
This implementation is still awaiting complete installed release qualification.

## Independent schedules

The selected public certificate has its own persisted ARI or lifetime fallback
schedule. A due decision authorizes one installation-bound issuance permit.
The permit binds the prior candidate, configuration, selected generation, and
exact historical schedule receipt. Later ARI updates do not revoke an already
recorded due decision. A known pending order keeps the same account and CSR.

A certainly invalid or expired known order or authorization can authorize a
later cycle after a retained cooldown. The terminal record must identify the
exact reason and order, preserve the server's retry lower bound, and confirm
that the old challenge was withdrawn. The cooldown begins at five minutes and
increases to six hours; a longer server deadline remains binding. The next
permit retains the exact terminal receipt and eligibility time. Legacy terminal
records without that evidence, account failures, rejected certificates and
unknown order outcomes remain explicit holds.

Workload refresh uses a separate conservative 30-minute interval from the
generation's credential observation. The producer validates all fresh workload
tokens with at least one hour remaining; the interval leaves time for the
bounded maintenance operation. The ingress token's possibly longer observed
lifetime does not prove an equally long lifetime for every other workload.

When workload refresh is due and the current public chain remains valid, the
owner can publish a token-only successor before optional ACME work. The public
chain and enrollment provenance remain identical. A CA timeout or failure to
refresh the separate account-signing credential therefore cannot prevent that
already-due workload refresh. Integrity or configuration failures remain errors.
A permit may continue through same-certificate descendants, but cannot move to
a different certificate or retained key.

A newly issued certificate must differ from its predecessor and extend the
actual expiry. It must still have the required activation margin. Changing an
order URL or serial while returning the old certificate lifetime does not
constitute a renewal. Staging candidates cannot enter this production owner.

## Immutable transaction

Each sequence retains the following work and evidence:

1. A generation intent binds the prior selected generation, original install
   configuration, current native session, public ingress plan, and hashes of
   the scoped identity and source credentials.
2. `generation-work/<sequence>` holds private identity inputs, a read-only
   source view and the fixed producer's output transfer. It does not change the
   selected files in place.
3. A native create intent precedes helper replacement. Reconciliation accepts
   only the exact approved helper image, model, mounts, ownership, network and
   prior resource census. A matching replacement without that retained intent
   is refused.
4. The fixed producer runs once. Native create, start and completion evidence
   binds its exact container. The host verifies the complete 42-file public
   candidate, completed scoped enrollment, certificate and credential metadata.
5. The generation publisher writes an immutable directory under
   `application-generations/<20-digit-sequence>-<binding-sha256>`. An interrupted
   file copy resumes only from an exact admitted partial or completed temporary
   file. Published files are never overwritten.
6. The owner derives and checks the new native Compose model. Only runtime
   services whose generation bindings change may be replaced. The selection
   compares each service's referenced secret and config declarations as well
   as its native service hash: Compose can leave that hash unchanged when a
   referenced credential file path changes. Pending activation and completed
   receipt validation enforce the same required consumers. OpenBao, its
   readiness watcher, HTTP-01, setup jobs, persistent volumes, and the owned
   network retain their identities. Creation, startup, and a complete native
   checkpoint precede selection.
7. The private `evidence/application-generation-current.json` selector changes
   atomically after those records validate. Initial publication refuses any
   preexisting selector; subsequent publication checks the predecessor's bytes
   and inode, exchanges the exact files, and checks both sides of the exchange.
   The evidence directory and installation bindings are checked before and
   after publication. An uncertain result poisons the current writer and keeps
   its lock held until it exits.

The original generation and completed predecessors remain available for
inspection and qualification of recovery material. Retention alone does not
establish an automatic rollback procedure or a verified backup. No automatic
generation pruning is implemented.

## Stale completed attempts

Selected generation sequence numbers remain contiguous. A completed producer
whose credential admission deadline elapsed, or whose public certificate
expired before selection, can be superseded by an immutable attempt within the
same next sequence. Attempt zero
keeps the original record names and serialized fields. Later attempts use
`generation-<sequence>-attempt-<attempt>-<kind>.json` with both numbers padded to
20 digits, and a separate `generation-work/<sequence>/attempt-<attempt>` directory.
The selector, selection receipt, binding, ingress plan and native operations all
identify the same attempt. The next selected generation also pins its parent's
chosen attempt. Historical validation checks every supersession link.

Supersession first requires a certainly successful, unrestarted helper and its
complete admitted output. Certificate integrity and clock consistency are
checked separately from expiry. A failed, running or unknown helper does not
grant a new minting attempt. In particular, an ambiguous retained start intent
cannot be bypassed by allocating another attempt.

A durable supersession intent precedes native changes. If runtime replacement
had not begun, the serving selected census is preserved. If replacement was
interrupted, only its already authorized consumer footprint is stopped and
converged to the exact stale model with create-only commands. Those containers
are not started. OpenBao, readiness, HTTP-01, setup jobs, networks and persistent
volumes retain their identities. A separate baseline receipt records this
factual census without claiming healthy activation or changing the selector.

That authenticated baseline authorizes at most one fresh producer attempt per
recovery invocation. Existing scoped renewal credentials remain the minting
authority. A still-admissible public leaf is reused; otherwise certificate
recovery enters the same retained due decision, account, CSR, known order and
terminal cooldown policy as ordinary maintenance. The baseline is not presented
as the selected application session. Losing a response resumes the same
recorded attempt and order. Workload freshness and actual certificate validity
are rechecked before every runtime create, start and selector publication.

Pause, stop and security seal remain stop-only even between baseline capture
and the next helper intent. They do not finish convergence or mint credentials.
Installed interruption testing is still required for the complete runtime and
CA path; local receipt tests do not establish arbitrary-duration availability.

## Restart and deliberate stop

An incomplete replacement may contain a mixture of retained and newly created
container IDs. The generation owner authenticates that intermediate state
before ordinary doctor or health admission. It first starts the exact retained
OpenBao, readiness and HTTP-01 containers as necessary and restores OpenBao TCP
TLS through scoped local recovery. It never replays initial keys, policies,
AppRoles, initialization or unsealing setup.

New or missing IDs require a preceding native create intent for the specific
role. Neighboring resources, unexpected containers, changed setup execution,
different models and storage adoption are refused. Completed producer evidence
and known native results are reused; an unknown result cannot be treated as a
fresh transaction.

Supported stop, pause, shutdown and security-seal operations use the same
intermediate resource admission to stop the owned runtime. They do not start a
helper, mint credentials, finish an activation or change the selector. The
durable lifecycle intent controls whether later boot and timer invocations may
resume it. Only explicit resume clears a deliberate security seal.

An unfinished initial-root retirement excludes new generation mutation.
Conversely, initial-root retirement cannot begin while generation or relevant
issuance work is pending. Lifecycle recovery restores local TLS, resumes an
already-authorized root-retirement operation, then performs ordinary generation
maintenance. It does not initiate retirement merely because a timer ran.

## Status and remaining holds

Lifecycle status exposes the selected sequence, attempt and binding, public
certificate expiry and renewal deadline, credential refresh deadline, pending
ACME stage, retry deadline, pending generation attempt, last successful
activation and first blocking dependency.
Read-only status does not contact the CA, sign, renew, recreate containers or
select a generation. Neither successful local maintenance nor a status report
grants installation readiness.

The following limits still require implementation or installed qualification:

- A lost new-order response without a retained order URL remains an explicit
  reconciliation hold. Reboot does not authorize a duplicate CA order.
- Before application ownership begins, a positively terminal known order may
  receive a distinct initial-installation retry permit after the original
  preparation, account, key and CSR lineage, confirmed challenge withdrawal,
  and durable cooldown are revalidated. Unknown outcomes, legacy untyped
  terminal records and selected-generation/lifecycle lineage remain held.
- A retained helper start intent whose container still appears never started
  remains an uncertainty hold. The owner does not replay that setup operation
  based solely on the container's current state.
- A crash after a public plan is retained but before its helper intent is
  recorded needs a separate unused-preparation supersession boundary if that
  plan later expires. It must not manufacture a successful helper receipt or
  overwrite the immutable plan.
- Recurring private-CA generation replacement is not yet connected to this
  public-generation transaction. It reports a specific hold when its
  conservative refresh deadline is reached. Imported foundations retain their
  customer-managed credential responsibility.
- The exact shipped image, rootless UID mapping, native Docker daemon restart,
  host reboot without login, real CA orders, public browser trust, authenticated
  journey and backup/restore still need installed evidence.
- Signed acceptance-only execution and ordinary completed-install admission
  remain gated. Candidate startup receipts remain in Provisioning and cannot
  claim Ready.

Component tests exercise real filesystem publication and inode replacement,
complete historical certificate lineage, actual native observer logic over
controlled CLI fixtures, and real nonroot preparation ownership. They do not
substitute for a running customer deployment.

The contracts CI lane also runs 14 explicitly named permission-sensitive
preparation and canary fixtures as an ordinary UID/GID with no capabilities and
`no_new_privs`, through `scripts/ci/qualify-installer-recovery-fixtures.sh`.
Every selected case must report a real pass. This is component ownership and
filesystem coverage, not live Docker, public CA or host-reboot qualification.

Changing the immutable secret-directory path changes native service bindings
even when some individual file bytes are unchanged. A rotation may therefore
recreate several consumers, including services with persistent storage, while
preserving their image and storage identities. This work does not promise
zero-downtime token reload. Installed recovery and load qualification must
measure the resulting interruptions and reconnection behavior.
