# Installation-owned ACME enrolment

`installer_acme::run_for_install` is the bounded initial-enrolment owner in
`marty-deployment-catalog`. It borrows the existing installer lock during
`Provisioning`, uses the maintained ACME client with a nonexportable OpenBao
account key, and returns an admitted certificate candidate. It does not advance
the installation phase or activate a certificate. The read-only ACME status
view reports retained evidence and explicitly leaves readiness, current
certificate freshness, public reachability and recovery qualification unproved.

## Caller contract

The caller supplies the exact installation directory, a
`BoundAcmeConfiguration`, independently retained account and ingress keys, an
admitted signed CSR, the bounded OpenBao HTTPS transport and an account
credential provider. The public entry point requires the live rootless
installation profile. Configuration, installation UUID, release identity,
runtime, environment, key references, public keys and CSR bytes are bound to the
existing journal before network work.

Configuration uses the selected Let's Encrypt environment and its exact
directory, the `shortlived` profile, explicit agreement to the observed terms
URL, the saved canonical DNS identity and optional IP landing identity. An
optional contact is forwarded only when explicitly supplied. No contact is
inferred or required in the account response. Production uses the certificate
owner's fixed public roots. Staging requires explicit test roots whose digest
is retained in the enrolment binding; staging admission remains marked as such.

The caller must obtain the original CSR with `installer_acme::retained_csr`
before asking OpenBao for another signature on a restart. The helper validates
the retained signature, exact identifiers, SPKI, DER bytes and metadata against
the current configuration and ingress key. Re-signing an identical template
can produce different DER and is not a substitute for retaining the CSR already
bound to an order. Account, CSR and edge TLS permissions remain independent.

The caller also creates `acme-http01` as an owner-controlled `0755` directory
beneath the private `0700` installation and mounts that directory read-only into
the responder. The worker does not create containers, publish ports or infer
public routing. Its publication contract is shared with the actual responder
through `marty-selfhost-identity::acme_http01`.

## Durable state and interrupted operations

The owner writes append-only private evidence through `LockedMaintenance`, not
through a second journal or independently acquired lock. The environment-specific
sequence starts at `acme-staging-000000.json` or
`acme-production-000000.json`. Each receipt retains its preceding digest, exact
binding and observed state. Sequence gaps, partial or linked records, changed
bindings, unexpected transitions and unsupported receipt shapes hold execution
before another CA request. Receipts are `0600`, bounded to 128 KiB each and 512
per order cycle. Cycle zero keeps the original filenames. Positive cycles use
`acme-<environment>-order-<20-digit-cycle>-<6-digit-sequence>.json` and retain
the exact predecessor, account/CSR/key/configuration, and an explicit typed
permit. Selected-generation renewal binds a completed candidate. Initial
replacement permits instead distinguish an expired candidate from a confirmed
initial terminal order; the latter can precede the installation's first
certificate. Their original-preparation authority cannot be used by selected
generation maintenance. An unknown `newOrder` outcome never permits a
replacement cycle.

Polling uses a separate, bounded `acme-poll-<environment>-<20-digit-cycle>.json`
checkpoint. It contains only timing and an exact immutable phase anchor. It
cannot supply an account URL, order status, CSR, challenge, certificate, or
terminal decision. Its current and complete `.next` files are validated against
the whole phase history; applicable delays are combined conservatively. Only a
real change of phase or authority can obsolete an older timing anchor. An
identical phase receipt or timing-only legacy receipt cannot erase a delay.
A one-time immutable required marker makes loss of the current checkpoint a
recovery hold, including when an older staged file survives. A complete
checkpoint left before marker completion is validated and the marker is
completed before further CA requests.

| Operation | Durable boundary | Recovery behavior |
| --- | --- | --- |
| Account registration | Account intent before the registration POST; account URL after success | A retained intent without a URL first uses the same key with `onlyReturnExisting`. A definite `accountDoesNotExist` response permits a later explicit registration attempt. |
| New order | Exact CSR/profile/identifiers and order intent before `newOrder`; URL and immutable order target after success | A known URL is restored. An unknown result without a URL holds without even a directory request. The worker never guesses that a lost response means no order exists. |
| Challenge publication | Exact public snapshot and previous digest before atomic replacement | A restart replays the same pending snapshot. It accepts the already-published matching file or its exact retained predecessor. |
| Challenge notification | Exact published authorization/challenge target and notification intent | The target is refreshed and checked before notification. Only a pending challenge receives the readiness POST; processing/valid observations do not trigger another POST. |
| Finalization | Finalization intent before sending the retained CSR DER | A known order is queried first. Processing/valid state proceeds without repeating finalization; a ready order can resend the exact retained CSR. |
| Candidate admission | Admitted full chain and its validation metadata before challenge withdrawal | A restart revalidates the retained chain and completes withdrawal. No active generation or installer `Ready` state is written. |
| Initial terminal order | Distinct initial authority, positive known-order terminal reason, observation time and cooldown, followed by confirmed withdrawal | While the original preparation is still pristine, a v2 initial permit binds the immediate terminal receipt and exact original account/key/CSR/configuration. A retained permit resumes the same cycle. An old untyped terminal record is not upgraded into retry authority. |

The fetched directory must still advertise the exact accepted terms URL and
selected profile before account registration or same-key recovery. Preparation
only fetches the directory. The explicit registration boundary rechecks that
same metadata, including when `onlyReturnExisting` is used.

Order identifiers, authorization URLs, finalize URL, profile and account remain
fixed. Active-order expiry cannot silently extend the retained operation
deadline. A valid order may report a different expiry; the worker validates the
timestamp and retains the original deadline while independently checking the
certificate's actual validity. RFC 8555 section 7.1.3 explicitly makes order
identifiers and authorizations immutable and does not impose the same rule on
expiry. A valid authorization may likewise report a new expiry after challenge
completion; that observation never changes the target of a readiness POST.
Authorization status is classified only after checking the exact identifier
and authorization URL. Terminal authorizations do not need `expires`. Pending
authorizations may omit it: the retained order deadline bounds them, and any
earlier authorization bound remains effective. Valid authorizations must supply
an expiry, as required by RFC 8555 section 7.1.4.

## Publication and retry behavior

The public file contains only identifier, token, key authorization and bounded
snapshot timestamps. Account URLs, credentials, CSR material and certificate
material stay out of that projection. Each write starts as a private `0600`
temporary file, becomes `0444`, is flushed, atomically renamed to `active.json`,
and is followed by a directory flush. Directory/file ownership, exact modes,
regular-file type and link count are checked. The responder can read the public
file as its nonroot UID through its read-only mount.

Before notification the worker re-fetches the selected authorization, verifies
the same identifier and live deadline, and compares challenge URL, token and
key authorization with the published record. A changed target is refused.
Publication lifetime cannot exceed the retained order/authorization deadline
or the responder's maximum lifetime. A terminal result or admitted candidate
withdraws challenges using an atomically published empty snapshot. Interrupted
withdrawal is replayable. Identical live projections are reused; a renewed
timestamp is published only when an extension is needed near the responder's
maximum lifetime, or when the actual authorized challenges/bounds change.

Retry state records the failure count and one chosen next-attempt timestamp.
Backoff is bounded and includes persisted jitter; HTTP `Retry-After` can delay
the next attempt further. Restarting neither redraws the deadline nor resets
repeated challenge failures. Calls made before the deadline do no CA work.
The failure counter saturates at 32 while bounded backoff continues. Temporary
network failure never fabricates a terminal order; old `retry_limit` terminal
receipts remain explicit holds. A successful order or authorization hint is
included if a later fetch or readiness request fails in the same invocation.
Successful polling of an unchanged phase conservatively retains retry history;
actual phase or authority progress resets it. This keeps complete checkpoint
predecessors ordered across interruption.

Before remote work the owner publishes a same-phase attempt checkpoint, keeping
the failure count and retained lower bounds. Checkpoint storage requires Linux
`O_TMPFILE`: complete private bytes are flushed before a fixed staging name is
linked. First publication uses no-replace; replacement verifies the exchanged
predecessor inode and bytes. A stronger staged checkpoint is first promoted and
flushed; cleanup removes only a complete predecessor whose applicable timing is
already retained durably. The held installation/evidence directories are
checked before and after publication. Any uncertain operation poisons the
current writer, which retains its lock until reopened for reconciliation. A
filesystem that cannot safely create/link/flush the checkpoint refuses before
the next CA request.

Unchanged Pending or Processing polls consume no new phase receipts. Ordinary
work requires room for at most eight phase writes plus 64 reserved receipts.
At the reserve boundary, ordinary challenge work defers to the retained order
expiry or a later CA deadline; finalization, certificate reconciliation,
certain terminal observations, and challenge withdrawal retain capacity.
Repeated real account/order mutations are separately bounded and hold before
using that reserve. A known Processing order remains queryable after the old
order deadline. Regressing Pending/Ready responses cannot erase a retained
finalization stage or cycle it repeatedly through the reserved phase budget.

The transport and signing operations have their own shorter deadlines inside
the worker's 90-second invocation limit. Timing publication refuses a backward
observation; entry also retains the two-minute wall-clock skew guard.

## Verification and remaining integration

The focused tests run the actual vendored protocol, verify every account JWS,
validate a signed CSR and a certificate chain, exercise the actual snapshot
parser and private ledger, and reopen the installation between invocations.
The CA and test keys exist only in the fixture. Tests cover lost registration,
lost order and finalization responses; publication interrupted before/after
rename; exact retained CSR recovery; persisted backoff and saturated retries;
changed/processing/valid challenge targets; changed valid-order expiry;
staging-root isolation; and malformed evidence or projection permissions.
Polling regressions cover more than 512 unchanged observations, more than 32
temporary failures, current/staged checkpoint interruption, invented anchors,
required-checkpoint disappearance, preserved CA lower bounds, and completion or
withdrawal after entering the phase reserve.

These tests are component and interruption evidence. They do not prove public
CA issuance, a publicly reachable port 80 responder, shipped-image behavior,
an activated keyless leaf, reboot recovery or AWS load characteristics.
The connected generation owner supplies the authenticated handoff and retains
separate token/certificate schedules; deployed runtime reload and lifecycle
qualification still need their own evidence. Candidate completion
records an actual-lifetime fallback through the separate
[renewal schedule owner](installer-acme-renewal.md); its anonymous ARI refresh
API retains selected times and refresh deadlines without creating an order.
This worker returns a candidate; activation and qualification belong to those
separate owners. See [hosting continuation and recurring issuance](installer-acme-host.md).

Protocol references:

- <https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.3>
- <https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.4>
- <https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3.1>
- <https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1>
- <https://www.rfc-editor.org/rfc/rfc9773.html>
- <https://letsencrypt.org/docs/profiles/>
