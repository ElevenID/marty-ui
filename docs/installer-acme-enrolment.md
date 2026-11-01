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
per environment. Reaching the limit holds the operation; this initial ledger
is not yet a recurring-renewal history format.

| Operation | Durable boundary | Recovery behavior |
| --- | --- | --- |
| Account registration | Account intent before the registration POST; account URL after success | A retained intent without a URL first uses the same key with `onlyReturnExisting`. A definite `accountDoesNotExist` response permits a later explicit registration attempt. |
| New order | Exact CSR/profile/identifiers and order intent before `newOrder`; URL and immutable order target after success | A known URL is restored. An unknown result without a URL holds without even a directory request. The worker never guesses that a lost response means no order exists. |
| Challenge publication | Exact public snapshot and previous digest before atomic replacement | A restart replays the same pending snapshot. It accepts the already-published matching file or its exact retained predecessor. |
| Challenge notification | Exact published authorization/challenge target and notification intent | The target is refreshed and checked before notification. Only a pending challenge receives the readiness POST; processing/valid observations do not trigger another POST. |
| Finalization | Finalization intent before sending the retained CSR DER | A known order is queried first. Processing/valid state proceeds without repeating finalization; a ready order can resend the exact retained CSR. |
| Candidate admission | Admitted full chain and its validation metadata before challenge withdrawal | A restart revalidates the retained chain and completes withdrawal. No active generation or installer `Ready` state is written. |

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
withdrawal is replayable.

Retry state records the failure count and one chosen next-attempt timestamp.
Backoff is bounded and includes persisted jitter; HTTP `Retry-After` can delay
the next attempt further. Restarting neither redraws the deadline nor resets
repeated challenge failures. Calls made before the deadline do no CA work.
The retry limit moves to a terminal state and withdraws the public projection.
The transport and signing operations have their own shorter deadlines inside
the worker's 90-second invocation limit. A backwards wall-clock jump greater
than two minutes holds the operation.

## Verification and remaining integration

The focused tests run the actual vendored protocol, verify every account JWS,
validate a signed CSR and a certificate chain, exercise the actual snapshot
parser and private ledger, and reopen the installation between invocations.
The CA and test keys exist only in the fixture. Tests cover lost registration,
lost order and finalization responses; publication interrupted before/after
rename; exact retained CSR recovery; persisted backoff and retry limits;
changed/processing/valid challenge targets; changed valid-order expiry;
staging-root isolation; and malformed evidence or projection permissions.

These tests are component and interruption evidence. They do not prove public
CA issuance, a publicly reachable port 80 responder, shipped-image behavior,
an activated keyless leaf, reboot recovery or AWS load characteristics.
Activation still needs an authenticated generation handoff, runtime reload and
live verification. Recurring renewal still needs an active-certificate owner,
persisted ARI selection and refresh deadlines, expiry fallback, credential
recovery and installed lifecycle tests. The worker deliberately stops before
those claims.

Protocol references:

- <https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.3>
- <https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3.1>
- <https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1>
- <https://www.rfc-editor.org/rfc/rfc9773.html>
- <https://letsencrypt.org/docs/profiles/>
