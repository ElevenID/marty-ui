# Durable ACME renewal scheduling

The enrolment owner records a renewal fallback before returning an admitted
certificate candidate. `installer_acme_renewal` retains the schedule for that
exact certificate and can refresh it through the maintained client's anonymous
ACME Renewal Information (ARI) request. This module creates no order and
activates no certificate. An active-generation owner must still decide when
and how to perform a renewal and retire the predecessor certificate.

## Bound to an admitted candidate

`ensure_for_candidate(&mut LockedMaintenance, &AcmeCandidate)` requires the
candidate's exact completed enrolment receipt, installation, environment,
configuration binding, leaf/full-chain digests and certificate validity. It
uses the existing installation lock and private evidence writer. Calling it
again reuses the retained decision. It never contacts the CA or OpenBao.

Each certificate has its own append-only sequence:
`acme-renewal-<environment>-<leaf-DER-sha256>-000000.json`, followed by numbered
records. Receipts are `0600`, have bounded size and link to the previous receipt
digest. Partial records, gaps, changed bindings and changed selections for a
previously recorded window hold execution before another request. The sequence
is separate from account/order enrolment and from workload credential refresh.

The initial fallback uses the actual `notBefore` and `notAfter` values from the
admitted leaf. For a certificate shorter than ten days it falls halfway through
the lifetime; otherwise it falls two thirds through the lifetime. The current
`shortlived` profile uses the first rule. No fixed 90-day or 160-hour renewal
date is assumed.

## Anonymous ARI reads

`refresh_for_candidate(&mut LockedMaintenance, &AcmeCandidate)` constructs the
selected directory's bounded HTTPS adapter and restores the retained public
account view. Its signer rejects every signing request. The maintained
`Account::renewal_info` API uses an ordinary GET, so no OpenBao client,
credential provider, key export, account registration or account JWS is needed.
Reading a directory or ARI response does not agree to changed CA terms.

The public initial-install wrapper is
`refresh_for_install(&mut InstallerState, &AcmeCandidate)`. It requires a live
`Provisioning` transaction, rejects a nested Tokio runtime before borrowing the
existing lock, and preserves the installer phase. Internal generation owners
can use the locked candidate functions once their own activation contract is
in place.

The certificate identifier comes from the admitted leaf's authority key ID
and DER serial-number contents. The serial's leading sign byte is preserved;
converting it to an unsigned integer would produce the wrong ARI identifier.
A leaf without a usable authority key ID retains its lifetime fallback and
makes no ARI request.

Before the directory request, the owner records a fetch intent and a retry
deadline. An interruption after either GET can therefore be retried after a
retained delay without resetting the schedule or claiming that the prior read
completed. Both transport calls are bounded inside a 25-second invocation
deadline.

## Scheduling decisions

For a usable suggested window, the owner chooses an unbiased random whole
second within the window and persists it. A refresh returning that same window
reuses the selected time, including if an intervening response had suggested
a different window. A newly observed window receives its own selection. A
selected time in the past is reported as due; this module does not turn that
observation into a new order.

Successful ARI `Retry-After` hints control the next information fetch, with a
one-minute local minimum. A longer CA hint remains a lower bound even when it
exceeds the usual twice-daily polling cadence. Relative hints are rounded up
before converting to persisted whole seconds. A hint beyond certificate expiry
leads only to expiry handling, without another CA request. The CA's next-information
deadline is independent of the selected renewal time.

Temporary failures use persisted exponential backoff with jitter and a capped
failure count. Invalid responses, missing `Retry-After`, unsupported ARI and
exhausted temporary retries use a six-hour retry interval. Error response
`Retry-After` can delay another request further. A retained earlier ARI
selection survives a failure; the lifetime fallback can make renewal due
earlier while ARI is unavailable. No retry deadline delays expiry handling.

The owner checks expiry before fetching and again after directory preparation,
so a slow directory request cannot start an ARI request for an expired leaf.
Expiry clears the next-fetch deadline and persists an expired state. Read-only
status also derives expiry from the current clock. Neither an expired schedule
nor a due schedule authorizes certificate activation or order creation.

The receipt bound is 32,768 records of at most 16 KiB per certificate. This
covers intent/result pairs for a 160-hour leaf even at the minimum one-minute
refresh interval. Normal intervals require only a few dozen records. Exceeding
the bound holds the operation; records are never silently truncated or adopted.

## Integration and evidence

Candidate completion calls the offline `ensure_for_candidate` boundary. The
separate refresh API can collect an initial ARI decision or refresh a retained
schedule. Workload-token refresh does neither. Status keeps automatic renewal,
certificate activation and installation readiness explicitly unproved.

Tests reuse the actual in-memory enrolment fixture, including its account JWS,
signed CSR and certificate-chain admission, to obtain candidates. They then
exercise the maintained ARI client against a GET-only fixture. Cases include
window reuse and changes, interruption before a result receipt, corrupt or
noncontiguous evidence, absent or invalid ARI, server backoff, environment and
candidate substitution, DER serial encoding, and expiry before or during
directory preparation. These are component and persistence tests; they do not
prove an installed renewal timer, public CA issuance or an activated leaf.

Before live recurring renewal, the generation owner must bind refresh calls to
the authenticated active certificate, stop polling a replaced predecessor,
create a separate durable renewal order when due, and verify the new keyless
leaf before retiring the old generation. ARI scheduling is independent of
8-hour edge-token replacement and cannot trigger new orders from that path.

References:

- [RFC 9773, certificate identification and renewal scheduling](https://www.rfc-editor.org/rfc/rfc9773.html)
- [Let's Encrypt integration guide, renewal and retries](https://letsencrypt.org/docs/integration-guide/)
- [Pinned maintained client ARI API](https://docs.rs/instant-acme/0.8.5/instant_acme/struct.Account.html#method.renewal_info)
