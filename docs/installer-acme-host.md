# ACME hosting setup and pending-order continuation

The installer now has an explicit ACME hosting selection and a host transaction
that connects retained OpenBao custody, scoped credentials, and the enrollment
worker. A completed enrollment produces an admitted certificate candidate. The
separate generation and activation owners decide whether that candidate can
become the served certificate; a successful setup or CA order does not mark an
installation Ready.

## Hosting selection

The ACME settings belong to the immutable hosting record:

```json
{
  "schema": "elevenid.installation-hosting/v1",
  "mode": "direct",
  "public_origin": "https://login.example.com",
  "public_entry_origin": "https://203.0.113.7:8443",
  "listener": { "bind_address": "0.0.0.0", "port": 8443 },
  "tls": {
    "termination": "marty-keyless",
    "certificate_source": "acme",
    "http01_host_port": 18080,
    "acme": {
      "environment": "production",
      "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
      "profile": "shortlived",
      "terms_url": "https://letsencrypt.org/documents/LE-SA-v1.8-July-06-2026.pdf",
      "terms_agreed": true
    }
  }
}
```

The names and address above are documentation examples. Select a DNS name and,
if required, a real reachable IP entry origin. The canonical identity remains
the DNS origin; the single IP entry origin is an explicitly admitted landing
alias with an independently configured port. Both identifiers must match the
CSR and issued leaf exactly. The configured terms URL must still be the terms
advertised by the selected directory when the account is registered.
The example reflects the [production directory](https://acme-v02.api.letsencrypt.org/directory)
observed on 2026-11-01. Its agreement flag illustrates the schema; the customer
must review and authorize the actual advertised agreement before registration.

ACME is initially supported only with direct DNS hosting and the managed
OpenBao foundation. Imported foundations, external proxy termination, local
fallbacks, and changing an installation's saved origin or CA environment are
not admitted by this path. Existing managed-CA and imported hosting records do
not acquire new serialized fields.

`http01_host_port` is an explicit unprivileged host port, at least 1024 and
different from the ingress, OpenBao, and other admitted listeners. Compose
publishes it on `127.0.0.1` only. The customer must route public HTTP port 80 for
each selected identifier to that listener. The response service accepts only
the exact selected DNS/IP origins and reads only the public challenge child
directory; the installer parent, credentials, and order journal remain private.

Staging selects the exact staging directory and requires an explicit
`--acme-staging-roots ABSOLUTE_PATH`. The command validates and retains those
public CA bytes as `evidence/staging-acme-roots.pem`. The host binds their exact
hash and reparses their certificate constraints on continuation. Production
refuses this override and uses the compiled maintained public root set. A
staging candidate remains qualification evidence and cannot enter production
activation.

## Boundary before the first CA request

The fresh installer completes these steps while holding its original
installation lock:

1. Create the application storage and operator-password projection through the
   existing exclusive creation operations. Save metadata-only preparation
   evidence; no passwords or key material enter this record.
2. Enroll the durable workload/ingress renewal owner from the still-live initial
   workload credentials. Save the public authority plan, successful native job
   receipt, and hashes of the private retained AppRole identity. A later pending
   order does not require the original eight-hour tokens to remain usable.
3. Persist ACME host intent. Run the two fixed setup jobs for account/CSR custody
   and scoped credential enrollment. The initial root credential stays inside
   the OpenBao-owned filesystem and the fixed container helpers. The host reads
   public custody results and receives only the intended scoped identities.
4. Start the owned HTTP-01 responder with its dedicated public child mount.
   Retain the cumulative Compose resource and input-file identities from every
   earlier setup operation.
5. Persist and read back the complete preparation boundary. Revalidate the
   scoped account and CSR bindings before invoking the enrollment worker.

Application settings, including the default policy, are selected in the earlier
`Verified` phase. The initial-order ownership gate authenticates that selection
through the existing settings reader before allowing its exact
`application-settings-input.json` and `application-settings-selection.json`
records. These policy records do not mean an application has started. Missing,
changed or unbound settings remain refused, as do unrecognized `application-*`
records and all generation, Compose application, lifecycle and uninstall markers.

The completed renewal environment is an immutable input, including the public
origin values, challenge port, and authority-plan digest. Each later setup phase
derives a new environment file from those exact bytes. An already-present
setting must be byte-identical and unique; conflicting or duplicate settings,
layers, or file bindings are refused. Earlier bound input files are preserved.

Signed trial scopes retain separate preparation provenance. A customer
`CandidateTest` uses its authenticated inventory and completed rootless storage
canary. A signed `AcceptanceOnly` qualification uses the exact authorization,
controller consumption and inventory subjects plus their signature/provenance
sidecars pinned in the installation journal, together with the same completed
canary records. The preparation reader requires the exact named evidence set;
the two scopes cannot substitute for each other. Neither scope gains original
creation/deletion receipts or a Ready outcome, and an older acceptance record
without the pinned grant set cannot enter this execution path.

The setup evidence retains `activation_performed: false` and
`installation_ready: false`. Partial setup is not treated as absent, and neither
setup job is recreated automatically after an uncertain outcome.

## Read-only preparation diagnosis

Use the exact retained operator as the installation owner to inspect both host
preparation and the enrollment ledger:

```sh
/absolute/installation/marty-deploy acme status \
  --install-dir /absolute/installation
```

This command does not use Docker, log in to OpenBao, issue credentials, contact
the CA, start a service, or change retained evidence. A zero command exit means
the status report was produced; inspect its fields before judging installation
health. The existing `configured` field still means that an enrollment ledger
exists. It can be `false` after successful custody, credential and HTTP-01 jobs
when the prepared host checkpoint has not passed its final readback.

The additional `host_preparation` object reports that earlier boundary:

| State | Meaning |
| --- | --- |
| `not_selected` | The saved hosting selection does not select ACME. |
| `not_started` | ACME is selected, but none of the fixed host setup records is present. |
| `incomplete` | Some setup evidence exists, but the complete prepared record is absent. |
| `refused` | A retained host readback check failed; `check` identifies its fixed boundary. |
| `prepared` | The immutable historical setup and provenance checks passed. |

`host_preparation.initial_preparation` separately reports the pristine storage
check needed before first application startup. Its `checked`, `matches` and
`check` fields distinguish an unexamined initial gate from a pass or refusal.
Application activity can legitimately change the original storage observations:
historical preparation can remain `prepared` while this initial check reports
`application_preparation`. Recurring maintenance uses its existing historical
provenance and selected-generation authority; status does not choose or change
that authority.

Refusals from the instrumented ACME host admission boundaries append a fixed
code, for example `check=prepared_decode` or `check=responder_receipt`. The same
closed codes appear in status. These are examples of diagnostic boundaries, not
conclusions about a particular retained installation. Private paths, parser
details, credential values and backend error bodies are never included in these
messages.

| Code group | What to inspect privately |
| --- | --- |
| `prepared_read`, `prepared_decode`, `intent_read`, `intent_decode` | Exact retained record custody and typed JSON shape. Reading a JSON object in another language does not exercise native deserialization. |
| `application_preparation`, `application_provenance`, `public_renewal` | Initial storage observations versus immutable setup provenance, and the retained renewal owner. |
| `evidence_fingerprints`, `prior_receipt`, `responder_receipt` | Bound record bytes, cumulative receipt identity, and the native receipt encoding. |
| `current_input_receipt`, `historical_input_receipt`, `input_custody` | Current input bindings, retention of earlier inputs, and their current file custody. |
| `custody_job`, `credentials_job`, `resources`, `runtime_inputs` | Completed job proofs, retained resource identities, and the exact configured roots and listeners. |

Receipt hashes bind the native bytes. This workspace enables
`serde_json/preserve_order`; recursively sorting a parsed JSON object is not the
native `ComposeReceipt` encoding. Semantic JSON equality and a different sorted
hash alone do not establish corruption or a product serialization defect.

Every report retains `runtime_observed: false`, `continuation_authorized: false`,
`setup_replay_authorized: false`, `activation_performed: false` and
`installation_ready: false`. It is a local retained-evidence observation, not a
live Engine, OpenBao, certificate, application or release qualification. Preserve
the first failure and the original records. A diagnostic code does not permit
editing evidence, repeating a setup job, extending a trial or bypassing the
existing continuation and signed-candidate gates.

The 2026-11-04 AWS candidate exercise motivating this change reached successful
ACME setup jobs and a retained prepared checkpoint, then returned the former
generic host refusal before an enrollment ledger appeared. The exact native
predicate remains unresolved. These diagnostics improve the next signed
candidate investigation; they do not claim that the earlier deployment or its
blocked demos have been repaired or qualified.

## Continuing a normal pending order

Run the retained operator as the installation owner under no-new-privileges:

```sh
/usr/bin/setpriv --no-new-privs -- \
  /absolute/installation/marty-deploy acme continue \
  --install-dir /absolute/installation --docker-bin /usr/bin/docker
```

This uses the installation's complete prepared boundary. It does not recreate keys,
policies, AppRoles, setup containers, application storage, or the password
projection. A known order continues with its retained account URL and exact
signed CSR bytes. Unknown outcomes of non-idempotent order creation remain an
explicit reconciliation hold.

Before using scoped credentials, continuation checks the exact hosting
selection, release/runtime identities, preparation records, private renewal
identity, staging trust where applicable, executable and Compose inputs,
completed setup jobs, and current owned resources. Replacing a directory inode,
changing any bound file, or changing a retained setup execution is a refusal.
An order that is still pending returns a durable pending outcome rather than
pretending the installation is complete.

The original application preparation proof is specific to the interval before
first application startup. Normal application activity changes those storage
directories. Recurring maintenance uses the selected generation and current
Compose session as its authority. It retains the original preparation's exact
provenance and immutable setup files, while leaving historical storage ownership
and mode observations out of that recurring admission check.

Initial continuation has its own replacement authority, separate from renewal
of a selected generation. A completed candidate that expired before activation
can authorize a replacement. A known order with an authenticated invalid or
expired order/authorization can also authorize a later attempt, including before
the first candidate exists or after an expired candidate's replacement failed.
The latter case requires a distinct initial-terminal receipt, confirmed challenge
withdrawal, and the retained cooldown. The first consecutive terminal attempt
waits at least five minutes; subsequent consecutive failures double the delay up
to six hours. A longer CA `Retry-After` or previously retained polling deadline
remains the lower bound without that cap. A completed candidate ends that
consecutive-failure series.

Both reasons require the complete, still-pristine original preparation and its
exact host intent, configuration, custody and credential evidence. The account
URL, distinct account/ingress keys, signed CSR, origins, CA environment, profile
and agreed terms remain unchanged. The v2 initial permit explicitly identifies
either the expired admitted candidate or the immediate confirmed terminal
predecessor. Existing v1 expiry permits remain readable. Initial permits refuse
to run after application, selected-generation, lifecycle or uninstall ownership
appears. Their terminal proof cannot substitute for a generation-renewal permit.

An interruption after writing a permit but before the first order-stream receipt
resumes that same permit. Interrupted withdrawal resumes locally and must finish
before another order is authorized. An unknown `newOrder` result, an account or
certificate-admission failure, or an old terminal record without the typed
initial proof remains held; none is converted into permission for another order.

A candidate inside the minimum one-hour activation margin is reported as
non-activatable, with its expiry as the next replacement eligibility time. A
historically admitted certificate that expired during interrupted withdrawal
can finish its local receipt chain without being presented as a fresh candidate.

## Recurring certificate issuance

The generation owner authorizes a renewal only after a retained ARI or fallback
deadline is due. Its permit names the selected certificate, original generation,
current configuration and exact scheduling receipt. A later ARI refresh does
not invalidate that historical due decision. A workload-only successor may
continue the same order when it still serves the same certificate and keys.

Each issuance has an independent append-only order stream. Cycle zero retains
the original enrollment filenames and serialized shape; positive cycles bind
their explicit permit and predecessor. They start with the existing account
already bound and cannot enter account-registration states. A known order keeps
the original CSR bytes through restart and finalize reconciliation. A lost
new-order URL remains a hold, including after reboot.
If finalize succeeds remotely but its response is lost, passing the order's old
expiry during a retained backoff does not classify it as terminal. The worker
waits for that deadline and reobserves its known URL; an already valid order can
finish without requesting or finalizing another certificate.

An authenticated invalid or expired order, or invalid or expired authorization
on a known order, can reach a different outcome. The worker records the exact
terminal reason, observation time and cooldown before it withdraws challenges.
It records withdrawal completion only after publishing and rereading the empty
public projection. An interruption in this local step resumes withdrawal for
the same order without registering an account or requesting another order.

The first such terminal attempt waits at least five minutes. Further terminal
attempts against the same selected certificate double that delay up to six
hours. A later CA `Retry-After` or retained polling/retry deadline remains the
lower bound even when it exceeds six hours. The deadline is durable and is not
redrawn after restart. The successor permit binds the exact terminal receipt and
eligibility time; if that permit exists before the worker's first ledger record,
continuation uses it again. Its historical withdrawal proof remains valid when
the successor legitimately publishes new challenges.

Transport retry exhaustion alone does not establish that a known order is
terminal. It remains a hold, as do unknown new-order outcomes, account failures,
certificate-admission failures and old terminal records that lack the typed
timing and withdrawal evidence. No error-message substring can authorize a new
cycle. These conditions remain distinct in the maintenance status.

Before using scoped credentials, the maintenance host starts only the exact
existing OpenBao, unseal/readiness and HTTP-01 containers when needed. Their
native health probes use OpenBao's local Unix listener. The fixed scoped Unix
TLS recovery runs before verified HTTPS, so an expired local HTTPS certificate
does not force root access or setup replay. The host then revalidates the account
and ingress public keys and checks the generation permit again before CA work.

Recovery of an interrupted generation can supply a separately validated native
baseline when the retained containers no longer match the selected logical
session. That capability pins the real container census and stopped application
roles; it does not replace the selected certificate or issuance permit. The host
checks both authorities before and after infrastructure recovery and scoped-key
authentication. Full Compose model admission retains the ingress-listener
policy, while recovery commands and health checks select only the three existing
OpenBao, unseal/readiness and HTTP-01 roles. Setup jobs remain observation-only.

Expired selected certificates remain historically identifiable and are due for
replacement; they are not re-admitted as currently valid. The public certificate
admission boundary and the separate generation activation gate remain required
for every newly issued leaf. ARI performs no requests for an already expired
certificate. Its record budget is per candidate and covers the sole admitted
short-lived profile's maximum 160-hour issued lifetime, including DNS-only
installations; it is not a lifetime limit on installation renewals.

## Signed candidate qualification

An admitted installation and a signed candidate trial retain different
preparation provenance. A candidate trial must match its recorded execution
scope, both copies of the signed inventory and retained sidecars, the installed
operator digest, and the complete rootless storage canary chain. The read-only
canary verifier reobserves its retained directory inodes, mapping observations,
marker, restored ownership, and completed removal receipts.

Candidate preparation creates storage and the password projection exclusively,
then records their metadata for continuation. It does not mint the admitted
installation's original creation/deletion receipts or permit Ready. Acceptance-
only and unsigned-development scopes do not gain admission through this path.

## Evidence and qualification limits

The focused component tests cover exact environment derivation, duplicate and
conflict rejection, staging-root parsing and retention, cumulative native
receipts, and immutable preparation bindings. Recurring tests exercise separate
order streams with one retained account and exact CSR, known-order resume after
a lost finalize response, unknown-new-order holds, historical certificate
admission after expiry, and refusal to reuse the old leaf or unchanged expiry as
a replacement. Terminal retry cases cover retained CA deadlines, interrupted
withdrawal, increased cooldown and evidence that cannot cross predecessors.

Settings regressions run the real settings preparation and selection writers
before the initial-order gate, using both default and explicit synthetic policy.
They cover legacy absence, unbound or foreign selections, missing or changed
records, links, unsafe modes, and later-ownership markers. Every accepted and
refused gate call preserves the journal and evidence bytes, modes and link
counts. These are local component checks, not evidence of a successful AWS
installation or public certificate issuance.

The complete preparation fixture runs the enrollment worker under the same
installation lock, expires its actual temporary certificate, reopens the saved
state and verifies reuse of the original replacement permit. It also checks
that application, generation, lifecycle or uninstall markers prevent this
pre-activation path from running. The opt-in tests require a real
nonroot process identity to exercise the rootless admission checks. They use
synthetic native observations and real temporary certificate signatures to test
the readers; they do not claim that Docker or a public CA was exercised.

Diagnostic regressions also exercise native strict decoding and typed receipt
roundtrips with the workspace's actual `preserve_order` feature, including a
prepared record larger than 128 KiB. Small tests check fixed-code sanitization,
pre-ledger status and unchanged evidence. The existing full prepared-boundary
fixtures retain their ordinary-user requirement. Run those two opt-in cases
explicitly as a nonroot user under no-new-privileges; a default test run that
skips them is not evidence that their admission or mutation cases passed:

```sh
cargo test --locked -p marty-deployment-catalog --lib \
  installer_acme_host::initial_rollover::tests
cargo test --locked -p marty-deployment-catalog --lib \
  installer_acme_host::diagnostics::tests
cargo test --locked -p marty-deployment-catalog --lib \
  status_reports_preledger_host_progress_without_exposing_or_changing_evidence
/usr/bin/setpriv --no-new-privs cargo test --locked -p marty-deployment-catalog --lib \
  installer_acme_host::boundary_tests::complete_pending_boundary_reopens_and_rejects_rebound_inputs_proofs_and_native_jobs \
  -- --ignored --exact --test-threads=1
/usr/bin/setpriv --no-new-privs cargo test --locked -p marty-deployment-catalog --lib \
  installer_acme_host::boundary_tests::recurring_setup_retains_provenance_without_reapplying_original_storage_observations \
  -- --ignored --exact --test-threads=1
```

Run the commands from the `rust` workspace. They use synthetic temporary state
and never contact AWS, Docker, OpenBao or a public CA. They do not replace the
signed artifact and installed-runtime qualification gates.

The normal PR CI contracts lane already invokes
`scripts/ci/qualify-installer-recovery-fixtures.sh` for both opt-in cases. It uses
the compiler-recorded default production library executable, enforces ordinary
UID/GID, no-new-privileges and empty capability sets, and checks that every named
case passed exactly once. No workflow or release gate needs to be relaxed for
these diagnostics.

The live qualification still needs the shipped images, actual external HTTP-01
routing, a production certificate, keyless runtime activation, and the selected
AWS host. Recovery from a stopped prepared stack and an expired local OpenBao
HTTPS certificate must use runtime-only restart and the fixed Unix TLS recovery
operation before reconnecting over HTTPS. Recurring public issuance and its
systemd scheduling require a selected-generation transaction and actual
reboot/crash qualification. These are separate claims from a successful initial
setup or a valid candidate certificate.
