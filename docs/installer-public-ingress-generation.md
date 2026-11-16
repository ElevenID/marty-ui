# Public ingress in the immutable application generation

This slice carries a completed production ACME candidate into the existing
generation transaction. It does not create a second certificate writer. The
application generation owner remains responsible for publishing immutable
credential files and the application selection receipt.

## Three independent trust branches

Existing private-CA ingress and imported AWS foundation generations retain
their current schemas, inventories and certificate checks. A public ACME
generation has its own schema and an exact 42-file renewable inventory: the
existing 40 workload/Keycloak files, the admitted ingress fullchain, and the
restricted ingress TLS signer token. It has no `installer_ingress_ca_cert`.

Production admission uses the compiled Mozilla roots and the exact selected
DNS name plus optional IP entry alias. Returned certificate roots, local OS
trust and staging roots cannot widen that trust. OpenBao's separate TLS CA
still authenticates the remote signer connection and remains a normal runtime
input. Staging certificates remain qualification candidates and cannot be
selected through this production generation path.

## Public plan and independent credentials

Before contacting the CA, `PublicRenewalAuthorityPlan::from_initial` binds
the saved ACME configuration, canonical DNS/IP origins, original ingress
receipt and public key, and hashes of all 43 initial credential files.
`record_for_install` persists `evidence/renewal-public-authority-plan.json`.
The existing renewal bootstrap receives the read-only
`/input/public-renewal-authority-plan.json` and its separately bound
`MARTY_INSTALLER_PUBLIC_RENEWAL_AUTHORITY_PLAN_SHA256`. It proves the still-live
initial tokens and enrolls durable renewal authority before a CA request can
leave the installation waiting. The completed host receipt also binds hashes
of the three private AppRole inputs; none of those private values enters the
public plan.

After issuance, `PublicIngressPlan::from_candidate` binds the completed
production enrolment ledger, hosting selection, installation UUID, order and
CSR digests, retained version-one P-256 ingress SPKI, and exact admitted chain.
It additionally binds the pre-CA authority plan and its completed enrollment
receipt. Its `record_for_install` persists
`evidence/generation-public-ingress-plan.json` before generation. The generation
helper receives both plans read-only and the additional
`MARTY_INSTALLER_PUBLIC_INGRESS_PLAN_SHA256` for
`/input/public-ingress-plan.json`. Both parsers require bounded canonical bytes,
exact digests, and closed fields.

The host checks each native Compose model before creating either helper:
its plan digest must be a bound input, its mount must be the exact read-only
file with host-path creation disabled, and no overlapping mount can shadow it.

The public renewal-policy branch can read the retained ingress key and policy,
mint the exact TLS signer profile, and prove that token against the retained
public key. It does not receive an account-signing credential or a CSR
credential. It has no ingress CSR or private-CA issuance permission. Existing
workload and Keycloak renewal permissions stay within their existing scopes.

## Certificate carry and source validation

The first transition authenticates the original private-CA certificate and
its unchanged ingress SPKI at the original validated observation time before
selecting the independently admitted public chain. The original files and all producer evidence remain in place. Only the
42-file candidate is presented to the application generation publisher.

A later candidate that only refreshes credentials must carry byte-identical
public certificate-chain bytes and the same enrolment provenance. It mints a
different bounded TLS token and records that the certificate was reused. No
ACME request, CSR operation or certificate issuance is reachable from that
producer. A different certificate requires its own completed enrollment cycle
and admitted candidate before the generation owner can select it.

The native pending, validation and completion records bind the public-plan
digest. Host receipts bind the same plan, exact owned helper, image, network,
transfer and output hashes. Historical receipt checks use their recorded
observation time. After a long CA wait, the enrolled replacement path checks
all fresh workload/Keycloak tokens and certificates live, compares their exact
policy scopes to the completed enrollment, and verifies that original SPKI and
issuer continuity still hold at the recorded original time. It does not require
expired original tokens to sign again. Existing private-CA and CA-rotation
preflights retain their original behavior.

New certificate admission requires at least one hour remaining. Read-only
inspection of an already selected public chain accepts it through its actual
validity interval and rejects exact expiry; renewal degradation is a separate
condition. The metadata distinguishes certificate reuse from a
new TLS token and retains `activation_performed: false` and
`installation_ready: false`.

## Activation boundary

The original `application-generation` directory remains immutable. The recurring
owner publishes each successor under
`application-generations/<sequence>-<binding-digest>` and records its parent,
producer, native activation, and full saved Compose session. It changes only
the private current-generation selector after validating the completed native
activation and exact selected files. A lost publication response reopens the
same transaction; it cannot turn into an unrelated generation or replay the
initial setup jobs.

Lifecycle recovery invokes the pending generation owner before ordinary
service observation, because interrupted replacement can leave an authenticated
mixture of old and new container IDs. Supported pause and security-seal commands
can stop that owned mixture without completing a renewal. Historical lineage
verification visits each generation once per verification operation and does
not impose a lifetime generation count limit.

The implementation and remaining recovery holds are described in
[generation maintenance](installer-generation-maintenance.md). Local component
checks establish the documented boundaries, while installed image, long-offline
recovery, browser, reboot and signed-artifact qualification remain separate
release requirements. The transaction continues to report
`installation_ready: false`.

## Offline public-trust fixture

The public production-path tests use Let's Encrypt's published first short-lived
certificate and its E6 intermediate, with a fixed historical validation time.
They use the real compiled public root set. See
[`tests/fixtures/acme/README.md`](../tests/fixtures/acme/README.md) for sources,
hashes and limits: the certificate was revoked and is now expired; it provides
signature/path test material, not a live validity or custody assertion.

No test creates a public CA account or order. No fixture contains the private
key for that published public certificate.
