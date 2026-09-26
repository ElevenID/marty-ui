# Beta-only Rust passport bureau simulator

The beta environment has no separately deployed ICAO signer or personalization
bureau. Managed issuer-profile/KMS signing supplies the former; this executable
supplies only a **non-physical** bureau simulator for software acceptance. It
must not be used to represent a manufactured or shipped document in production.

The simulator is built into the native issuance release image as
`marty-passport-beta-bureau` but has no default Compose service or host port.
It refuses to start unless `ENVIRONMENT=beta` and
`PASSPORT_BETA_BUREAU_ENABLED=true`. Its exact HTTP and persistence behavior is
in `contracts/passport-beta-bureau-behavior.json`.

It accepts the frozen single and batch bureau envelopes. It retains no MRZ,
data group, SOD, DSC certificate, or raw payload. Its dedicated beta-only table
holds an organization-scoped idempotency key, request digest, and callback
delivery state. Repeated identical submissions return the same bureau job ID;
conflicting reuse is rejected. A job advances from queued through simulated
production statuses only after the native issuance callback accepts the
organization-bound event signed by the KMS-held callback MAC. An unavailable
signing service or rejected callback leaves the prior durable status in place
and is retried. The `BETA-SIM-` tracking prefix is deliberately conspicuous.

The existing internal service token authenticates submissions and polls. The
existing signing-keys internal credential authenticates the KMS signing call.
No new passport bearer-token file or cryptographic key is provisioned for this
simulator. The final beta overlay must keep the service on the private Compose
network, use the immutable released services image, enable both KMS callback
provider and consumer, and remove the legacy raw callback-secret mount. Until
that reviewed overlay and its gates land, this binary is **not deployed**.

This is not a substitute for an external physical bureau. Production
personalization remains an outstanding integration requiring a real provider,
contract, credentials, data-handling review, and acceptance evidence.
