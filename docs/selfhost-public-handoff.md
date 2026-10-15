# Public self-host handoff gate

The current public Stack release is not an installable self-host product. The
release workflow can prepare an image-locked ZIP in an opt-in job, but that job
marks it **unqualified** and keeps it as a short-lived Actions artifact. Do not
send that ZIP to a customer as a supported installer.

An outside-party handoff needs one public release containing these exact assets:

| Asset | Purpose |
| --- | --- |
| `selfhost-bundle.zip` | Extracted, image-only installation |
| `selfhost-images.json` | Every Compose service pinned to an image digest |
| `selfhost-bundle-preparation.json` | Archive, lock, source, and producer run identity |
| `selfhost-preparation-transaction.json` | Original transaction bytes used by the preparation receipt |
| `prepared-selfhost-product-descriptor.json` | Original unqualified descriptor |
| `selfhost-qualification.json` | Exact installed journey result, including clean startup, migrations, login, issuance, presentation, verification, and cleanup |
| `selfhost-product-descriptor.json` | Qualified descriptor bound to the ZIP and evidence |
| `release-transaction.json` | Promoted public Stack release transaction |
| `SHA256SUMS` | Checksums for every asset above |

Keep the preparation transaction separately: its bytes are hashed into the
preparation receipt. The public Stack transaction is subsequently promoted and
therefore has different bytes. Substituting the latter invalidates the receipt.

After downloading all assets anonymously from the **same** public release,
run from a checkout of that release source:

```bash
python scripts/check_selfhost_release_handoff.py \
  --release-dir /path/to/downloaded-assets --tag v1.2.3
```

This check validates local asset closure, checksums, the prepared ZIP and lock,
the transaction lineage, and descriptor/evidence metadata. It does **not**
verify Sigstore signatures, prove that the download was anonymous, or replay
the installed journey. Those are separate mandatory publication and acceptance
gates. Its output says so explicitly. A successful local audit alone does not
authorize a support claim.

The opt-in `scripts/run_selfhost_business_journey.py` is the installed
component. It requires an unchanged extracted ZIP, the exact preparation
transaction/receipt/descriptor and image lock, independent state and secret
roots, a rendered all-profile Compose model, a uniquely named empty Compose
project, and a clean checkout of the public integration suite at an explicit
40-character revision. It revalidates artifact and source identity, the
reviewed service graph, and an empty state directory. It uses an empty Docker
credential store to pull the exact digest images, starts the selected local
services, checks their health and completed migrations, then selects only
`tests/oss_stack/selfhost_customer_journey.py`. It always tears down its owned
project and volumes after startup, including when the journey fails. It does
not delete the external state or secret directories. A passing component
report remains **unqualified**: an outer gate must own external OpenBao,
KMS custody proof, trusted fixture creation, signatures, and publication.
The integration test requires a real PKCE user, active issuer and verifier DID
profiles, and proves issue/present/allow followed by revoke/present/deny
through public routes.

The fixture contract for that exact test is in the public integration suite's
`tests/oss_stack/SELFHOST_CUSTOMER_JOURNEY.md`. The installer must provision
the migration-seeded organization, a disposable authorized Keycloak user, and
active KMS-backed issuer and verifier profiles before invoking the test. Public
profile inventory checks active DID bindings without exposing custody
coordinates; separate signed KMS evidence must prove managed, non-exportable
key custody for the exact installed artifacts. A `kms_custody` result and the
revoked-credential negative result are required in the eventual qualification
evidence. No external CSCA or DSC is used by this SD-JWT fixture.

The runner requires all eight `SELFHOST_*` fixture variables listed in the
integration contract in its process environment before it touches Docker.
Supply the test password through an operator secret runner. Supply a separate
absolute Compose env file outside source control; it must resolve
`SELFHOST_STATE_DIR`, `SELFHOST_SECRET_DIR`, hostnames, external `BAO_ADDR`, and
all other variables in the prepared ZIP. Populate every required secret file,
including scoped OpenBao tokens and workload TLS identity material, in the
secret root before running. The state root must exist and be empty. Provide
`--fixture-setup` as the absolute path to
`scripts/setup_selfhost_synthetic_fixture.py` in the exact prepared source
checkout, and `--fixture-setup-sha256` as its exact SHA-256. The runner rejects
a changed or substituted hook. The
runner invokes that script after health checks and migrations, before the
public test. Its contract is to create the disposable Keycloak user and active
KMS-backed issuer/verifier profiles through supported provisioning, and fail
unless they match the eight `SELFHOST_*` values passed to both processes by
the caller. Pass `--kms-custody-evidence`, `--kms-custody-signature`, and
`--kms-custody-public-key` as isolated absolute paths. The runner passes the
first two paths to the setup script as
`SELFHOST_KMS_CUSTODY_EVIDENCE_PATH` and
`SELFHOST_KMS_CUSTODY_SIGNATURE_PATH`. The script must write a new signed JSON
document with schema `marty.selfhost-kms-custody/v1`, the exact `source_sha`,
`archive_sha256`, `image_lock_sha256`, `organization_id`, `issuer_did`, and
`verifier_did`, plus `issuer_key_non_exportable: true` and
`verifier_key_non_exportable: true`. The runner verifies its signature using
the supplied OpenSSL Ed25519 public key before issuing, and requires that key's SHA-256 digest
in the prepared release source commit's reviewed
`deploy-config/selfhost-kms-custody-trust-roots.json`. This branch carries a
disposable test signer digest for review; no published release contains that
policy yet. Adding a trusted signer requires a reviewed source change and a
new prepared release. The
integration checkout is pinned to protected-main commit
`0b9aec1994378aba4ef4715f858de813b1a329ea`; a PR head cannot qualify.
The synthetic fixture hook is an opt-in follow-on candidate and has not yet
passed an installed run, so no installed journey has qualified a release.

The follow-on synthetic fixture setup and trust bootstrap contract are in
`docs/selfhost-synthetic-fixture.md`. They are not part of any currently
published bundle.
The exact artifact staging and isolated Linux invocation are in
`docs/selfhost-disposable-qualification-runbook.md`.

Before adding these assets to the release publisher, run the full installation
from a fresh extracted ZIP and disposable external OpenBao and state. Bind the
result to source SHA, producer run, ZIP and image-lock digests. The journey must
use customer-facing authentication and complete issue, present and verify with
no source-tree mounts or skipped cases; record bounded cleanup on failure and
success. Verify image provenance and third-party licenses, sign the final ZIP,
lock, descriptor and evidence, and test anonymous download and installation.

The gate currently fails against v1.1.243 because that release publishes only
Stack manifests, SBOMs, and a transaction. The v1.1.244 passport release is a
separate beta migration gate and does not imply a self-host handoff.
