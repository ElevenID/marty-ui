# Installer verification transaction

The Compose installer authenticates release inputs before executing their code
or configuration. Docker digest pinning and Compose configuration validation do
not replace publisher authentication.

One `VerificationTools` instance belongs to one acquisition transaction. The
command creates it before selection/admission checks and passes that same
instance into release or candidate preparation. Ordinary Compose lifecycle
operations consume the prepared, bound artifacts; they do not recreate a
verifier or repeat release authentication for each service.

The shell bootstrap still authenticates the initial operator before executing
it. Its process boundary is intentionally separate: no shell flag or saved
receipt can populate the native verifier's in-memory cache.

## Successful-check reuse

Each native check binds the subject digest and byte count, both signature and
provenance proof digests and byte counts, expected workflow, source commit,
producer run and attempt, and the complete fixed verification policy. The fixed
policy includes repository identity, ref, issuer, hosted-runner restriction,
SLSA predicate, verifier digests and a policy revision covering certificate-output
validation.

On every call, including a cache hit, the installer checks the exact pinned tool
executables, private ordinary-file ownership and modes, canonical paths, size
bounds, and current artifact/proof bytes. It checks the artifact/proof bindings
again before returning. An unchanged successful transaction entry avoids only
the repeated Cosign and GitHub verification subprocesses.

Changed artifact or proof bytes, or different expected identity/policy, cannot
reuse an earlier result. Verifier failures, certificate-policy failures, or
changed inputs during verification never insert a success. A new transaction
starts empty; nothing is serialized, loaded from installation state, or shared
with another process. A byte-identical copy in another valid private staging
directory may reuse the same content-and-policy result.

## Preserved policy

- Cosign verifies the blob with the exact ElevenID workflow identity at
  `refs/heads/main` and GitHub Actions OIDC issuer.
- GitHub verifies the local attestation bundle with the exact repository,
  signer workflow, source ref and source digest, SLSA v1 predicate, and rejection
  of self-hosted runners. Native certificate checks still require the expected
  repository ID, source, workflow, run/attempt and hosted runner; duplicate or
  conflicting identity fields are rejected.
- Admission, channel expiry, candidate authorization, nonce handling, operator
  identity, inventory contents, payload bounds and complete extracted-file
  closure remain independently checked by preparation. Cached signature success
  grants no release admission, resource ownership, recovery or cleanup authority.
- The approved image inventory still comes from the authenticated release
  package and image lock. Existing independent image-provenance checks performed
  by release producers are unchanged. This consolidation adds no OCI-policy
  shortcut or new publisher rule for third-party images.

Every Compose layer and included file must remain inside the authenticated
bundle's complete file inventory. The resolved configuration must still bind
the actual executed immutable images and private dynamic inputs to the selected
release, installation, project and daemon. This cache does not establish those
separate configuration or runtime guarantees.

## Focused regression checks

Run the existing installer-only locked development build with:

```sh
cargo test --locked -p marty-deployment-catalog --lib installer_verify::tests
cargo test --locked -p marty-deployment-catalog --lib installer_release::tests
```

The transaction tests use real private files and the production certificate
parser while replacing only external verifier invocation. They check unchanged
and copied artifacts, changed content and each proof, wrong workflow/source/run
or attempt, tool/certificate failures, in-flight changes, private-file custody,
pinned-tool enforcement, policy revision and transaction lifetime. They also
assert the unchanged standard-tool arguments. These are cache/policy regression
tests; they do not claim cryptographic verification of their synthetic fixtures.

Real signed artifact verification and the integrated rootless Compose tests
remain separate acceptance checks. Local development builds remain unsigned
and do not qualify a published release.
