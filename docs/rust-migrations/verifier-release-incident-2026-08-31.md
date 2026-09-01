# Verifier release containment evidence — 2026-08-31

Status: contained; the quarantined marty-ui `v1.1.209` and `v1.1.210`
coordinates are not deployable, and no beta or production deployment occurred.

This record preserves the registry and workflow evidence discovered while
recovering the verification-image consolidation release order. It distinguishes
an incomplete release attempt from a defective runtime artifact and avoids
reusing a coordinate after any versioned image has been published.

The evidence classification is exact: `v0.1.72` is a valid issuance component,
not a failed verifier artifact; `v1.2.76` is retained held evidence only and
grants no cutover authorization; `v1.2.77` is intermediate evidence only; and
`v1.2.78` is preliminary, non-activating evidence. PR `#737` introduced the
candidate producer; its first dispatch occurred only after the later hardening
described below. PR `#741` hardened the producer but retained raw tar-header
offset defects. PR `#744` corrected those specific defects. Producer run
`33465702948`, attempt `1`, was dispatched from exact protected-main commit
`2fa1ffa3b36a0c978a41377dd64ab084bc8fc204` before the trusted consumer landed.
It failed bundle validation with `OCI layer tar is empty` before attestation or
artifact upload, so it supplies no admissible candidate-gate acceptance. A
corrected producer run and authenticated, inspected consumer result are still
required.

## Immutable observations

- `marty-ui@v1.1.209` has no GitHub release. Its interrupted release published
  only `ghcr.io/elevenid/marty-ui-oss/ui:1.1.209`, at
  `sha256:c223ee06d86dc85bc960a22aec4328f1e22fb6f38124bc261d38c3c21c0ac995`.
  The corresponding `services:1.1.209` and `migrations:1.1.209` coordinates are
  absent.
- Annotated tag `marty-ui@v1.1.210` peels to
  `4326524a1c6a265bad6f6b46945e248345af0451` and GitHub reports it as unsigned.
  Successful preparation run `33406442463` retained artifact `9763321737` with
  SHA-256
  `a70de185f8d3fa6d0e62af98123af375eaaadd675d756cf02358626737a425fb`.
- Release runs `33406717748`, `33407206697`, `33407461450`, and `33408972797`
  completed cancelled. Before the last cancellation, `build-ui` pushed,
  attested, and signed `ui:1.1.210` at
  `sha256:28f48e7ed885046ae753c1f4eea8855b8769cd166602741a8783cbc3dba64643`.
  The same run retained Docker-build artifact `9764517871` at
  `sha256:85da3af1f128b5fb2784ebba6c22b91cffeeaeee16fd7a205de81e7cb727e3c1`.
  Both that tag and digest remain resolvable. No `services:1.1.210` or
  `migrations:1.1.210` image and no GitHub release exists.
- OCI image tags omit the Git tag's leading `v`; absence checks must use, for
  example, `1.1.210` rather than `v1.1.210`.
- Both marty-ui release workflows are disabled. The `stack-release`
  environment disallows administrator bypass and admits only the inert
  `release-hold-disabled` tag policy. Protected PR `#727` separately requires
  exact `release_state=eligible` in both tag preparation and publication.
- `marty-credentials@v0.1.72` is not a failed verifier artifact. It intentionally
  published only the issuance image, at
  `sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176`,
  with provenance bound to commit
  `85b128a85426b3f5aeaf6f948ba5dfa2836e95d8`. The stack consumes that issuance
  component; skipped PyPI publication is not a stack input. The release remains
  usable unless a concrete component gate fails.
- Credentials adapter-retirement guard PR `ElevenID/marty-credentials#253`
  merged at `cbda2ac7e3376b858c1e8d5d010a304474c659cf`; it preserves the separate
  still-used adapter and does not change the issuance-only `v0.1.72` decision.
- Immutable `marty-integration-tests@v1.2.76` remains the held stack's exact
  bootstrap evidence. Its artifact-scoped checks do not authorize verifier
  cutover.
- Immutable `marty-integration-tests@v1.2.77` is independently verified
  intermediate evidence: it preserves the Python oracle and the rejected Rust
  bootstrap as a bounded negative control, but it does not clear cutover.
- Protected integration PR `#404` packaged the reviewed `#400`-`#403` harness
  lineage as immutable `marty-integration-tests@v1.2.78` at merge commit
  `3baad4b5dbccc720a50ff9ae5a280349180c02a8`. This preliminary harness release
  remains non-activating and explicitly blocked on
  `canonical.oid4vp-positive-runtime-not-exercised`; it does not pin a
  corrected Rust services image or authorize publication or deployment.

## Containment decision

Versions `v1.1.209` and `v1.1.210` are permanently quarantined and must never be
retargeted, completed, or deployed. No future UI release coordinate is selected
or reserved by this record. A coordinate may be selected only after all
prerequisites pass and exact-coordinate absence is confirmed; nothing may be
published through the current direct-tag workflow while the release lock is
held.

Before the next UI/services artifact write or activating stack write, complete
and test:

1. Execute and validate the corrected read-only, non-publishing candidate
   producer from an exact protected-main descendant containing PR `#744`. It
   must build the exact
   services Dockerfile and arguments, export an OCI archive plus
   SBOM/source/config digests, verify the archive and image labels without
   pulling a substitute, and run both the retained Python oracle and Rust
   candidate. Merged producer code alone is not candidate-gate evidence.
2. Retain the current hardened 19-check portable differential, its Rust-only
   default-disabled compatibility check, and the landed artifact-differential
   gates: trusted-positive OID4VP claim projection, migration idempotence by
   applying the release twice, explicit default-disabled and enabled
   compatibility behavior, and exact candidate/oracle evidence-set comparison
   with only documented language-neutral differences. The eligible runtime
   must actually exercise the positive OID4VP path; the deterministic fixture
   contract alone is not runtime evidence.
3. A digest-first, resumable release transaction. Create the durable draft claim
   only after eligibility, tag, environment, and exact no-`v` registry absence
   checks. Push and attest content-addressed images, run the public stack and
   verifier gates on the exact services digest, promote version tags only after
   those gates pass, and publish the manifest/release last. Retry is permitted
   only for the same draft, tag, source, and exact digests. Tombstone a version
   on conflicting coordinates or when safe exact-source completion is no longer
   possible, not merely on a transient pre-write failure.
4. Cancellation-point tests covering failure before image writes, partial
   digest evidence, partial tag promotion, a complete draft, a published
   terminal release, and mismatched existing coordinates.

The candidate lane reduces prepublication risk but cannot replace the final
test against the exact released services digest. The public integration pin is
published only after that immutable digest exists. Production and persistent
self-host remain unchanged.
