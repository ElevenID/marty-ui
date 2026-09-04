# Verifier release containment evidence — 2026-08-31

Status: contained; the quarantined marty-ui `v1.1.209` and `v1.1.210`
coordinates are not deployable, the claimed but unwritten `v1.1.211`
transaction is tombstoned, and no beta or production deployment occurred.

This record preserves the registry and workflow evidence discovered while
recovering the verification-image consolidation release order. It distinguishes
an incomplete release attempt from a defective runtime artifact and avoids
reusing a coordinate after any versioned image has been published.

The evidence classification is exact: `v0.1.72` is a valid issuance component,
not a failed verifier artifact; `v1.2.76` is retained held evidence only and
grants no cutover authorization; `v1.2.77` is intermediate evidence only; and
`v1.2.78` is preliminary, non-activating evidence. Public
`marty-integration-tests@v1.2.79` is the independently verified exact-digest
transaction harness. PR `#737` introduced the
candidate producer; its first dispatch occurred only after the later hardening
described below. PR `#741` hardened the producer but retained raw tar-header
offset defects. PR `#744` corrected those specific defects. Producer run
`33465702948`, attempt `1`, was dispatched from exact protected-main commit
`2fa1ffa3b36a0c978a41377dd64ab084bc8fc204` before the trusted consumer landed.
It failed bundle validation with `OCI layer tar is empty` before attestation or
artifact upload, so it supplies no admissible candidate-gate acceptance. The
corrected lane subsequently passed from exact protected-main commit
`7a1e2d6f31a563b33832b46921ec3376cd124113`: producer run `33490549237`,
attempt `1`, and authenticated, inspected consumer run `33491836719`, attempt
`1`, both completed successfully. All 19 language-neutral checks matched and
the Rust-only default-disabled-route check passed. That historical candidate
remains blocked by `canonical.oid4vp-positive-runtime-not-exercised`.
Protected UI PR `#762` subsequently merged the real trusted-positive Rust gate
at `339660c4418f824251edba5c0c5ff27cf27fd1ba`, closing the missing-capability gap.
Protected UI PR `#763` merged the digest-first resumable release transaction at
`4e817b32f6d65f88c763af79e2f07df1eb8a1ce7`. Protected PR `#766` activated the
live `v1.1.211` lock while the example remained held, merging at
`bc4d93fd58e3309be9dc0748becf3d32bbc5e9dd`. Claim run `33896525605`
durably reserved that exact coordinate. Release run `33896763851` failed in
`resolve-transaction` before checkout because `gh run download` omitted
`--repo "$GITHUB_REPOSITORY"`. It created no tag, image, release, or
deployment. Protected recovery PR `#767` repaired the boundary at
`21eacfbbf2039655c0eb46322c1f375ccc6216a5`; tombstone run `33899690771`
terminally sealed the claim in artifact `9947135634`. This separately reviewed
activation selects verified-absent `v1.1.212` rather than retargeting the old
transaction.

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
- Before activation, both marty-ui release workflows were disabled and the
  `stack-release` environment admitted only the inert `release-hold-disabled`
  tag policy. On 2026-09-04 the workflows were enabled and the environment was
  restricted to protected branches, retained its required `burdettadam`
  reviewer, allowed that sole maintainer to review the deployment, and
  continued to disallow administrator bypass. Protected PR `#727` separately
  requires exact `release_state=eligible` in both tag preparation and
  publication.
- Successful claim run `33896525605` retained artifact `9945946292`
  (`stack-release-claim-v1.1.211`) with transaction ID
  `d7f6bee501f68a3e44ede6cf67547f7bdcc033494338cf61b500bf295eaecfd1`.
  Its source is exact protected-main commit
  `bc4d93fd58e3309be9dc0748becf3d32bbc5e9dd`.
- Release run `33896763851` failed before checkout, build, digest checkpoint,
  promotion, publication, or deployment because its pre-checkout artifact
  download relied on repository inference in an empty runner directory. No
  `v1.1.211` public coordinate was written, but the durable claim still makes
  that coordinate non-reusable.
- Protected recovery PR `#767` merged the explicit-repository download and
  stable-LF lock-byte repairs at
  `21eacfbbf2039655c0eb46322c1f375ccc6216a5`. Tombstone run `33899690771`
  retained terminal artifact `9947135634`
  (`stack-release-tombstone-33896525605-33899690771`), preserving transaction
  ID `d7f6bee501f68a3e44ede6cf67547f7bdcc033494338cf61b500bf295eaecfd1`
  and incident-evidence SHA-256
  `485e543f787c6dd7396c77a687523a94d5f839214984cbe1acbcc6ab081eb5c4`.
- The tag, GitHub release, and all three registry coordinates for `v1.1.212`
  were verified absent on 2026-09-04 before this activation change.
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
- Protected integration PR `#414` merged the repository-qualified containerd
  load contract at `bdd3b33b9268ca4c8c3d37126e7c253ec8fce710`. UI PRs
  `#759` and `#760` then pinned that exact harness and made its hardened-floor
  ancestry available to the consumer.
- Protected integration PRs `#415` and `#416` published the immutable
  transaction harness as `v1.2.79` from
  `7d24c73c1ef7e7dfb7e5cf119c6552321e58fa71`. Its source archive is
  `sha256:622e878e47a9c8239160bc2e38fe2423d6fe9843de18e6c953433ccd32a905b7`
  and its SPDX SBOM is
  `sha256:3606d43a02379764b804ad22e29f1426edc66d0b7248152a0c159a947ec0821f`.
- Protected UI PR `#762` merged the real trusted-positive OID4VP Rust runtime
  gate at `339660c4418f824251edba5c0c5ff27fd1ba`. It is packaged but
  deliberately unrouted as a service entry point. No published `marty-ui`
  services digest has exercised it yet.
- Successful producer run `33490549237`, attempt `1`, retained candidate
  artifact `9794047091` (`verification-candidate-33490549237-1`) from exact
  protected-main commit `7a1e2d6f31a563b33832b46921ec3376cd124113`.
  Its OCI archive is
  `sha256:de72b842fa9cdce313776f71fb5d908e396ee2073ed468e8f5979d4cf8dc2bb0`;
  the image digest is
  `sha256:8059aa1f946cdf2c64ff5750eaad18e4ce9685e37d7d1189987593337a2281f9`;
  and the SBOM digest is
  `sha256:de1dc018e631ae53bbbca1cb613dcd2688ff9e5d00dc86414452a76f031ea7cf`.
- Successful consumer run `33491836719`, attempt `1`, retained minimized
  evidence artifact `9794114167`
  (`verification-candidate-evidence-33490549237-1`). Its comparison status is
  `matched_with_runtime_blocker`: 19 language-neutral checks matched, the
  candidate-only `compatibility.default-disabled-routes-absent` check passed,
  and `canonical.oid4vp-positive-runtime-not-exercised` is the sole blocker.

## Containment decision

Versions `v1.1.209` and `v1.1.210` are permanently quarantined and must never be
retargeted, completed, or deployed. Target `v1.1.211` was selected only after
its tag, release, and registry coordinates were confirmed absent; all
coordinates were reverified absent immediately before successful claim run
`33896525605` on 2026-09-04. That claim is immutable even though release run
`33896763851` made no external artifact write. Recovery PR `#767` repaired the
download boundary and tombstone run `33899690771` sealed the claim. This
separate reviewed activation selects fresh absent coordinate `v1.1.212`; the
held example and all component pins remain unchanged. The digest-first
transaction merged by protected PR `#763` remains the only authorized claim
and publication path.

Before the next UI/services artifact write or activating stack write, complete
and test:

1. Preserve the successful read-only, non-publishing producer/consumer evidence
   above. Do not treat it as publication, deployment, or release clearance.
2. Retain the current hardened 19-check portable differential, its Rust-only
   default-disabled compatibility check, and the landed artifact-differential
   gates: trusted-positive OID4VP claim projection, migration idempotence by
   applying the release twice, explicit default-disabled and enabled
   compatibility behavior, and exact candidate/oracle evidence-set comparison
   with only documented language-neutral differences. These candidate checks
   now pass. Protected UI PR `#762` implements the eligible positive OID4VP
   runtime path, but a fresh exact services digest must still exercise it; the
   deterministic fixture contract or an unbound local run is not release
   evidence.
3. Retain the digest-first, resumable release transaction as the sole release
   path. Create the durable draft claim
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

The candidate lane and merged runtime gate reduce prepublication risk but cannot
replace the final test against the exact content-addressed services digest. The
public static integration pin is published only after that immutable digest
exists. Production and persistent self-host remain unchanged.
