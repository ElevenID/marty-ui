# Beta acceptance follow-up: v1.1.216

## Included behavior and immutable inputs

Beta `v1.1.215` remains published/deployed at source
`1866528ab859ea7007ca34671ad80a62131fd79d`. Its custom Keycloak theme and
organization selection work, but the release-bound KMS recording fails at token
exchange because the deployed claims column is JSON, not the earlier JSONB test
fixture. Its failed partial video, audits and backups remain retained.

This activation includes:

- `#784`: lossless worker result JSON, with the frozen Python oracle and exact
  large-integer persistence regression. No standalone worker cutover.
- `#786`: Canvas JSON/JSONB-compatible deep-link, platform configuration,
  target-upsert and roster-cursor writes, preserving unrelated metadata and
  existing scope/generation fences. Merged `fdcdf7e3b72749db29cb9cef3bf97ad1479075e4`.
- `#785`: JSON/JSONB-compatible atomic token claims, preserving DPoP/non-DPoP,
  HMAC storage, nonce clearing and single-use behavior. Merged
  `895218b408f20922bda741d51886ec0744a0754f`.
- `#787`: one shared Rust validator for lifecycle/wallet release-run lineage,
  supporting current digest-first main dispatch and exact historical tag-push
  evidence while retaining signed-manifest/source/browser/device gates.

The draft was prepared on reviewed combined queue candidate
`28b46b4006ed71f330d10041082fb93f5920bd6d`. All eleven #787 paths match its
reviewed head exactly. Do not make this activation ready or claim a release
until #787's protected queue has landed and its merge content is proven.

Only the aggregate coordinate changes to `marty-ui@1.1.216`; the eligible state
and every immutable component entry remain unchanged. Python issuance `0.1.72`
and the integration `1.2.79` qualification harness remain selected. Integration
`1.2.80` is separately published with a static `1.1.214` pin, to reconcile after
the next aggregate publication. No crypto-owner local commits or incidental
dependency upgrades are selected. Calendar/demo `VERSION` remains `2026.08.0`.

Preliminary authenticated checks on 2026-09-05 found no Git tag, GitHub release
or versioned UI/services/migrations image for `1.1.216`; recent claim records
contained no claim for it. These observations are not a reservation. Repeat
authoritative absence and exact-protected-main checks in the claim workflow.

## Required gates and acceptance

1. Land all prerequisites and this separate activation through maintainer review
   and protected PR/queue checks. Claim only the exact protected-main source.
2. Use the normal digest-first aggregate release transaction. Independently
   verify publication, every asset/checksum, source-bound provenance/signatures,
   manifest, SBOMs and terminal transaction. Never modify or reuse published215.
3. Deploy exact digests through the official beta wrapper, including restored-
   backup migration rehearsals, live native migrations and public/local markers.
   Capture fresh before/after29-container production invariants. The user allows
   beta downtime/forward retries; production deployment is out of scope.
4. Use fresh artifact/attempt paths and the exact reviewed recorder revision.
   Recorder main is not protected under its current GitHub plan; explicitly verify
   the reviewed SHA and completed green checks rather than assuming protection.
   Rerun the unchanged KMS switching demo, full browser/credential lifecycle and
   governed device-evidence acceptance. No response overrides or relaxed checks.
5. Collect source-bound operational samples and evaluate the governed event-
   stream/revocation windows. Two passing215 samples are not full new-release
   soak or proof of token/demo acceptance. Elapsed windows alone do not retain
   superseded Python after complete pre-v1 behavioral/failure/ownership gates.
6. Reconcile the roadmap/static integration pin with the actual publication;
   retire only proven-merged owned branches, retaining failed recordings,
   release transactions, backups and other workers' intended features.

The broader goal remains open: standalone Canvas worker whole-consumer parity
and routing, feature-preserving cleanup, full demos and acceptance soak. This
activation neither deletes reachable Python nor claims those gates complete.
