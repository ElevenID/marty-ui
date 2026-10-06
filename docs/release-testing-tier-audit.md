# Release E2E tier boundary (2026-10-05)

This is an implementation inventory, not a claim that nightly releases or a
shorter E2E gate already exist. PR, merge-queue, unit, integration, security,
deployment-preflight, and official-release checks remain unchanged until their
owners and evidence consumers are migrated and tested.

## Release identity and entry points

| Owner | Current entry point | Relevant constraint |
| --- | --- | --- |
| `marty-ui` | `prepare-stack-tag.yml` and `cd.yml` | The stack transaction accepts only stable `vMAJOR.MINOR.PATCH` tags and binds a protected-main SHA, lock, images, checkpoints, and published release. Production promotion has its own approval boundary. |
| `marty-ui` | `e2e-tests.yml` | Manual or `beta-deployed` dispatch requires a successful stack release, exact source/manifest lineage, completed private demo qualification, and maintainer review evidence before the beta lifecycle result is accepted. |
| `marty-ui` | `wallet-conformance.yml` and passport beta acceptance workflows | These consume release/deployment evidence and may include device or protected-environment obligations. A Linux-only nightly does not remove official device or portability evidence. |
| `marty-demo-recorder` | `release-qualification.yml` | Manual or `marty-ui-beta-deployed` dispatch validates the complete portfolio contract against beta; it does **not** execute every journey. `official-private` and `local-private` require supplied deployment evidence, while `historical-bound` does not. Only `official-private` is lifecycle-qualified. |
| `marty-demo-recorder` | `src/cli.js`, `src/automatedPublication.js`, `src/portfolioPublication.js`, `src/youtube.js` | Scenario recording and YouTube staging/promotion are separate CLI/code entry points, not steps in `release-qualification.yml`. The portfolio publication code currently specifies an eleven-demo ordered roster, so it must not be assumed to publish the 12-scenario v3 contract without an explicit migration. |
| `marty-integration-tests` | `integration-tests.yml`, `release.yml`, `official-interoperability.yml` | PR checks run hermetic unit tests; the `v*` release workflow publishes a versioned suite; official interoperability has its own scheduled/manual lanes. Neither is a nightly stack E2E selector today. A nightly tag in that repository would also match `v*` and needs explicit routing. |

The recorder's `portfolio-v3-acceptance-contract.json` lists twelve scenarios,
each with a happy path and one or more failure paths. Treat that as the scenario
inventory, not as proof that all scenarios are already automated or suitable
for nightly. Map every selected journey to an assertion owner and evidence
consumer before changing execution. Recording/video is presentation evidence,
not a substitute for independent behavioral assertions.

The stable stack claim additionally requires a completed successful full Canvas
qualification from the CI workflow's weekly schedule or manual dispatch on
the **same protected-main commit**. If main changes after that run, dispatch CI
again on main and wait for it to complete before preparing the stable tag.
The routine PR/merge-group CI run is not a substitute: it deliberately omits
the pinned historical replays. This release-time gate does not run another
copy of the historical suite on every PR.

## Approved target policy

- Nightly is a distinct, immutable **prerelease** version and tag, not an
  untagged scheduled build of `main`. Use a SemVer prerelease identity such as
  `v1.2.1-nightly.20261005.123456789` with a unique run component; bind it
  to the exact protected-main source, lock, image digests, and deployed stack.
  A retry keeps the same claim identity; it must not move or reuse a tag for
  different bytes. This is a proposed tag shape, not an existing release
  command. It runs owned happy-path E2E/demo assertions on one Linux
  target and emits machine-readable results. It must not create, approve,
  upload, or publish release-bound YouTube recordings.
- Official production is the stable release tier. It retains every applicable
  happy, denial, error, recovery, external-wallet/device, and release-bound
  evidence obligation before promotion. Only this tier may run the recording
  and YouTube publication/approval path. Existing beta/RC or other prerelease
  identities are **not** silently classified as official or nightly.
- Classification must come from a verified release claim/manifest and exact
  tag, not an untrusted dispatch input or a substring match. Missing,
  inconsistent, or unknown tier evidence fails closed. Do not broaden the
  stable transaction's tag regex to route nightly through production CD.

## Safe implementation sequence

1. Define and test an authenticated, immutable nightly claim/manifest and
   unique prerelease tag. Keep stable stack transaction and promotion behavior
   unchanged. Prove retry/resume and conflicting-tag rejection.
2. Split assertion-only nightly intake from the existing recorder qualification
   and beta lifecycle path. Nightly cannot require a dummy recording receipt;
   official cannot accept the shorter nightly result. Bind both to the same
   deployed-release identity and retain real behavioral assertions.
3. Select and justify representative happy journeys from the canonical
   portfolio on one Linux runner. Keep official full-scenario and external
   device/provider coverage. Verify dispatch, manual, retry, and resume routes
   cannot bypass their tier gates or invoke YouTube in nightly.
4. Add end-to-end policy tests and compare actual nightly/official runs before
   reporting a measured speed improvement. A reduced nightly result must
   never be relabeled as complete official release evidence.
