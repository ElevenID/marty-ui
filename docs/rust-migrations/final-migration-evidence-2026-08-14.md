# Consolidated Rust migration final evidence

> This document closes wave one. The later nine-workstream aggregate and its
> accepted v1.1.194 beta lifecycle are recorded in
> [Rust migration wave-two final evidence](wave-two-final-evidence-2026-08-15.md).

## Outcome

The technical work in the [Consolidated Rust Migration Roadmap](../CONSOLIDATED_RUST_MIGRATION_ROADMAP.md) is complete at the approved beta boundary. Security-sensitive protocol, cryptographic, policy, verification, status, state-machine, wallet, licensing, DTC, and VDS-NC decisions have one canonical Rust owner. Superseded Python and Dart decision kernels were deleted once implementation-independent behavioral, failure, ownership, packaging, and regression gates passed.

Production and persistent self-host deployments were not changed. Their promotion requires a separate approval using this evidence package.

## Canonical ownership and source composition

The final `marty.rust-migration-composition/v1` report was generated at `2026-08-14T12:57:37.831824+00:00` from clean tracked worktrees. It validated ownership manifest SHA-256 `28e183a29dfc240e42b57170635132854c541ca582c0028ac4f1e87342bd74aa` and reported:

- 19 of 19 governed capabilities in `native-active` state;
- no missing repositories and no dirty repositories;
- all five absent paths are expected legacy-deletion sentinels: the removed eMRTD service kernel, two removed PKD utility copies, and two removed Dart OID4VC parser/test paths;
- no remaining legacy entry is a second decision implementation; retained entries are explicitly classified adapters or orchestration, transport, storage, provider, DTO, UI, or platform code; and
- the gated deletion comparison removed 25 Python files and 4,047 physical Python lines.

The measured revisions were:

| Repository | Revision |
|---|---|
| `ElevenID/Marty` | `b200d497b3238118d21b824ddacd2d0346346052` |
| `ElevenID/marty-authenticator` | `c41ff41da488cea238c9799656378b803ddd73fc` |
| `ElevenID/marty-core` | `36212c03ad9ea0479922707e1a6f24746e7f886d` |
| `ElevenID/marty-credentials` | `939cb492749ec86caf824da71249dc8bfb0e80b9` |
| `ElevenID/marty-subscriptions` | `46ffa2497beba48e4fae3b3feba729ee531a6d07` |
| `ElevenID/marty-ui` | `5abfe0dfe42b68b137a8f40210401011f6eeb022` |

The report can be reproduced with the procedure in [language-composition evidence](language-composition-evidence.md). Generated/vendor/build trees are excluded, tracked worktrees must be clean, and every revision is recorded in the report.

## Implementation and deletion chain

The closing dependency chain included:

- protocol migration and conformance in [Marty PR #39](https://github.com/ElevenID/Marty/pull/39), merged as `725e797d873412f68da08e5ce7774bb24cc9ac4c`;
- native credential revocation propagation in [marty-credentials PR #177](https://github.com/ElevenID/marty-credentials/pull/177), released as `v0.1.60`;
- implementation-independent credential lifecycle coverage in [marty-integration-tests PR #360](https://github.com/ElevenID/marty-integration-tests/pull/360), released as `v1.2.63`;
- Python revocation service/kernel removal in [marty-ui PR #489](https://github.com/ElevenID/marty-ui/pull/489), including 4,866 deleted lines in that workstream;
- immutable stack release `v1.1.171` in [marty-ui PR #500](https://github.com/ElevenID/marty-ui/pull/500); and
- fail-closed beta evidence hardening in [PR #501](https://github.com/ElevenID/marty-ui/pull/501), [PR #502](https://github.com/ElevenID/marty-ui/pull/502), [PR #503](https://github.com/ElevenID/marty-ui/pull/503), [PR #504](https://github.com/ElevenID/marty-ui/pull/504), [PR #506](https://github.com/ElevenID/marty-ui/pull/506), and [PR #507](https://github.com/ElevenID/marty-ui/pull/507).

Behavioral tests exercise published protocols, fixtures, executable artifacts, and public APIs. They do not prove parity by importing, mocking, or inspecting the removed implementation. Missing native backends, malformed values, retired response shapes, missing or ambiguous organization resources, inactive templates/policies, unsupported operations, and invalid trust decisions fail closed.

## Immutable release evidence

The accepted stack release is [`marty-ui v1.1.171`](https://github.com/ElevenID/marty-ui/releases/tag/v1.1.171), built from `eaf14510e470629ba316363781079321ff4d274b`. Its stack manifest SHA-256 is `f53e7bf1fffafb50a2cc0038c59c114673966ccbf1aa467f81fb6a3550eb8b41`.

| Artifact | Immutable digest |
|---|---|
| UI image | `sha256:26a6a1d0adbea32b258f20c8c16357bd3976fd5c15cfe64ee6d2284f98738795` |
| Services image | `sha256:8cd968f238fa4c6c4830a3863014684d00f19cb9db7edce3430458bd7c22054a` |
| Migrations image | `sha256:1820c450e2804c600114e8f92b048aa0c25525abb404becfdaab99313c5e7c90` |
| `_marty_rs` wheel | `sha256:b19a52a43580dcb9a086f12419712e2f27a0ce43aeaa499ed37cd816886d6655` |
| `marty-verification` wheel | `sha256:e2f6b1a0e07b66508bd29291706ef3796bb50d589e93d0686dd45b4ce472907d` |
| `marty-iso18013` wheel | `sha256:2394b917488d792c29f9a950aad40b38b7d3146447c5855991daebec6866282f` |
| Credential issuance image | `sha256:1aedcd5f25ad05fc2eb439f3e3168b9a7a746578ec9a7044c9dffdcbed621876` |

The stack pins `marty-core v0.1.55` at `d40b2f2501fa158ee62ecdf4673a76dd9d008f92`, [`marty-credentials v0.1.60`](https://github.com/ElevenID/marty-credentials/releases/tag/v0.1.60) at `fd7a21c4fc6b93130e9398b00db0b441650e4260`, and [`marty-integration-tests v1.2.63`](https://github.com/ElevenID/marty-integration-tests/releases/tag/v1.2.63) at `0a67f1d68bd196ee66394d80785fb1dfbbd910fd`. Release artifacts and attestations were verified before deployment.

## Beta behavioral acceptance

Beta was updated once to `v1.1.171` and remains pinned to source ID `4edc3fe2f9f2d1e94cfc1af78516b609f00b5446`. No later evidence-tooling merge triggered another beta deployment.

Protected workflow [run 31801875146](https://github.com/ElevenID/marty-ui/actions/runs/31801875146) passed against the exact immutable stack and exercised:

- stack/release/source binding and the public MIP 0.4.1 contract;
- a fresh organization and every credential primitive;
- applicant and membership-badge issuance, logout, and credential login;
- application, template, direct verification, and canonical result parsing; and
- renewal, suspension, reinstatement, revocation, status-list ownership, and cross-organization denial.

The accepted `mip-03-beta-credential-lifecycle` artifact has ID `9219741455` and digest `sha256:3a34268b173f9f674099a8f8fefc5d2264f814e712bcd85bd759cfe70fbbe352`. Its reports are release-ready, with renewal accepted, suspension denied, reinstatement allowed, revocation denied, status-list ownership confirmed, cross-organization access denied, zero unexpected responses, and zero page errors.

Earlier evidence-tooling failures were corrected by PRs #501–#507. Two canceled attempts produced no behavioral verdict because browser/runner setup stalled; the accepted protected run completed the full suite.

## Deployment boundary

This evidence closes implementation phases 0–9 and authorizes deletion under the pre-v1 policy. It does not authorize production or persistent self-host changes. Rollback remains selection of a previous immutable image; there is no Python or Dart runtime fallback. A production promotion proposal may reference this package, but promotion must be separately reviewed and approved.
