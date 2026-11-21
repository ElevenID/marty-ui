# Agent trust runtime milestone checkpoint

This integration advances the application work after Marty Protocol PR #38.
It reconciles the existing delegated-authority draft in Marty PR #1994 with
main at `f662bb326bd0a83eb8191dc002bc3db57ec08cc3`, including the accepted
Core JWT 11 dependency alignment. It preserves that existing lifecycle service
and Flow admission implementation.

## Implemented in this application slice

| Milestone area | Deliverable | Qualification boundary |
| --- | --- | --- |
| M01 protocol adoption | Independently pinned optional protocol source, manifest and schema checks | Existing public MIP 0.5.0 and support catalog remain unchanged |
| M01 runtime reconciliation | Delegation workspace integration and Flow persistence guards alongside current issuance-intent protections | Internal composition; no new public delegated route |
| M01 upgrade operations | Read-only database preflight, role separation checks and evidence-preserving upgrade/rollback procedure | No automatic reconstruction of missing historical evidence |
| M02 principal binding foundation | Strict Rust principal/runtime/key/session consistency checks, typed fingerprints and opaque validated output | Authentication, current source state, agent directory and administration remain separate work |
| P03 application lifecycle commands | Atomic grant/journal/original-result persistence, typed caller command identity and authorized historical recovery | Lifecycle commands only; delegated start/finalization are not composed as public commands |

The source pin is Protocol commit
`6126da7619e057be2ff58dd38a5d50f49891d1b3`, with source-pack manifest digest
`3d9fc9475050d80ea2e0a835a3c8cf801a642303a063fa4d3014485ceb6b8d37`.
The source checker does not execute upstream code. Its schema checks are
separate from semantic corpus tests and from production runtime qualification.

## Responsibility boundary

Marty owns identity and authority checks, immutable grants, trust evidence,
challenge/receipt state and recovery of its own committed outcomes. A recovered
grant snapshot is historical evidence; it does not restore expired or revoked
authority and does not authorize another business operation.

Rifare continues to own logical agent definitions, prompts and models, task and
runtime orchestration, domain/resource permissions, business state, budgets,
reservations, provider execution and business outcomes. No Rifare integration
should import private Marty Core code or read Marty storage. Public consumers
must wait for the qualified Gateway contracts that compose these internal
building blocks.

## Remaining application exit gates

The broader milestones are not closed by these libraries and internal service
interfaces. The next application packages still need:

- A tenant-scoped agent/machine directory and authorized lifecycle/admin APIs,
  with owner attribution, enrollment, suspension, retirement and key history.
- Authenticated exact-terms grant approval and independent current authority
  producers, including qualified represented-subject session establishment.
- Qualified workload/proof authentication adapters, source freshness policies
  and production composition of the command authorization/confirmation ports.
- Durable `START_USE` command correlation and retained tenant/verifier nonce
  admission, followed by dedicated `FINALIZE_USE` persistence and managed
  receipt signing. Ordinary Flow finalization remains guarded.
- Gateway hosting, tenant/action authorization, public contracts, clients,
  independent consumer verification and explicit capability qualification.
- Rifare adoption of those public features after the corresponding runtime
  gates pass. This checkpoint changes no Rifare business execution behavior.

See [the optional protocol consumer contract](architecture/agent-trust-protocol-consumer.md),
[principal binding integration](principal-runtime-binding.md),
[the delegation upgrade procedure](delegated-authority-upgrade.md), and
[the delegated-authority service](../rust/services/delegated-authority/README.md)
for the implemented contracts and their limits.

## Validation record

Validation is local, using Rust 1.95 and PostgreSQL 17.12 against the accepted
Core/JWT 11 dependency graph. Hosted GitHub Actions are not part of this work's
evidence.

| Check | Result |
| --- | --- |
| Protocol source consumer | 82 tests; 355 source files verified, 14 selected/transitive schemas, 26 positive and 26 negative schema fixtures |
| Principal binding consumer | 24 regressions and the opaque-output compile-fail doctest; complete external corpus of six valid and 30 invalid vectors |
| Delegated authority service | 122 service tests with PostgreSQL enabled, including atomic commands, expiry/clock bounds, reconnect recovery and the legacy-writer migration race |
| Database upgrade preflight | 42 live PostgreSQL tests, including role separation, drift, preserved history and the exact migrator checksum format |
| Flow compatibility | 97 selected tests, plus explicit PostgreSQL issuance-prerequisite and public-verification regressions |
| Accepted Core dependency boundary | 42 tests |

The final application tree contains locally authored synthetic examples. Exact
private protocol corpora are exercised only through explicitly configured,
independently verified external checkouts. After that fixture separation, the
new synthetic command digest case and external command corpus gate both passed;
production service code and database migrations were unchanged.

The selected default Flow run reported nine existing fixture-gated ignores.
Two relevant PostgreSQL gates were then executed explicitly and passed. The
remaining TLS/OpenBao, retention and separately fenced-role acceptance gates
remain outside this local integration evidence. Full workspace/UI qualification
and production runtime enablement are separate gates. Scoped formatting, diff
checks and the OSS boundary check passed; optional Clippy was not completed.

Existing migration files 0001–0003 retain their original bytes and checksums.
No protocol release, production rollout or public discovery enablement is
implied by this checkpoint.
