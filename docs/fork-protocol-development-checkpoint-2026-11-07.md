# Fork and protocol development checkpoint — 7 November 2026

This checkpoint continues **ElevenID Fork and Protocol Implementation Plan,
7 November 2026**. It recovers the development state after the reviewed private
fork adoption and identifies the next bounded implementation work. The plan's
21 work packages are not all complete.

## Recovered foundation

| Repository | Merged foundation | Commit |
| --- | --- | --- |
| Core | [PR 414](https://github.com/ElevenID/marty-core/pull/414) | `11655e38c2dbf69bfa5bc3c873f80c5fad628723` |
| UI / services | [PR 1842](https://github.com/ElevenID/marty-ui/pull/1842) | `bcb2f29ed7b2bac02586827e0357895957e52c87` |
| Verifier | [PR 180](https://github.com/ElevenID/marty-verifier/pull/180) | `ab126edaa4ed381d86d9ee89c4b72ca70b40490d` |
| Authenticator | [PR 83](https://github.com/ElevenID/marty-authenticator/pull/83) | `cf7b40ee4ad2a4cbb6cf5fc95a8beb40a0c71eb0` |

The adopted source revisions are SSI
`63a9bcce3daf6f45d1e38e43cf687738bb02cb53`, the separate linked-data source
`6f86efc1579033e14ff2ad7d115ca0857e16a67f`, SD-JWT
`fbe1e1b2c4bf0d62b0fdf0f47f265ffdaaae1ff2`, isomdl
`fc3aaa2628cd106d4f36f50c957d7f33211f8a5e`, and MMF
`0d3b92b836591934c53875ecae337fb690271698`. Earlier upstream-sync receipts
describe inputs to this adoption; they do not replace these merged consumer
revisions. The consumer manifests and lockfiles remain the authoritative pins.

Before publication, UI main advanced to
`22d398ada79a65d9e9684643b05263e893785dda` through the unrelated Windows renewal
fix in [PR 1843](https://github.com/ElevenID/marty-ui/pull/1843). That main commit
is merged into this continuation; the reviewed signing-boundary patch is
unchanged.

W01–W03 have a merged foundation: reviewed dependency adoption, governed issuer
evidence for the implemented JOSE path, and bounded internal retrieval. This
does not imply every credential family, retrieval adapter, client-discovery
mode, or platform is qualified. Core's verified SD-JWT wallet test is already
registered; it should not be recreated as unfinished W01 work.

## This continuation

| Work package | Current development | Completion boundary |
| --- | --- | --- |
| W05 — verified prerequisites before issuance | Atomic signing authority revalidation, frozen Flow requests, authoritative policy-revision checks and bounded native SD-JWT/DCQL query/subject/key evidence | Full authoritative trust/status/replay evidence and an issuance-owned continuation are still required |
| W14 — verified wallets | Reconcile existing [Authenticator PR 57](https://github.com/ElevenID/marty-authenticator/pull/57) with the merged fork foundation, current APIs and verified receipt/presentation contracts | Source integration and tests; external wallet activation and release qualification remain open |

### W05: current signing authorization boundary

The issuance service previously validated a transaction, performed asynchronous
proof and issuer/lifecycle work, then claimed whichever authorized row existed
under that transaction ID. A concurrent change could replace the dataset or
authorization after validation.

The continuation carries the original admitted transaction and any linked
authorization session to the repository. Under row locks, the repository checks
the unchanged transaction, tenant, bearer binding, session association and live
expiry before claiming `authorized` to `signing`. The selected issuer resolution
remains separate from that original authority. Same-target concurrent recovery
must pass the same live-authority gate and must not return a credential for a
different dataset. Exact legacy deterministic session bindings remain supported.

Behavioral tests cover rejected mutations and recovery. PostgreSQL contract
tests exercise the real row-lock and concurrent-claim boundaries. The existing
CI database-contract runner dispatches the entire `credential_postgres_contract`
target with `ISSUANCE_POSTGRES_TEST_URL`; it must execute those new cases, not
merely compile a test binary or return from tests with no database configured.

This change does not introduce canonical prerequisite evaluation, persist a
proof-to-subject/dataset continuation, or atomically check a prerequisite policy
revision. In particular, the existing asynchronous Canvas readiness check does
not establish that broader policy guarantee.

### W05: policy and request binding continuation

Flow now freezes the saved policy reference and generated Presentation Exchange
and DCQL artifacts at session start. Retrieval uses those artifacts; evaluation
requires the same policy reference from the policy-owned producer. A final
repository comparison rejects a result if the stored request context changed
while evaluation was running, with nonce consumption and callback insertion
rolled back together. The validated reference is retained in the result and
callback decision digest.

[Policy-bound verification](policy-bound-verification.md) describes the service
contract, coordinated deployment, workload mutual TLS, legacy-session restart
behavior and validation. The next bounded producer now verifies one exact
SD-JWT/DCQL query and emits native issuer-scoped subject and holder-key evidence.
[SD-JWT prerequisite evidence](sd-jwt-prerequisite-evidence.md) records the
supported profile, private construction, correspondence and freshness checks.
It does not yet produce the full canonical trust/status/replay record. No
result in this slice grants a single-use issuance continuation or locks a
remote policy revision through credential signing.

### W14: current verified-wallet integration

PR 57 keeps paired remote KMS holder signing and verified receipt storage,
while adopting main's reviewed pins and retired legacy interfaces. This
continuation adds or corrects:

- One Final `credentials` response object, with strict ambiguity, deferred,
  multi-credential, type, format and cryptographic rejection boundaries.
- Frozen inline credential offers so acceptance uses the issuer, configuration
  and grant shown in the native preview.
- Rejection of every present key-attestation requirement until that capability
  is implemented, including an empty requirement object.
- Rust enforcement of the exact optional-disclosure set and authenticated
  credential format, plus the matching Presentation Exchange issuer algorithm.
- Rejection of both raw legacy presentation submission endpoints, including ZK.
- Migration of tests from retired local-key and unverified-storage contracts to
  verified receipts or explicit unsupported outcomes.

The detailed source and acceptance record is maintained in Authenticator's
`docs/verified-wallet-integration.md` and PR 57. That PR remains draft. Required
work includes authenticated verifier/destination handling, complete request
semantics, consent for always-shared signed claims, a governed relationship
between issuance service/configuration and credential issuer, real KMS/device
acceptance, browser migration and regenerated public artifacts. A passing audit
of existing checked-in WASM artifacts does not qualify a new-fork build.

## Next implementation order

1. Finish review and exact-commit gates for the signing boundary and wallet
   integration. Resolve failures; do not bypass protected merge or release rules.
2. Complete the selected SD-JWT/DCQL native producer with authoritative
   issuer/type trust, status and durable replay outcomes in the full canonical
   evidence contract. Bind that evidence to the tenant, issuing template, exact
   dataset and saved policy reference through an issuance-owned single-use
   continuation and expiry. Revalidate and consume that authority at the
   signing boundary.
3. Implement the selected W04 request/client authentication profile and recipient
   consent required by W14. Reject unsupported security parameters explicitly.
4. Complete the first prerequisite-to-issuance workflow against one selected
   credential/template profile, including status/trust behavior from W06 and
   per-credential policy from W09 where that profile requires them.
5. Qualify the supported device and browser matrix with real remote signing,
   then continue the other next-priority W06–W10 profile/status/trust work.

The broader plan still governs the later W11/W13/W15–W18 expansions,
W12/W19/W20 bounded pilots, and W21 measured execution optimization. A fork repin
does not activate those capabilities. No paid service or release is required by
this development checkpoint.

## Validation and review record

Final commit IDs, independent review dispositions, and hosted CI status belong
in the corresponding PRs. The wallet continuation is published in PR 57
at `cfaab632dfe9ee8fbb7221a9c5090a6185e85c0d`, with both independent source audits
complete. Its local gates passed: 58 native Rust tests, pinned bridge
regeneration with no generated-file differences, clean Flutter analysis, 276
Flutter tests with four existing skips, 18 affected tests after review fixes,
three acceptance tests, and a standard JavaScript release build. The existing
public artifact audit also passed within the artifact limits described above.

The signing-boundary continuation has two independent source passes, a successful
locked build of the admission, signing and PostgreSQL contract executables, and
13 passing behavioral tests. Actual PostgreSQL execution remains pending the
existing hosted CI database gate.

The policy/request binding continuation also passed two independent source
audits, 942 selected Rust library/behavior tests (15 explicitly ignored), a
locked build across the seven affected package groups, and strict
workspace/all-target Clippy on the CI-pinned Rust 1.95.0. Descriptor and focused
CI-context checks passed. The shared revision assertions use the existing
contract test target to retain the reviewed migrations build context. Hosted
results and the final published head are tracked in PR 1845.

The bounded SD-JWT/DCQL producer and three hosted integration corrections
passed two new independent source audits. The current locked/offline Rust run
passed 161 library/behavior/contract tests across ten executables, with one
existing disposable-KMS test explicitly ignored. The compile-fail doctest
confirming that query evidence cannot be deserialized also passed. Forty-one
focused Python dependency, Docker-context and descriptor checks passed. These
are current-increment receipts, separate from the preceding 942-test foundation
run and from actual database execution.

The signing-boundary PR must distinguish behavioral test results from actual
PostgreSQL execution. Local environment restrictions that prevent a supported
database instance are a pending CI gate, not a database test pass. Both PRs
require two independent source audits and retain any unresolved activation
conditions in their descriptions.

## Publication handoff and continuation

- Authenticator PR 57 is updated at `cfaab632dfe9ee8fbb7221a9c5090a6185e85c0d`
  and remains draft under its documented external activation gates. All seven
  hosted workflows passed, including 280 Flutter tests, three acceptance tests,
  58 native tests, and unchanged regenerated bindings. Four existing Flutter
  tests are skipped; the scheduled-only scorecard check is also skipped on PRs.
- The user explicitly approved publishing the W05 batch and continuing
  development. The reviewed source is now published on
  `work/w05-atomic-signing-authorization` at
  `67f864ef4a5495eee25d7177b460d901dfc98c9e`, based on main `22d398a`.
  The restored source tree was checked against every reviewed file hash before
  publication; its tree is `e06e5cb730d180d0476ed814952557f8a1e56bf5`.
- The earlier automatic publication-review pause is resolved by that explicit
  approval. [Draft PR 1845](https://github.com/ElevenID/marty-ui/pull/1845) is
  open; actual PostgreSQL execution
  remains a required CI gate before merge. Protected merge and release rules
  continue to apply.
- The following published head, `0a6cc6c7b28413baf4e38261cdc77a3eb7e00edd`,
  added saved-policy identity, frozen generated requests and
  original-instance finalization to the same W05 PR. It reuses the existing
  OID4VP contract and canonical digest owner.
  Its hosted run executed the Flow HTTP/PostgreSQL stale-context regression and
  workspace atomic-finalization database assertions. Three failures remained:
  the forbidden Auth-to-Flow dev dependency, a stale descriptor hash expectation
  and Canvas renewal's historical-schema fixture missing native expiry columns.
  Dedicated serialized database gates were skipped after those failures;
  issuance tests returning early without their database URL were not database
  evidence.
- This development increment fixes those three integration failures and adds
  bounded native SD-JWT/DCQL query, subject and key evidence. It retains the
  existing override API while binding evidence to the effective trust-profile
  identity, and rechecks credential validity and holder-proof freshness after
  asynchronous work. The full canonical trust/status/replay record and
  issuance-owned continuation remain subsequent work. A passed decision alone
  cannot authorize issuance.
