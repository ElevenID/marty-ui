# Architecture and development-feedback improvement tracker

Created: 2026-10-02 (America/Denver; baseline CI completed 2026-10-03 UTC).
Status: active implementation (2026-10-10 00:26 UTC checkpoint). Gateway and
Canvas acceptance ownership, narrow compatibility code, and fast test layers
have merged. Recent UI #1129–#1131 brought Canvas configuration fail-fast,
phase timing, and Bookworm-first reusable test compilation. The protected
Canvas job changed from 51m36s before #1131 to 31m57s on its merge candidate;
only the removed duplicate compilation is clearly attributable to that
refactor. UI #1132–#1139 added shadow-only dependency observations and bounded
PR feedback selection; #1141 added public-vector execution proof, #1142
added exact protocol-test source ownership, and #1144 guarded current Canvas
REST capture inputs. UI #1148 added fixed Canvas probe-timing owners, and
#1150 moved the pinned HTTPX timeout matrix to exact-main full qualification
while routine CI keeps one TLS timeout and one certificate-rejection proof.
The protected #1150 database step took 10m28s versus 12m30s on the preceding
protected run; full exact-main qualification passed. #1151 added eight exact
root pytest source owners without removing a check; its protected run passed.
#1152 added merge-group historical-input observations without changing gate
selection. #1153 reused isolated schema clones for 22 Canvas repository cases;
PR and protected CI passed, with 20 fewer repeated container/migration cycles.
The hosted wall-time runs vary too much to attribute a pipeline saving yet.
UI #1186, #1187, and #1189 and Core #354 have merged; #1189's first fresh
full-main REST attestation passed on its merge commit but authorizes no test
skips or exact-current-main release qualification.
Full protected checks remain. The separate roster component draft is deferred
for lifecycle/qualification reasons. Core #352
merged its authenticated presentation-proof API and #353 its narrow digest
crate, but UI migration and nightly release qualification remain incomplete.
Earlier failed main evidence remains ineligible for release/reuse. UI #1201's
fourth-file worker-only pilot and #1202's dedicated self-host acceptance owner
are now merged after protected validation. Historical checkpoints below are
not current merge-status claims.

October 9 delivery checkpoint: UI #1205 moved the nine Flow admission and
consumer cases to a dedicated acceptance owner without dropping the 139-case
Linux Canvas/Flow roster. UI #1206 merged the exact eight-file, fail-closed
Flow PR selector; #1207 proved its selected Flow lane with nine real cases and
then passed full protected merge-group qualification. The #1207 PR reached its
gate in 11m01s, of which the Flow job took 10m35s (9m24s compile, 23s database
step). This is observed faster feedback for that exact test-source class, not
an attributable full-pipeline saving. Main's one-reviewer rule was restored
after each temporary self-merge exception.
UI #1208 has since merged its Auth-to-Applicant shadow-edge witness and a
bounded synthetic renderer-test deadline correction; the full protected
Canvas, contracts, image, release, and security checks passed. It changes no
runtime behavior or service-package selection. The broader dependency input
graph remains incomplete.
UI #1209 moved the existing synthetic renderer deadline/output proof to an
image-free exact case before image/database setup, retaining both real
rendered-process cases. Its PR and protected merge-group CI passed; the
one-reviewer rule was restored after merge. This is earlier diagnostic
feedback and duplicate-probe cleanup, not a measured full-job saving.
UI #1210 repaired Gateway's base-Compose Verification address and guarded all
15 configured upstream addresses. Its full PR and protected merge-group checks
passed; main's one-reviewer rule was restored. This is deployment correctness,
not a CI speedup.
UI #1211 retained two timing-sensitive published Canvas worker references but
serialized them after observed shutdown-bound failures under parallel load.
UI #1212 repaired the oracle Kubernetes Gateway Signing Keys binding and
guarded its parsed ConfigMap/container environment. Both passed full PR and
protected queue checks and merged; main's one-reviewer rule was restored and
verified. These are reliability and deployment-correctness changes, not
measured CI speedups.
UI #1216 and #1217 have now merged the bounded Kubernetes policy test-source
lane and its first exact-source pilot. UI #1218 merged exact-digest Docker Hub
mirror/cache fallback with all required PR and protected checks; it addresses
registry-throttling reliability, not a measured CI speedup. The protected
one-reviewer rule was restored after the merges.
UI #1220, #1222, and #1223 then merged provider-app reuse and JSON-depth
timing, a Gateway-to-Credential-Template shadow edge, and the status-provider
native-seed fixture. All passed exact-head and protected merge-group checks;
main's one-reviewer requirement was restored and verified after #1223.

## Objective and scope

Reduce the amount of unrelated code and infrastructure needed to validate a change. Establish independently testable Rust boundaries, select checks from their actual dependencies, and report failures earlier while preserving behavior, features, security guarantees, and release qualification.

The user authorized implementation of the investigated improvements, requires self-review and regression prevention, and prefers reuse of Rust code following DRY. All repositories are eligible for a justified change; the evidence currently prioritizes `marty-ui`, with a smaller selector/preflight follow-up in `marty-core`. Repository creation, service deployment splits, and broad framework replacements are not prerequisites.

The October 7 product-packaging and integration plan is now part of this active
work, not a competing CI plan. Its product-level work IDs remain the source of
truth for distribution, integration, consumer, and commercial acceptance; this
tracker coordinates their implementation with A0-A8. The consumer audit was
made against release v1.1.230 and source revisions older than current main, so
each defect and dependency must be rechecked against the implementation base.
Private business sources and unapproved pricing/marketing claims are not
copied into this repository or turned into engineering decisions.

This document coordinates the new architecture work. [The original build audit](rust-build-audit.md) and [its evidence](rust-build-audit-evidence.md) remain historical records of earlier optimizations. Those completed changes must not be reimplemented.

## Evidence baseline

The investigation inspected UI main `8ad6c73f2b44d1a23feecc7754f1284d64655e66`, Core main `73f6d5898b2147d0ab4f7cca318c76006a2fa3d6`, and MMF main `c55d323e6aa64cad4f49308792f1d21eaab0ebc8`. Refresh these revisions before implementing each PR; this evidence baseline is not an implementation base.

| Observation | Evidence and consequence |
| --- | --- |
| Canvas acceptance took 61m40s; other Rust contracts took 12m29s | [Protected UI run 37077519687](https://github.com/ElevenID/marty-ui/actions/runs/37077519687). Passport image: 9m59s; release contracts: 8m06s; Rust lint/packaging: 7m26s. These parallel jobs must not be added together. |
| The Canvas lane combines multiple sequential responsibilities | Compilation 6m25s; Bookworm compilation 9m43s; public image 12m06s; preflights 8m09s; main database-backed group 23m20s. Separating test execution alone does not eliminate its build prerequisites. |
| A nominal Canvas executable also owns system acceptance | [`canvas_published_schema_contract.rs`](https://github.com/ElevenID/marty-ui/blob/8ad6c73/rust/services/issuance/tests/canvas_published_schema_contract.rs) includes self-host, Kubernetes, Envoy, DIDComm, renewal, and Flow composition. |
| Issuance is a broad compilation boundary | Approximately 124,000 lines under `rust/services/issuance/src`, including embedded tests; approximately 55,000 in Canvas-prefixed modules and 12,500 in passport-prefixed modules. Its manifest has 60 normal and 20 development dependencies. Size is supporting evidence, not a timing measurement. |
| Tests couple neighboring service implementations | Gateway and issuance have mutual development dependencies; issuance tests also depend on Flow, signing keys, and packaging crates. These are test edges, not proof of a production dependency cycle. |
| UI selection is coarse | [`ci.yml`](https://github.com/ElevenID/marty-ui/blob/8ad6c73/.github/workflows/ci.yml) enables both Rust lanes for all Rust/proto/contract changes and sets `all=true` for merge groups. Both lanes compile the workspace. |
| Declared Cargo dependencies permit narrower candidates | Local manifest analysis found notification's reverse dependency closure contains only notification, out of 23 packages. Runtime/API/deployment consumers must also be mapped before omitting acceptance checks. |
| Core's selector is not sufficient as a sole gate | [`ci_affected_packages.py`](https://github.com/ElevenID/marty-core/blob/73f6d58/scripts/ci_affected_packages.py) follows package dependencies, but a local fixture-path probe selected nothing for JSON changes; its Git diff excludes deletions. Full gates still provide broader coverage. |
| Historical and native verification are distinct | Timeout tests separately reproduce frozen Python observations and run native worker scenarios against the recorded corpus. Their input closures differ and should be tracked independently. |
| Other repositories are not established priorities for restructuring | Latest sampled successful MMF CI was about five minutes and integration-repository hermetic CI about 90 seconds. Core PR CI was about 17.5 minutes, including a 14m23s preflight. These are different runs/workloads, not comparative benchmarks. |

No speedup is promised from crate size or static graph inspection. Preserve before/after evidence from normal validation; use a small local experiment when it resolves a specific design uncertainty.

## Implementation queue

Statuses: `planned`, `investigating`, `implementing`, `review`, `CI`, `merged`, `deferred`. A deferred item needs an evidence-backed reason, a retained safety guarantee, and an explicit disposition; it must not silently disappear from the goal.

| ID | Work and intended result | Dependencies | Status | Owner / PR / evidence |
| --- | --- | --- | --- | --- |
| A0 | Inventory test obligations and their inputs; identify effective execution, owning package, runtime dependencies, and current gate | None | investigating | [UI #1073](https://github.com/ElevenID/marty-ui/pull/1073), [#1075](https://github.com/ElevenID/marty-ui/pull/1075), [#1076](https://github.com/ElevenID/marty-ui/pull/1076), and [#1079](https://github.com/ElevenID/marty-ui/pull/1079) merged the Canvas producer, embedded-input, scenario-owner, and scenario-input safeguards. [#1110](https://github.com/ElevenID/marty-ui/pull/1110) merged the preparer-dispatch inventory; [#1122](https://github.com/ElevenID/marty-ui/pull/1122) added public-vector source guarding, and [#1141](https://github.com/ElevenID/marty-ui/pull/1141) proved the 23 declared Rust test owners executed in protected CI. [#1130](https://github.com/ElevenID/marty-ui/pull/1130) and [#1131](https://github.com/ElevenID/marty-ui/pull/1131) added Canvas/ordinary-DB phase timing evidence. Remaining runtime/selector and acceptance obligations still need mapping. |
| A1 | Move cross-service/system tests into a dedicated workspace acceptance package; separate deployment/packaging, DIDComm/renewal, and Canvas groups | A0 | implementing | [UI #1044](https://github.com/ElevenID/marty-ui/pull/1044), [#1058](https://github.com/ElevenID/marty-ui/pull/1058), [#1081](https://github.com/ElevenID/marty-ui/pull/1081), [#1083](https://github.com/ElevenID/marty-ui/pull/1083), and [#1086](https://github.com/ElevenID/marty-ui/pull/1086) established and parallelized the Canvas acceptance targets; [#1108](https://github.com/ElevenID/marty-ui/pull/1108) merged eleven base-runtime/self-host support moves and [#1111](https://github.com/ElevenID/marty-ui/pull/1111) merged eighteen Flow/DIDComm/renewal/Kubernetes support moves. [#1118](https://github.com/ElevenID/marty-ui/pull/1118) merged Gateway-to-Issuance PostgreSQL webhook ownership; [#1121](https://github.com/ElevenID/marty-ui/pull/1121) merged all six Gateway-to-Signing Redis/OpenBao cases with their exact gates, removing the last service-to-service development dependency in UI service manifests. [#1123](https://github.com/ElevenID/marty-ui/pull/1123) merged the separate Canvas acceptance package after protected validation. |
| A2 | Extract one small domain/compatibility boundary from issuance, preserving public behavior and reusing existing Rust implementations | A0; coordinate moves with A1 | merged | [UI #1045](https://github.com/ElevenID/marty-ui/pull/1045), `7502053e9`; protected queue run passed and merged as `d9947b312` |
| A3 | Harden Core selection and implement conservative UI affected-check planning in shadow mode | A0; map A1/A2 changes | implementing | Core [#348](https://github.com/ElevenID/marty-core/pull/348) and UI [#1046](https://github.com/ElevenID/marty-ui/pull/1046), [#1047](https://github.com/ElevenID/marty-ui/pull/1047), [#1051](https://github.com/ElevenID/marty-ui/pull/1051), and [#1052](https://github.com/ElevenID/marty-ui/pull/1052) established the fail-closed shadow planner. [#1109](https://github.com/ElevenID/marty-ui/pull/1109) merged nine source-backed non-Cargo service-consumer edges; [#1117](https://github.com/ElevenID/marty-ui/pull/1117) added Trust Profile-to-Presentation Policy. [#1132](https://github.com/ElevenID/marty-ui/pull/1132) merged nine further observed control-plane edges into Issuance, Credential Template, and Verification. [#1133](https://github.com/ElevenID/marty-ui/pull/1133) merged four Flow HTTP reference observations; [#1135](https://github.com/ElevenID/marty-ui/pull/1135) merged Organization gRPC membership consumers. All remain shadow-only. Service changes continue to select the full Rust workspace; the complete non-Cargo graph remains unmapped. |
| A4 | Assign overlapping case matrices to the lowest adequate test level, retaining real adapter and process guarantees | A0; use A2 where appropriate | implementing | Pure Python-value extraction [UI #1060](https://github.com/ElevenID/marty-ui/pull/1060), mixed-roster/body-reader unit coverage [#1100](https://github.com/ElevenID/marty-ui/pull/1100) and [#1102](https://github.com/ElevenID/marty-ui/pull/1102) merged. [#1112](https://github.com/ElevenID/marty-ui/pull/1112) moved pure self-host fixture controls and an Envoy scalar-value matrix to fast owners; [#1124](https://github.com/ElevenID/marty-ui/pull/1124), [#1126](https://github.com/ElevenID/marty-ui/pull/1126), and [#1127](https://github.com/ElevenID/marty-ui/pull/1127) added layered worker/configuration and typed-transport owners. Real CLI, ZIP, Compose, Envoy-image/process, database, and published-process guarantees retain their acceptance owners. |
| A5 | Separate historical oracle qualification from native regression testing; define complete reference inputs and evidence validity | A0, A1 | implementing | Provenance, producer, scenario, and input safeguards [UI #1050](https://github.com/ElevenID/marty-ui/pull/1050), [#1055](https://github.com/ElevenID/marty-ui/pull/1055), [#1073](https://github.com/ElevenID/marty-ui/pull/1073), [#1076](https://github.com/ElevenID/marty-ui/pull/1076)–[#1079](https://github.com/ElevenID/marty-ui/pull/1079), and [#1082](https://github.com/ElevenID/marty-ui/pull/1082) merged. [#1102](https://github.com/ElevenID/marty-ui/pull/1102) moved 33 pinned historical replays to weekly/manual full qualification while retaining native regression; [#1106](https://github.com/ElevenID/marty-ui/pull/1106) requires exact-main full qualification before stable tagging. [#1110](https://github.com/ElevenID/marty-ui/pull/1110) guards preparer dispatch; [#1112](https://github.com/ElevenID/marty-ui/pull/1112) guards Canvas helper mount inputs. Neither establishes complete historical reference closure or authorizes additional qualification skips. |
| A6 | Enable proven selective validation and earlier failure reporting; validate the assembled result on protected main/release paths | A1-A5 review and evidence | implementing | [UI #1064](https://github.com/ElevenID/marty-ui/pull/1064) retained fail-closed planned-skip and all-success merge-group gates; [#1080](https://github.com/ElevenID/marty-ui/pull/1080), [#1082](https://github.com/ElevenID/marty-ui/pull/1082), and [#1107](https://github.com/ElevenID/marty-ui/pull/1107) proved initial exact-input selection. [#1110](https://github.com/ElevenID/marty-ui/pull/1110), [#1112](https://github.com/ElevenID/marty-ui/pull/1112), [#1119](https://github.com/ElevenID/marty-ui/pull/1119), and [#1127](https://github.com/ElevenID/marty-ui/pull/1127) added bounded test-only paths; [#1114](https://github.com/ElevenID/marty-ui/pull/1114) preserves failed timing-artifact upload as a failing job after one same-job retry. [#1129](https://github.com/ElevenID/marty-ui/pull/1129) moved two required Canvas configuration proofs earlier while retaining late checks. [#1131](https://github.com/ElevenID/marty-ui/pull/1131) measured a 12m20s compile-stage saving by removing duplicate compatible compilation. [#1134](https://github.com/ElevenID/marty-ui/pull/1134) routed exact shadow-planner-only PR inputs to their release owner, and [#1135](https://github.com/ElevenID/marty-ui/pull/1135) measured a 10m56s scoped PR run versus 39m50s for #1134's full-matrix PR; protected #1135 still ran all 23 jobs. This is observed scoped feedback, not a whole-repository average or faster Canvas execution. Unknown/mixed implementation inputs remain broad. |
| A7 | Evaluate and, where justified, separate Core's cheap preflight feedback from extensive feature/security validation | A3; independent scoped follow-up | deferred | Independent Core dependency PRs now show mixed critical paths: preflight was last for UUID but affected tests were last for cc. The expensive KMS/EUDI steps share Cargo inputs on one runner; splitting without reuse would duplicate setup/compilation and has no demonstrated gate saving. Keep the feature/security matrix and re-evaluate only with a proven artifact-reuse or fail-fast design. Exact runs and step timings appear in the A7 refresh below. [Core #350](https://github.com/ElevenID/marty-core/pull/350) removed a duplicate EUDI invocation without a claimed whole-pipeline saving. |
| A8 | Split release E2E by verified release tier: nightly prerelease happy paths on one Linux target; stable official releases keep complete happy/error evidence; YouTube recording/publication only for official releases | A0, A4, A5 | implementing | Separate immutable nightly prerelease tag selected by the user. [#1106](https://github.com/ElevenID/marty-ui/pull/1106) merged the release-owner inventory, fail-closed tag grammar, and exact-main stable qualification gate. [#1113](https://github.com/ElevenID/marty-ui/pull/1113) merged a read-only nightly-claim preparation step; [#1127](https://github.com/ElevenID/marty-ui/pull/1127) merged typed OID4VP/verification transport, not signed-presentation trust or nightly E2E qualification. Neither creates qualified nightly deployment nor relaxes official E2E/YouTube gates. |

Batch related, independently reviewed changes into one coherent PR when they share an owner and validation path, so the full PR and protected-queue runs are paid once per batch. Keep targeted local checks and explicit test-ownership evidence for each slice. Avoid a PR that simultaneously moves tests, changes their assertions, and reduces their triggers; such changes need separate proof even when bundled. Do not push documentation-only follow-ups that restart a running PR unless they correct a release-blocking defect.

2026-10-06 local A0 candidate (not yet merged or qualified): `contracts/canvas-worker-tier-obligations.json` records exactly 33 historical-reference worker cases and four preflight-capable native cases from `marty-canvas-acceptance` / `canvas_published_worker_contract`. The 37 routine `full-after-preflights` skips comprise 33 historical replays, two timeout/lease native preflights already executed in the same run, and two mixed-roster/body-timeout native matrices excluded from the routine tier. All four native cases run as preflights in weekly/manual full qualification, then are skipped only in that later target invocation with same-run proof. Each named case has a unique assertion summary; the inventory identifies its Rust target/source, tier, test layer, independent-oracle role, cheapest proving layer, common inputs and case corpus/scenario or preflight inputs. The existing producer/scenario/import manifests bound the named files, not complete transitive runtime or historical-capture provenance. The additive runner guard compares this narrow inventory with the compiled worker `--list` before selection, then checks exact selected IDs from the existing libtest-filtered list. Missing, extra, duplicate, or same-count substituted cases fail closed; `--list` proves discovery and selection, not execution. Existing run-bound preflight evidence, invocation/skip commands, count checks, and protected gates remain unchanged. This slice is incomplete A0/A8 coverage: the other Canvas tests, service acceptance targets, release-stack cases, and non-Cargo consumers still require explicit obligation mapping. Do not derive additional skips or a nightly qualification claim from it.

2026-10-06 refreshed A8 checkpoint: Core [#352](https://github.com/ElevenID/marty-core/pull/352)
merged at 06:06:38 UTC as `d949f65362b63157e4e4ecee23ea4610a6411089` after
protected validation. Its additive authenticated presentation-proof API had 43
targeted tests passing and two pre-existing ignored cases. The integration wallet
same-key signed-VP helper remains a locally reviewed unpublished draft (`a847`,
25 targeted tests passed). UI typed VP/submission/query and credential-trust
integration remain incomplete. Existing `OpenBadgeLogin` bearer/holder-binding
defaults remain unchanged; a new holder-key requirement is not implied by this
maintenance work. Neither the merged Core prerequisite nor the wallet draft
establishes nightly qualification or a measured pipeline speedup.

2026-10-05 checkpoint: [#1100](https://github.com/ElevenID/marty-ui/pull/1100) and [#1102](https://github.com/ElevenID/marty-ui/pull/1102) added owned mixed-roster/body-reader tests, retained native timeout/lease checks on routine CI, and moved 33 pinned historical process replays to weekly/manual full qualification. [#1106](https://github.com/ElevenID/marty-ui/pull/1106) merged the requirement for successful full qualification on the exact main SHA before stable tag preparation; a new main commit requires a new full run. The nightly release path is not yet implemented, and no nightly speedup is claimed.

2026-10-06 reconciliation: [#1108](https://github.com/ElevenID/marty-ui/pull/1108)–[#1114](https://github.com/ElevenID/marty-ui/pull/1114), [#1117](https://github.com/ElevenID/marty-ui/pull/1117)–[#1121](https://github.com/ElevenID/marty-ui/pull/1121) merged. #1119 passed protected retry run `37408292483` and merged as `7ed056861`; #1121 passed protected run `37410984877` and merged as `13afdf04e`, with all six moved signing cases explicitly passing. [#1122](https://github.com/ElevenID/marty-ui/pull/1122) passed full PR run `37411619146` and is in protected validation at this checkpoint. The separate Canvas package and fresh startup evidence in this batch are pending. Ownership changes and the read-only nightly claim are not evidence of measured feedback speed or qualified nightly releases.

### A0: obligation and dependency inventory

Record each test group, its behavior/security obligations, owner, fixtures, environment switches, executable/image inputs, and required gate. Account for helper/child tests, ignored tests explicitly invoked elsewhere, and tests that return early without configured services. A matching test count alone does not prove matching execution.

The current Canvas runner (`scripts/ci/run-published-canvas-contracts.sh`) explicitly checks 165 named tests in its single `canvas_published_schema_contract` executable before the full run; 92 names begin `worker_`, and the rest span operations, DIDComm, renewal, Flow, status, self-host, Kubernetes, Envoy, and helper/child protocols. This list is a mandatory discovery/coverage guard, not merely documentation. A future split must move the relevant names and exact child invocations together; replacing it with a total test count would lose that guarantee. Repeated `--list` process launches are a small mechanical inefficiency, but do not dominate the measured ~60-minute lane, so keep the architectural split ahead of that micro-optimization.

Top-level CI gate census (2026-10-03): `.github/workflows/ci.yml` defines `changes` plus unconditional Python lint, UI fast feedback/crawler-build/crawler-Nginx/four test shards/lifecycle browser, Python services, passport-fence PostgreSQL, Rust feature probe/passport image/Canvas and contracts service matrix/lint and packaging/service images/supply chain, public protocol, release contracts, and security. `ci-gate` depends on 18 preceding job IDs on current main; the earlier 16-job count predates the feature-probe and passport-image additions. On PRs it accepts each result only as `success` or `skipped`; on merge groups it requires `success` for every dependency. This topology means a selective rollout cannot simply omit a job or infer success from a skipped lane: it must preserve the required aggregate's explicit treatment of planned skips versus unexpected absence and retain merge-group full validation. The current `changes` outputs are only broad UI/Python/Rust/release/verification/security classes, not obligation-complete per-group inputs. The Rust planner is shadow-only and cannot authorize a change to this gate.

Aggregate-skip baseline caveat (2026-10-03, before #1064): the PR branch of `ci-gate` looped over `needs.*.result` and accepted every `skipped` result, without proving that the skip matched `changes` outputs or a documented obligation map. It checked result vocabulary, not planned-versus-unexpected skip identity. #1064 subsequently added the exact expected-result checks while retaining merge-group all-success behavior; future selection changes must keep those guarantees.

A6 gate-safety follow-up [UI #1064](https://github.com/ElevenID/marty-ui/pull/1064) maps all 18 existing `ci-gate` dependencies to their PR classifier selectors and fails when a selected lane skips, an unselected lane runs unexpectedly, an unconditional lane fails, or a selector is missing. Protected merge groups still require every lane to succeed. Synthetic tests exercise all flag classes, both event modes, missing selectors, unexpected skips/failures, and dependency-count drift. An independent reviewer cleared the corrected head. Full PR and protected combined-head CI passed, including live Canvas and the final gate; despite an earlier manual queue removal, #1064 subsequently merged as `1904801e0`. This safety prerequisite does not itself enable any new skip or demonstrate a speedup.

Security-lane input check (2026-10-03): `security` is selected by the broad security classifier and runs Python dependency audit, Bun and npm UI/test audits, plus report-producing Bandit and Semgrep; `rust-supply-chain` is selected by the Rust classifier and checks advisories, bans, licenses, and sources through `cargo-deny`. The merge-group classifier sets `all=true`, and the aggregate gate requires every dependency to succeed there. This is an owner/trigger inventory, not proof that either lane can be narrowed on PRs; their lockfile, scanner configuration, and cross-language input closure still need mapping before A6 selection changes.

Public-protocol A0 inventory (2026-10-03): the `public-protocol-contract` job checks the pinned Marty-Protocol revision, installs Python contract dependencies, and runs `check_gateway_public_protocol_contract.py`. Its direct inputs include the pinned protocol schemas/metadata, gateway DTO and discovery/trust/issued-credential contract JSON, generated bindings, public-boundary documentation, two trust-configuration UI files, and Rust service source. The check compares protocol version and DTO fields, rejects named private-field leaks, and checks generated/documented boundaries. Its behavior-vector guard only searches all service `.rs` source text for each JSON filename; it does **not** itself prove that a Rust test executed the vector. Actual Rust test ownership and any path-selective trigger therefore require separate evidence. The job runs for UI/Python/Rust/release changes and remains a required `ci-gate` dependency; do not narrow those triggers from the filename search alone.

Public-protocol vector ownership follow-up (2026-10-05, `main` at `a98d7b766`): the source-reference guard covers 21 `gateway-*-behavior.json` files plus `credential-metadata-behavior.json` and `vc-api-adapter-behavior.json`. Rust references are in the Gateway service's library tests, Signing Keys library tests (issuer context/identity, signing authorization, Flow key envelope), Deployment Profile library test, and Issuance's explicitly registered `didcomm_delivery_behavior` integration target. Some tests load vectors through `contract()` helpers; the DIDComm vector also appears in a production `include_bytes!`, so filename presence alone cannot establish test ownership. The `test-rust-services` contracts lane compiles workspace test executables and runs `cargo test --locked --workspace`; that is the CI execution owner for non-ignored Rust tests, separate from the Python-only `public-protocol-contract` job. This inventory does not prove each vector's cases execute on every selected change: the broad Rust selector and actual Cargo result are required, and per-vector dynamic coverage would need separately justified evidence. No job selector, test set, or gate is changed here.

Release-contract A0 inventory (2026-10-03): `test-release-contracts` runs on release, verification, or Rust changes. It verifies digest-pinned released Core/Verification/ISO18013/Common wheels and a fixed Credentials v0.1.76 source/image, exercises released mdoc binding behavior and OSS commerce policy, replays the Canvas mirror reference in that exact image, runs `python -m pytest tests -v --tb=short`, then proves the pinned OCI archive/backend and DIDComm/retention release compatibility. On UI #1061 the repository-test step took 405 seconds of the 7m58s job. The separate `test-services` job runs `pytest` with `working-directory: services`, not the root `tests` tree, so these two steps are not duplicate collection of the same files. The release job is not the current Rust critical path (Canvas remains longer), and its released-artifact/environment obligations are distinct. Do not split or remove its broad test step until exact case ownership and Rust-change trigger coverage are mapped.

Release-test timing candidate (2026-10-10): local collection with `PYTHONPATH=packages` found 6,197 root cases in 1.36 seconds; only 22 are under `tests/unit`, which is a directory label rather than an execution-cost or obligation classification. A Windows attempt to run the 227-case Canvas published-preflight module was stopped after it did not finish promptly; no duration or failure conclusion follows from that interrupted attempt. The existing full release-test step now requests pytest's 20 slowest durations in its normal log, with the same collection, assertions, exit status, and required gate. Use hosted case/setup timing before proposing a root-suite split; this instrumentation alone claims no speedup.

Browser-lifecycle A0 inventory (2026-10-03): `test-credential-lifecycle-browser` runs for UI changes and is a required `ci-gate` dependency. It installs pinned API Core/Blog tarballs by digest, UI and Playwright dependencies, and pinned Chromium; verifies production CSP restrictions, runs the public-demo browser gate, then runs `playwright.applicant-wallet.config.js`. That focused config selects the applicant wallet-selection and MIP03 specs, launches the real Vite console app, and mocks backend calls at the browser network boundary. It excludes the neighboring `application-flow.spec.js` by `testMatch`; the gate is therefore browser UX/CSP evidence, not a full-stack service/process acceptance substitute. Any future selective trigger must account for UI source, test/config scripts, dependency locks, tarball digests, and browser/runtime inputs as well as the two selected specs.

Crawler/UI A0 inventory (2026-10-03): all three UI job families are selected by the broad `ui` classifier, but carry different obligations. `test-ui-crawler-artifacts` bootstraps digest-verified released API Core/Blog tarballs, checks crawler configuration and validator unit tests, then builds and validates both the normal prerendered public site and the `DISABLE_PRERENDER=1` production-image mode; it compares their crawler URL sets. `test-ui-crawler-nginx` exercises both configurations against the pinned production Nginx image. The four `test-ui` shards instead run Vitest and upload per-file timing artifacts. A code-only shard result cannot replace build-output or Nginx routing evidence. A future narrower trigger needs to cover UI source, package and lock inputs, crawler scripts/config, Docker/Nginx configuration and pinned image, the released tarball digests, and the workflow itself; merely matching `.test.*` files would be incomplete. These lanes are required through `ci-gate`, so retain them until that input closure and the planned-skip gate are proven.

Python-service A0 inventory (2026-10-03): `test-services` selects on `python`, installs digest-verified released Common/Core/Verification/ISO18013 wheels plus `requirements-services.txt`, verifies the released native trust-registry capability, and runs the retained `services` pytest tree against fake storage and its loopback mTLS fixture. Its inputs include the release stack lock, package requirements, service/test source, and TLS fixture; this is not the real PostgreSQL/Redis Rust integration obligation. `test-passport-fence-postgres` selects on `rust` and runs three named Python tests against disposable PostgreSQL to prove the atomic beta passport fence, probe target, and authority check. That database group is separately required even though its test code is Python. A language-extension-only planner could therefore skip a required runtime-boundary check; record obligation ownership and classifier inputs before narrowing either lane.

Feature-probe and passport-image A0 inventory (2026-10-03, current `main`): both are separate Rust-selected `ci-gate` dependencies. `test-rust-feature-probe` builds the standalone frozen `.github/feature-regression/rust-probe` manifest/lock and Rust subject against the issuance crate, runs the subject twice, requires byte-identical canonical output, validates expected behavior and safe diagnostics with `tests/test_feature_regression_rust_probe.py`, and enforces the manifest's target-size budget. Its inputs include the probe manifest/lock/source, validator, issuance source/features, patched third-party sources, Rust toolchain, and transitive Cargo graph; it is not a substitute for the service integration matrix. `test-rust-passport-image` builds `services/Dockerfile` with the opt-in passport self-signed feature and verifies that the resulting image refuses native HTTP startup without tenant API keys. Its closure includes the Dockerfile, build scripts, Rust/proto/contracts/assets copied into the image, pinned base images, feature selection, and runtime startup policy. A package-only or `.rs`-only path selector cannot safely skip either lane; retain the current Rust selection until these inputs and their cross-repository dependencies are represented in the shared obligation map.

Rust lint/image A0 inventory (2026-10-03, current `main`): `rust-lint-policy` is Rust-selected and checks workspace formatting, workspace all-target Clippy, the frozen feature probe's Clippy, MMF security feature policy, and rendered service packaging/migration ordering across base, beta, tunnel, and GHCR Compose files. Its affected-package planner is shadow-only. `test-rust-service-images` is also Rust-selected but separately verifies Canvas/self-host/DIDComm/native Compose ownership, builds the multi-target `rust/services/Dockerfile.ci` images, and smoke-tests real Gateway, issuance, verification, Canvas worker, organization, and credential-template image/runtime boundaries; the organization smoke uses disposable PostgreSQL and Redis, and the credential-template smoke uses disposable PostgreSQL. Both are direct `ci-gate` dependencies. Their inputs extend beyond Cargo packages to probe policy, CI scripts, Dockerfiles/build context, Compose/configuration, pinned images, runtime entrypoints, and relevant source/fixtures. Retain their current selection until each behavior and its transitive input closure has an explicit owner in the shared obligation map; neither job is replaceable by a package-scoped `cargo check` result.

Security/supply-chain A0 inventory (2026-10-03): `security` runs when the broad classifier marks security inputs; it concurrently executes Python dependency audit, UI Bun/npm audit, test npm audit, Bandit, and Semgrep. The job currently blocks on the three dependency-audit processes, while its Bandit/Semgrep shell commands use `|| true` and produce reports/timing artifacts even on scanner failure. This is the existing policy, not a newly proved blocking guarantee. `rust-supply-chain` runs on Rust-classified changes and executes `cargo deny check advisories bans licenses sources` against the workspace manifest. Both are `ci-gate` dependencies. Any selective planner must carry requirements/lockfiles, scanner configuration, source trees, Cargo manifests/lock, and relevant workflow inputs; a Cargo package-only map cannot represent these obligations.

Capture dependencies not represented in Cargo: HTTP/gRPC consumers, protobuf generation, embedded JSON/Markdown, schemas/migrations, scripts, compiler features, Dockerfiles, Compose/Kubernetes configuration, and pinned cross-repository artifacts. Prefer one machine-readable group/input manifest reused by planning, execution, and coverage checks over duplicated lists.

Cross-package Rust test-source edge (2026-10-04): `rust/services/issuance/tests/canvas_published_schema_contract.rs` imports `crates/selfhost-bundle/tests/support/extracted_bundle.rs` and `resolved_selfhost_runtime.rs` with `#[path]`. Those external source files call the `marty_selfhost_bundle` library, so issuance's `marty-selfhost-bundle` dev-dependency is required even though a search confined to the issuance tree finds no crate reference. A local removal experiment was discarded after independent review identified this consumer; no test or CI gate changed. The current shadow planner maps changes to that support directory through the bundle package and its declared reverse Cargo dependency to issuance, then conservatively selects all Rust packages because issuance is a service. A future composition-target move must relocate the source inclusion and crate dependency together before removing the issuance edge.

Canvas worker A0 inventory (2026-10-03, #1058 target): `canvas_published_worker_contract` has 134 discovered tests, of which 132 run by default and two capture-only tests (`capture_worker_body_timeout_published_process`, `capture_worker_lease_expiry_published_process`) remain ignored for explicit capture invocation. The default local run can pass quickly because hosted cases require `MARTY_CANVAS_PUBLISHED_SCHEMA_TEST=1`; that result is not evidence of the live obligation. The Canvas CI runner sets the opt-in, takes the worker and composition executables from the reusable Cargo artifact list, pulls both digest-pinned historical images from `canvas-worker-consumer-range-oracle.json`, runs four exact worker preflights, checks their run/executable-digest evidence before any skip, verifies mandatory names and no cross-target duplicates, and runs both full targets. The Python harness passes case-specific native origins to Rust test children; Rust fixtures create owned test databases and launch the actual worker with guarded database URLs. The required gate remains the Canvas matrix lane plus aggregate `ci-gate` on PR and protected merge-group validation. This inventory is one group, not an assertion that all A0 groups or non-Cargo inputs are mapped.

### A1: acceptance ownership

Canvas package candidate (2026-10-06): the two Canvas targets and thirty shared support modules move into sibling `marty-canvas-acceptance`; the three Passport/Gateway targets remain in `marty-service-acceptance`. The source move preserves assertions and test names, while workspace/lock entries, exact artifact and Bookworm selectors, repository-root guards, and ownership policies follow the new package. Locked metadata confirms two Canvas and three remaining targets with unique owners. Normalized package-scoped Cargo-tree entries fall from 723 in the broad acceptance package to 692 for Canvas, removing Signing Keys and its AWS KMS/Smithy dependency branch. Full workspace CI still validates both packages. This is a compile-boundary improvement, not a measured CI time saving; hosted compilation and the opt-in published-process/database suites remain required before merge.

Keep service behavior and adapter tests with their service. Move tests that compose several implementations into an acceptance package that depends on them. Remove service-to-service development edges only when their consumers have moved and standalone package validation confirms the boundary.

Share exact-owned fixture and process-management Rust helpers. Preserve resource isolation, bounded cleanup, child-process protocols, provenance checks, and preflight coverage accounting. Investigate `CARGO_BIN_EXE_*`, `CARGO_MANIFEST_DIR`, relative fixtures, and artifact-discovery assumptions before moving tests: an acceptance package does not automatically receive dependency binary paths.

The larger `canvas_published_schema_contract` target is not a simple file move. Its source embeds many `contracts/*` corpora with paths relative to the issuance test directory, uses `CARGO_MANIFEST_DIR` for three runtime roots, and the runner resolves the compiled artifact by both issuance package ID and target name. The shell runner requires named child/helper tests as well as top-level scenarios. A later split must update these inputs together, preserve every explicit name check, and validate actual binary/image startup; changing Cargo ownership alone would silently break its execution contract.

Next cross-service boundary evidence (2026-10-03): after #1044 merged, issuance still has `marty-flow` and `marty-gateway` as development dependencies. A repository-wide search of the merged issuance integration tests confirms their actual Rust imports remain in `tests/support/*` modules for flow, DIDComm, renewal, Kubernetes, and Canvas operations; those modules are assembled by the large `canvas_published_schema_contract` target. This target also imports selfhost-bundle support and published-image/database fixtures. Moving an isolated unrelated test would not remove these remaining service-to-service compile edges. A coherent next A1 slice must split the target's cross-service composition owner (or the complete target) while retaining the runner's named-test, artifact-ID, and relative-corpus contracts. No further service dependency has been removed on the strength of this inspection alone.

Dependency search caution: `marty-selfhost-bundle` appears only in issuance's dev-dependency declaration when searching the issuance directory, but the Canvas target imports `rust/crates/selfhost-bundle/tests/support/extracted_bundle.rs` and `resolved_selfhost_runtime.rs` with `#[path]`; those external support files call `marty_selfhost_bundle::...`. The dev dependency is used and must not be removed merely because a package-local text search reports no import. A future A1 move must follow external `#[path]` modules as part of the compile-input closure.

Relocation feasibility check: the deployment/Flow composition support closure references `env!("CARGO_BIN_EXE_marty-issuance-service")` and `env!("CARGO_BIN_EXE_marty-canvas-sync-worker")` in multiple helpers, plus twelve `CARGO_MANIFEST_DIR` assumptions across the target/support set. A new acceptance package would not receive dependency binaries through those compile-time Cargo variables. Moving the first 300 lines as a nominal standalone test would therefore break compilation or silently change fixture roots. The next slice needs an explicit owned-binary/artifact handoff and package-independent root strategy, with the existing CI named-test guard updated in lockstep; do not remove Flow/Gateway/selfhost dev edges until that target actually compiles and executes under its new owner.

Protected queue stage timing after #1044 (run 37112907655, Canvas job `111174201293`): the same job serialized reusable Rust test compilation (6.50 minutes), Bookworm-compatible base runtime compilation (9.48), public self-host image build (13.82), worker parity preflights (8.13), and isolated database contract suites (22.42). These five measured steps total about 60.35 minutes of wall time before small setup/other steps. The image and base-runtime prerequisites are entangled with acceptance cases in the issuance-owned target, while the database suite remains the largest single step. A coherent ownership split could permit some independent work to overlap, but the current run does not prove which stages can run concurrently or a resulting speedup; map the exact artifact and case dependencies first.

Canvas runner topology check (2026-10-03): the workflow's `Run isolated database contract suites concurrently` step invokes `run-db-contract-groups.py canvas`. In that mode its command map contains only `published-canvas`; the two-worker executor therefore has one active group. The four historical preflights use the separate `preflights` mode and can overlap two at a time, but the 22-minute published Canvas full target is currently serialized behind image and Bookworm preparation in one job. The step name's “concurrently” describes the generic helper, not Canvas full-suite parallelism. A1's worker/composition ownership split is a prerequisite for evaluating independent runtime groups; this observation alone does not authorize splitting an executable without preserving its fixture/image handoffs and named-test obligations.

Post-#1058 parallelism candidate: the split runner still executes the full composition binary and then the full worker binary serially after the SQL-logging positive control. `canvas_published_database` gives each owned test database a UUID scope, a disposable labeled container, and a Docker-assigned loopback port, which is evidence that these two binaries need not share a fixed database endpoint. It is not proof of full independence: composition also consumes the Bookworm executable, public image, Envoy/Compose artifacts, and process fixtures. Before parallel execution, check those process/port/cleanup resources, retain the exact mandatory-name and preflight-digest guards, and run both complete binaries with distinct logs and fail-closed combined status under hosted opt-in CI. Measure the actual Canvas step and job wall times; resource contention may offset overlap.

Parallel-target candidate `codex/canvas-parallel-targets-20261003` was rebased onto merged #1058 main. It preserves the serial SQL-logging positive control, then starts both complete target binaries with separate logs, waits for both, reports both exit statuses/logs, and fails if either fails. The exact mandatory-name, test-count, and preflight-digest checks precede launch unchanged. A synthetic barrier proves real overlap; separate failure cases prove neither status is masked and logs are cleaned after normal completion. The full runner/policy/database-group suite passed 257 tests locally before the rebase, plus Bash/Ruff/diff checks; independent review of the combined branch found no blocker. Forced CI cancellation retains the pre-existing limitation that SIGTERM cannot guarantee Rust fixture `Drop` cleanup; normal completion waits for both owners. Re-run focused checks on the rebased head and require actual hosted opt-in Canvas and protected queue validation before claiming a speedup.

Three completed protected Canvas runs provide a fresh comparison range, not a causal speed measurement: detached #1058 [run 37123397984](https://github.com/ElevenID/marty-ui/actions/runs/37123397984) took 54.4m overall / 19.9m in the full database group; #1060 [run 37129440091](https://github.com/ElevenID/marty-ui/actions/runs/37129440091) took 51.1m / 18.5m; #1061 [run 37129988486](https://github.com/ElevenID/marty-ui/actions/runs/37129988486) took 44.4m / 16.0m. In all three, public-image build (8.4–11.3m), historical preflights (7.9–8.1m), and the full database group remained serial stages. The observed spread can reflect cache/load variance and different combined heads; it does not prove an optimization. Measure the future parallel-target candidate against multiple comparable protected runs and check both test totals before attributing saved wall time.

Final protected #1058 baseline [run 37177395334](https://github.com/ElevenID/marty-ui/actions/runs/37177395334) passed and merged as `16fb0331a`. Its Canvas job ran 04:35:05–05:37:36 UTC (62m31s): reusable test compilation 5m53s, Bookworm acceptance compilation 9m44s, public image build 12m55s, worker preflight 8m08s, and full database group 24m15s. These remain serialized on merged main; the target split alone did not make them parallel. Compare #1081's actual database-step and whole-job times against this and the preceding range, while checking full test totals and accounting for cache/load variance.

First hosted parallel-target result [UI #1081 PR run 37180687909](https://github.com/ElevenID/marty-ui/actions/runs/37180687909) passed on the reviewed head: the database group took 14m15s (06:11:24–06:25:39 UTC), 10m less than the final protected #1058 baseline. Both full binaries retained the same totals as #1058: 145 composition tests passed, 125 worker tests passed, and two capture-only worker tests remained ignored; the separate SQL-logging positive control passed. The whole Canvas job took 43m05s versus #1058's 62m31s, but differences in compile/image-cache stages and runner load prevent attributing all 19m26s to target parallelism.

Protected [#1081 merge-group run 37182891790](https://github.com/ElevenID/marty-ui/actions/runs/37182891790) also passed and merged as `7b3b84989`: its database group ran 06:56:13–07:10:03 UTC (13m50s) and its Canvas job 06:28:22–07:10:36 UTC (42m14s). Relative to the final protected #1058 baseline, the measured step elapsed time was 10m25s shorter and whole Canvas elapsed time 20m17s shorter. Parallel execution explains overlap of the two complete test binaries; the additional whole-job difference includes build/cache/load variance and is not assigned to the change. The two successful #1081 runs support a repeatable database-step improvement, not a guarantee for every runner or change.

Artifact dependency check: the Bookworm step explicitly builds the issuance and Gateway binaries *and recompiles the entire* `canvas_published_schema_contract` target, then passes that target as `MARTY_BASE_RUNTIME_COMPAT_TEST_EXECUTABLE`; `base_runtime_container.rs` consumes it for rendered base-runtime acceptance. The public-image build loads a local Docker image, records its immutable image ID, and passes that ID plus the packager executable/revision to `selfhost_packaged_runtime.rs`. The same issuance-owned Canvas target contains both self-host child/coordinator tests and the database/worker suites. Moving only a GitHub Actions step to a separate runner would lose these local artifacts or duplicate the giant target build. The next A1 split must give each resulting test owner a proven binary/image handoff and update the named-test/artifact selectors before parallel jobs can be justified.

Local owner-feasibility experiment (2026-10-03): a temporary `[[test]]` entry in `marty-service-acceptance` pointed at the existing issuance Canvas source without copying it, and locked Cargo metadata accepted the path. A scoped `cargo +1.95.0 check --locked -p marty-service-acceptance --test canvas_published_schema_contract` then reported 854 compile diagnostics: the dependent package does not receive issuance's `CARGO_BIN_EXE_*` values, and the giant target's direct support-module imports require many dependencies absent from the narrow acceptance crate. The temporary registration was removed and the experiment worktree is clean. This rules out a manifest-only whole-target move; it does not prove a cohesive group split impossible. Keep the acceptance crate narrow and map a smaller support-module/test-name closure before moving code or adding broad dependencies.

Candidate narrower A1 boundary: the worker replay/preflight section is mostly contiguous in `canvas_published_schema_contract.rs` (lines 569–2267 on #1044 main), with one SQL-logging worker test later in the file. It contains the four exact historical preflights and their native child/reference helpers; the current runner guards 92 `worker_`-prefixed names and binds skip evidence to the compiled executable digest. A worker-target extraction must include that later logging case, shared `canvas_published_database` helpers, the complete explicit-name guard, and the exact executable digest/child invocations. This is a candidate for a coherent split from deployment/Flow composition, not a proven independent package yet; map cross-references and compile it before changing any trigger.

Worker-closure reconnaissance: within lines 569–2267, source references no `base_runtime_*`, `didcomm_*`, or `selfhost_*` module, and the four `renewal_` occurrences are scenario labels, not Rust module calls. The worker support files chiefly refer to each other, `canvas_published_database`, and a `worker_database_url` helper in the same region; `canvas_published_database` itself uses `bounded_fixture_command`. This suggests a test-target split might avoid carrying deployment/Flow composition into the worker executable. It is only a textual dependency probe: nested macro imports, `include_*` corpora, the later SQL-logging case, and exact CI test discovery still need compilation and parity checks before a PR can claim the closure is complete.

Worker-target split [UI #1058](https://github.com/ElevenID/marty-ui/pull/1058) (2026-10-03): isolated worktree `codex/canvas-acceptance-owner` moved the contiguous worker section and later SQL-logging case into a registered `canvas_published_worker_contract` target without changing their bodies. Both targets pass package-scoped Rust 1.95 `cargo check`, `cargo test --no-run`, formatting, and strict targeted Clippy; all 178 original top-level function names remain across the two files. The shared-helper diagnostic tests were extracted and included only in the composition target: actual test discovery finds 143 composition plus 132 worker tests, no duplicate names, all 165 mandatory runner names, and the eight helper tests pass once. The runner preserves exact worker preflights and binds reuse evidence to the worker executable digest. The synthetic harness and static policy checks were updated without dropping missing/duplicate/ignored/child/preflight mutations; 331 focused runner/policy tests plus 96 related ownership tests passed locally, and an independent reviewer cleared the corrected split. After an earlier manual queue removal, a corrected head passed renewed full PR and protected combined-head CI, including live Canvas, then merged as `16fb0331a`. The split is not evidence of a CI speedup; both binaries remain in the same lane and Bookworm compatibility still compiles composition.

Completion evidence: before/after obligation mapping, focused package checks, relocated scenario execution, packaging/Bookworm acceptance at a meaningful milestone, and no lost mandatory checks. Test moves must initially retain current triggers and assertions.

Post-split ownership check (2026-10-03): the new worker target still compiles under the issuance package. Its source uses three `CARGO_MANIFEST_DIR` runtime roots, `canvas_published_database` uses two more, and its `canvas_worker_process_signals` support calls `env!("CARGO_BIN_EXE_marty-canvas-sync-worker")`. These are concrete relocation inputs, not test behavior to drop. An acceptance-package move needs an explicit worker-binary handoff and a package-independent fixture-root contract, then package-scoped compilation and the existing live preflight/child-process checks. Merely changing its Cargo target owner would not satisfy A1.

Preparatory handoff branch `codex/canvas-worker-handoff-20261003` at `1608985a7` is stacked locally after #1058. It replaces hard-coded three-level fixture-root ancestry with a checkout-marker search shared by worker and database support, and lets the worker process fixture use an explicit absolute binary path while retaining Cargo's current default. Two focused tests cover both package depths and path selection; the target passes Rust 1.95 `cargo check`, `cargo test --no-run`, strict Clippy, and all 132 non-ignored default local tests. The latter return early where hosted opt-in services are required and do **not** substitute for live CI. An independent reviewer found no blocker but requires the eventual acceptance runner to source the override from the exact verified issuance compiler artifact; an arbitrary absolute file is not enough. Keep this branch unpublished until #1058 merges, then rebase and submit it as a separate maintenance PR with full protected validation.

The same local handoff branch now has runner commit `05a57f90e`: `run-published-canvas-contracts.sh` selects exactly one normal (`profile.test == false`) `marty-canvas-sync-worker` compiler artifact from the issuance package and exports that verified path to the worker tests. A local Cargo JSON probe showed the normal binary under `target/debug` and a distinct `--test` harness under `target/debug/deps`; selecting only by target name would be unsafe. The synthetic preflight suite passes 141 cases locally with one real-jq case skipped on Windows Git Bash; the latter is configured to exercise the runner's actual jq predicate against normal, harness, wrong-package/kind, missing, and duplicate artifacts when mandatory Linux CI runs. Bash syntax and diff checks pass. The independent reviewer cleared the runner change and its fail-closed identity checks. This remains an unpublished stacked branch pending #1058 merge and full CI; it does not yet relocate the target into the acceptance package.

Acceptance-owner candidate `d249a7944` is stacked locally after the two handoff commits. It registers the worker contract once under `marty-service-acceptance`, removes its issuance test registration, and keeps 22 shared fixture modules in one issuance support location rather than copying them. Both artifact selectors now require the acceptance owner, while the real worker binary still must come from the issuance compiler artifact. Locked offline metadata confirms a single worker target; the moved executable discovers 134 tests and its local default run passes 132 with the same two explicit capture-only ignores. The composition target still compiles and discovers 143 tests. Strict Clippy, formatting, Bash syntax, Ruff, and 156 focused Python tests passed before a new stale-issuance-artifact rejection test was added; that new test also passes. An independent reviewer cleared the final diff and found no coverage/gate break. Hosted opt-in Canvas execution and full protected CI remain necessary. The current workspace still compiles both targets, and acceptance dev-depends on issuance and shared support, so this is boundary ownership groundwork, not a measured speedup or a reason to narrow gates yet. Publish it as a separate maintenance PR after #1058 and its handoff predecessor merge.

Current A1 composition disposition (2026-10-07): the separate
`marty-canvas-acceptance` package and worker target have merged, but a further
three-way deployment/renewal-DIDComm/Canvas split is deferred pending a
coherent fixture boundary. The roughly 1,900-line composition target interleaves
those scenarios; self-host children use `canvas_published_database`, and
renewal/DIDComm helpers call base-runtime, gateway, Envoy, and Canvas support.
Additional test targets in the same package would retain its shared Cargo
dependency closure, while extracting packages would require owned shared
fixtures, not copies. The Bookworm artifact and runner bind named evidence to
the existing composition executable. An independent source review found no
supported compile saving or safe minimal move. Retain full Canvas execution;
revisit only with a target-specific dependency/timing experiment and a
non-overlapping fixture owner.

### A2: one narrow Rust extraction

Choose the smallest coherent candidate after dependency inspection: response text/JSON compatibility or a Canvas domain/projection group. Reuse the existing code and corpus. Keep HTTP, SQLx, runtime composition, and passport cryptography out of the new package when they are not intrinsic to its responsibility.

For later worker-domain extraction, separate lease identity from PostgreSQL operations without weakening transaction fencing or the database-clock check after acquiring a lock. Do not move database guarantees into an unverified mock.

Completion evidence: the new package builds/tests independently, consumers retain behavior, its dependency graph excludes unnecessary runtime implementations, and measured feedback supports or limits further extraction. Temporary re-exports may preserve callers; duplicate implementations may not become permanent.

### A3: affected-check planning

Reuse useful existing selection logic after correcting its gaps. Handle additions, modifications, deletions, renames, fixtures, build inputs, dependency consumers, and merge-group base/head semantics. Include dev/build dependencies and relevant feature configurations. Missing history, unknown paths, incomplete mappings, or invalid evidence must broaden selection.

Run the planner in shadow mode while current full gates remain authoritative. Log why each group was selected. Exercise representative changes and compare the planned obligations with full results. Use small deliberate fault probes where necessary to show a relevant failure would be selected; ordinary green runs alone are insufficient.

The initial local UI shadow planner computes package ownership and reverse Cargo consumers, but does not select test groups or skip any check. Reviewer worker confirmed deleted and moved path handling, alias/dev/build edges, and broad fallback. It logs `all: true` with a `*` package sentinel when diff or metadata cannot be proven. The planned lint-job placement only observes PRs the existing classifier already labels Rust; it does not audit classifier false negatives. Before promoting selection, independently cover the classifier's negative path, map non-Cargo group inputs, compare shadow decisions with full runs, and measure the added fetch/metadata time. No selector output is a gate yet.

Compiler-input audit (2026-10-03): `rust/services/auth/tests/executable_smoke.rs` embeds `services/entrypoint.sh` with `include_str!`, but the classifier previously sent that path only to Python/security. Merged [UI #1051](https://github.com/ElevenID/marty-ui/pull/1051) adds Rust selection for this exact path and executes the actual Bash classifier in a regression case; all 93 local workflow-policy tests passed, an independent reviewer found no blocker, and protected queue CI passed. This corrects a real false negative without omitting any existing lane. Other inspected external includes (`services/auth/assets/*`, `services/Dockerfile`, `scripts/build-rust-service-binaries.sh`, `config/envoy/*`) already select Rust or full validation.

Service runtime-edge audit (2026-10-03): Notification has Applicant HTTP event publishing, Gateway routing, and self-host wiring without Cargo edges. An independent reviewer found a second counterexample: Presentation Policy consumes Trust Profile over configured HTTP, but Cargo does not link those service packages. Therefore a single-service exception is insufficient. [UI #1052](https://github.com/ElevenID/marty-ui/pull/1052) makes the shadow Rust planner report all Rust workspace packages whenever the Cargo reverse closure reaches any `rust/services/*` package, while retaining narrow results for crate-only closures; eight planner tests pass and the reviewer cleared the corrected change. This is a fail-closed observation, not a test skip or measured speedup. It does not classify Python/UI/deployment obligations. Hold selective-gate promotion until the complete runtime edge and group-input manifest is proven.

Locked-metadata probe on the reviewed #1052 branch (before #1044 adds the acceptance package): 24 workspace packages were tested as direct owners; only `marty-oid4vp-contract` yielded a narrow one-package shadow result. The other 23 reached a service through Cargo or were service packages, so the fail-closed rule selected all. This is a deliberately safe planner result, but it shows that simply turning it into a gate would have almost no Rust-lane payoff. Prioritize proving the non-Cargo consumer graph and acceptance-group inputs before A6 selection; do not weaken the full gate to manufacture a speedup.

Runtime-edge reconnaissance shows this is not just two exceptional services: `rust/services/gateway/src/config.rs` declares service URL routes for Auth, Organization, Credential Template, Trust Profile, Issuance, Applicant, Notification, Compliance Profile, Presentation Policy, Deployment Profile, Flow, Verification, Revocation Profile, Device Registration, and Signing Keys. `rust/services/flow/src/config.rs` configures Organization/Credential Template/Presentation Policy/Issuance gRPC targets and Credential Template/Trust Profile/Deployment Profile/Issuance HTTP URLs; Auth and Applicant also configure cross-service targets. These declarations are candidate input edges, not yet a complete exercised-test map. Before narrowing A6, trace each configured edge through actual client behavior and the relevant acceptance tests, then include deployment-rendered and schema/proto inputs. A Cargo-only service map is demonstrably incomplete.

Two runtime edges have source-level client proof beyond configuration: Applicant's `GrpcEventPublisher::publish` sends a token-authenticated HTTP POST to the configured Notification ingest URL before publishing to Event Stream gRPC (`rust/services/applicant/src/providers.rs`), and Presentation Policy's `NativePresentationControlPlane::load_profile` performs an HTTP GET against the configured Trust Profile internal route (`rust/services/presentation-policy/src/control_plane.rs`). Flow's `connections.rs` also constructs an HTTP reference provider with Trust Profile, Credential Template, Deployment Profile, and Issuance URLs. Existing Presentation Policy `control_plane_behavior` uses a local Trust Profile responder, but a test double is not proof that all cross-service compatibility cases are covered. These edges must be reflected in group ownership before a Trust Profile or Notification change may omit consumer validation.

Auth adds another concrete consumer cluster: `rust/services/auth/src/service_transports.rs` sends Flow `StartVerification` and Organization `AddMember` gRPC requests and PATCHes Applicant profiles; `canvas_transport.rs` issues an HTTP GET to the Issuance Canvas LTI session service. `connections.rs` also connects both gRPC clients and probes Applicant and Issuance HTTP health before readiness. `service_transports_behavior` exercises the Applicant adapter with a test HTTP client, and `canvas_transport_behavior` exercises Canvas transport behavior, but those tests alone do not prove real cross-service protocol compatibility. A future affected-group map must include Auth consumers when Flow, Organization, Applicant, or Issuance contracts change, plus the relevant live acceptance obligation; treating Auth only as a Cargo reverse edge would miss runtime coupling.

Flow's runtime edge is active, not just a configuration string: `connect_providers` constructs Organization, Credential Template, Presentation Policy, and Issuance gRPC providers, then checks Signing Keys and physical-Issuance HTTP providers and the reference catalog before marking readiness. `HttpFlowReferenceProvider::resolve` performs organization/principal-scoped GETs for Issuance application templates, Credential Template delivery destinations, Trust Profile entries, and Deployment Profile entries. Its source-local provider tests exercise controlled HTTP responses, but those do not by themselves prove cross-service wire compatibility. A change to any of these provider routes may require Flow consumer and composed acceptance coverage even when Cargo reverse dependencies omit Flow; maintain fail-closed selection until these obligations are explicitly grouped.

2026-10-06 local A3 candidate (not merged): add observed non-Cargo Organization, Presentation Policy, and Issuance gRPC producer-to-Flow consumer edges alongside the already recorded Credential Template edge. Each new edge is backed by Flow's configured target, channel construction, concrete gRPC request, source call site, response-identity handling where present, and the provider's server implementation. Organization membership checks that returned identifiers are nonempty; it does not currently prove they equal the requested principal and tenant, so this inventory must not claim that stronger guard. These observations do not prove every Flow HTTP/proto/deployment input or cross-service compatibility obligation. The shadow planner still selects the full Rust workspace for any service change, and no CI gate, skip, release tier, or measured speedup changes in this candidate.

2026-10-10 local A3 candidate: Credential Template's issuer-resolution
request uses `SIGNING_KEYS_INTERNAL_URL` through Gateway's authenticated
`/internal/signing-keys/resolve-issuer-did` compatibility route. Compose binds
that URL to `gateway:8000`; Cargo has no Gateway-to-Credential-Template edge.
The shadow planner now records the source-backed runtime consumer and a
regression test checks the configuration, request, Gateway dispatch, and
deployed endpoint. It remains fail-closed for all service changes. This is
input-closure progress, not a narrower CI selection or measured speedup.

Completion evidence: selector regression tests, representative dependency cases, shadow results, and reviewer agreement on every newly omitted group. No GitHub gate may treat an unexpectedly missing required group as success.

Current-main embedded-Markdown check (2026-10-03): a same-line search of Rust `include_str!`/`include_bytes!` call sites surfaced `rust/services/issuance/src/canvas_sync_worker.rs` embedding `canvas_sync_processor_contract.md`, and the classifier already has a dedicated Rust case for that path. This addresses that known documentation false negative, not the broader non-Cargo runtime edge inventory; multiline macros, generated inputs, and indirect reads need a stronger input map before selective validation.

Direct-literal compiler-input check (2026-10-03, #1073 base): a multiline scan of literal `include_str!`/`include_bytes!` calls found external inputs under `contracts/*`, `config/envoy/*`, `services/auth/assets/*`, `services/Dockerfile`, `services/entrypoint.sh`, `scripts/build-rust-service-binaries.sh`, and `tests/vectors/*`. The classifier selects Rust for contracts, auth assets, Dockerfile, and entrypoint; it selects the full suite for config, scripts, and test vectors. The embedded issuance Markdown is already handled. The then-known `SELFHOST_BUNDLE.md` package-asset false negative was corrected by merged [UI #1070](https://github.com/ElevenID/marty-ui/pull/1070). This scan does not resolve `concat!`/environment-derived macro paths, generated files, runtime reads, or cross-service consumers; do not narrow any check from it.

A bounded `include_str!`/`include_bytes!` `concat!(env!("CARGO_MANIFEST_DIR"), "...")` scan found 37 calls on the same base: their suffixes resolve either to `contracts/*` (Rust-selected) or to the owning crate's Rust source/migrations. It did not reveal another classifier exception. This covers that common literal-concat form, not arbitrary macro expansion or generated/runtime inputs; the fail-closed shadow planner and broad gates remain necessary.

Embedded-input regression follow-up [UI #1075](https://github.com/ElevenID/marty-ui/pull/1075), reviewed head `938f4d455`, scans tracked Rust sources for `include!`, `include_str!`, and `include_bytes!`, resolves direct literals and the common `CARGO_MANIFEST_DIR` concat form, and requires every resulting external input to select Rust through the actual Bash classifier. Unsupported include syntax fails for review rather than being silently omitted. The shared synthetic classifier harness runs all inputs in one Bash process; 98 workflow-policy tests pass in about five seconds, plus Ruff and diff checks. An independent reviewer found no blocker. Full PR [run 37159145064](https://github.com/ElevenID/marty-ui/actions/runs/37159145064) and protected combined-head [run 37161991344](https://github.com/ElevenID/marty-ui/actions/runs/37161991344) passed, including Canvas and final gate; the PR merged into main as `52b6dd7d3` at 2026-10-04 00:33:11 UTC. The protected Canvas job took 58m30s, including 22m19s in the database group. This guards direct static input forms only; it does not prove generated or runtime input closure, and no CI lane selection or attributable speedup is claimed.

### A4: lower-level behavioral coverage

Use table-driven tests and shared Rust scenario data for pure decoding, projections, validation, and scheduling decisions. Reuse existing repository/provider ports; share contract tests between test doubles and real adapters where practical. Tests should assert externally meaningful outcomes, not mirror implementation steps.

Target a test pyramid by obligation, not by deleting broad tests: many isolated, fast unit cases at the base; fewer real-adapter/database/process integration cases in the middle; a small number of representative, released-stack end-to-end journeys at the top. For each existing case, record its owner, layer, happy/negative/security classification, fixtures, unique assertion, and the cheapest layer that can prove that assertion. Move pure decision matrices down with independent expected outcomes; retain a small real-boundary proof for each adapter or cross-service contract. Count and time cases per layer before and after each migration so a smaller E2E suite cannot conceal lost assertions.

Canvas LTI login pilot (2026-10-05): issuer and client-ID mismatch decisions are pure enough for unit tests, but each HTTP case also proves the route invokes validation and does not persist launch state on rejection. The focused HTTP suite itself takes about 0.01 seconds after compilation, and no corresponding released-stack E2E mismatch matrix was found. Retain both HTTP cases; adding a separate unit matrix would reduce no CI work. Do not open a speed PR for that seam without a distinct lower-level ownership benefit.

The first response-compat extraction already relocates 16 pure parser/owner tests. Inspection of nearby Canvas JSON tests shows the apparently similar cases have different obligations: `json_consumer_diagnostic_matches_published_boundaries` and `json_depth_diagnostic_matches_published_boundaries` run the pinned published application/database and compare frozen observations; `status_provider_matches_json_consumer_reference` and the status-runtime JSON cases exercise native provider and real route persistence. These are not duplicates of in-memory parser tests and should remain until a narrower real adapter proof replaces each named obligation. No A4 integration test has been removed yet.

The next four Retry-After paragraphs record historical local checkpoints;
their candidate status is superseded by the merged outcome immediately below.

2026-10-06 local A4 Retry-After proof candidate (not merged at that checkpoint): existing parser and backoff tests check their functions separately, while the seven frozen worker cases combine header parsing, first-attempt delay bounds, and processor rate-limit classification. A new fast unit test covers that composition with deterministic jitter and the existing provider/repository simulator ports, including no fact or candidate writes. It does not prove the durable PostgreSQL retry, lease clearing, ciphertext preservation, HTTPS transport, or whole-process behavior. All seven native and historical published-process cases remain unchanged; no tier, gate, or measured speedup changes in this slice.

Follow-up fast-seam candidate (not merged): the production 429 converter now uses the same header-map parser with a fixed-clock test covering all seven fixture headers, and an actual `CanvasSyncWorker::run_cycle` test checks representative zero, future-date (60-second), and clamped (86,400-second) hints, error category, worker identity, target generation, and retry outcome at the existing repository port. The port spy performs no SQL; its returned `Retry` is not a durable-state assertion. The original PostgreSQL contract covered only forced terminal failures without hints; the companion adapter proof below fills that gap. The real HTTPS/worker/database cases still own transport, issued-row, ciphertext, and released-schema evidence. All seven remain in their existing tiers. No production SQL, CI tier, or gate changed here.
The companion PostgreSQL contract candidate uses the existing dedicated `_test` fixture once for seven effective Retry-After hints, asserting repository lease/failure fencing, persisted retry deadlines, cleared leases, errors/results, and unchanged enabled targets. Its schema is synthetic and neither seeds issued-credential rows nor real encrypted OAuth secrets. It therefore does not replace the published-process HTTPS/date, issued-row, ciphertext, or released-schema evidence; no native case or gate is removed by this candidate.

Local A4 nested-case tier pilot (not merged or measured): the seven frozen Retry-After observations are identical after omitting only the case name for request, job, idle heartbeat, OAuth, credential/application snapshot, and fact fields; header parsing and retry timing vary. Each native replay separately performs the same issued-row and ciphertext preservation checks. An explicit routine `full-after-preflights` run retains native `http_date_future` (live HTTP-date/UTC deadline) and `malformed` (invalid-header fallback) in separate actual HTTPS worker processes. Plain full, unmarked standalone native diagnostics, and manual/scheduled full qualification retain all seven; the 33 historical replay selections and every other REST test are unchanged. Selection validates exact seven scenario and oracle names before filtering, rejects caller-provided or unknown tiers, and rejects a routine tier whenever full qualification is set even through a direct Python call. Fast parser/processor and PostgreSQL cases cover the seven input variants, but this is only a local candidate pending exact worker-port proof for 0/60/86400 hints, independent review, protected CI, and timing evidence; it is not permission to cut release evidence.

Current disposition (2026-10-07): [UI #1124](https://github.com/ElevenID/marty-ui/pull/1124)
merged the exact seven-case selector, the two native routine cases, all-seven
fast parser/processor and PostgreSQL proofs, and the worker-port 0/60/86400
proof after [normal](https://github.com/ElevenID/marty-ui/actions/runs/37437829353),
[full-qualification](https://github.com/ElevenID/marty-ui/actions/runs/37437847991),
and [protected](https://github.com/ElevenID/marty-ui/actions/runs/37444430694)
CI passed. A routine
tier is runner-owned and rejected under full qualification; default,
manual/scheduled full, and stable exact-main qualification still execute all
seven native HTTPS/process cases. The five omitted routine replays no longer
repeat their issued-row and ciphertext assertions in that same PR run; the
fast and synthetic PostgreSQL proofs do not replace that process evidence.
Keep the exact-main full qualification requirement: routine runs the live
future-date/UTC and malformed-header checks, while past-date and negative
cases remain in full qualification. No speedup is inferred from this
documentation reconciliation or from the stale local worktree, which must
not be ported onto current main.

The Canvas `body_timeout_reference_rejects_invalid_scenario_closure` mutation matrix is pure, but its `body_timeout_reference_cases` helper is also used by the live historical capture in the same target. Moving only the test would duplicate validation logic; making the acceptance crate its owner would create a development cycle with issuance; a new contract crate for one small helper is not justified without further consumers. Keep this control intact for now. The DIDComm CA-rotation test uses real loopback TLS, OpenSSL process ownership, and shared service fixtures, so it is not a mock-only behavioral matrix to relocate casually.

Test-inclusion audit (2026-10-03): `canvas_observation_values.rs` is source-included by the issuance behavior, Canvas management HTTP, and published Canvas targets, so its one diagnostic `#[test]` was compiled three times. `canvas_json_depth_replay.rs` is included by the latter two targets, so its one typed-token diagnostic test was compiled twice. These are genuine repeated pure assertions, unlike their surrounding HTTP/published-process cases. Local dedup commit `d4837f77b`, stacked on #1058 and not published, moves both unchanged assertion bodies into the already-required Canvas management HTTP test target. Both exact Rust tests pass; published composition and worker targets compile with no duplicate moved names. The focused runner/workflow-policy suite passes 231 tests, strict targeted Clippy and formatting pass, and an independent reviewer cleared the corrected diff. To avoid a separate full-CI cycle for two tiny tests, reviewed local integration branch `codex/canvas-acceptance-plus-dedup-20261003` at `8b453a5e4` combines this commit with the acceptance-owner follow-up: on that exact branch, the composition and acceptance-owned worker binaries compile and discover 141 and 134 tests. The independent combined review found no blocker; the mandatory-name roster remains dynamic and unchanged. Hosted Cargo artifact handoff, live Canvas, and protected queue CI are still required after #1058 merges.

First A4 slice: [UI #1060](https://github.com/ElevenID/marty-ui/pull/1060) moves the pure `python_value` module from issuance into the existing lightweight `marty-response-compat` crate, re-exporting the same implementation for current issuance callers. Its four unchanged unit tests now run in that crate; the separate signing diagnostic integration target uses the shared module instead of source-including it and rerunning those four tests. The target's own 12 frozen diagnostic tests remain, as do issuance's real HTTP signing-response tests. Locked offline checks passed for both crates; response-compat 20, signing contract 12, nearby issuance format 5, response-text 17, signing HTTP 7, and credentials protocol 3 tests passed. Strict targeted Clippy, rustfmt, and diff checks passed. An independent reviewer found and verified corrections to a stale documentation link and unused import, then cleared the exact head. Full PR and protected combined-head CI passed, including the live Canvas lane and aggregate gate; #1060 merged as `6aa6c3391`. This is one DRY ownership/test-level improvement; neither CI speed nor safety-gate reduction is yet measured or claimed.

A4 staged follow-up (2026-10-05, local head `67e810253`): the Envoy scalar YAML port/health-threshold matrix keeps its assertions but moves from the published-process support module to unit tests beside production `marty-release-evidence::envoy_config` parsing, rendering, and encoding. Test-only `serde_json` arbitrary precision preserves the feature-unification regression; actual Envoy image/process and runner obligations stay in acceptance. The same staged batch gives three pure self-host fixture controls one bundle-test owner without changing their assertions or the real CLI/Compose checks. On that combined head, 170 focused Python guards, the Envoy unit test, and all three self-host controls passed; touched Python Ruff and diff checks passed. Hosted/protected CI and any wall-time effect remain unverified.

CI incident on #1060: the first `Rust Lint and Packaging` job failed before invoking Clippy because `sccache` could not start its GitHub cache backend after a transient DNS lookup failure for the storage host. The job reported zero compiler requests; this was not a source lint failure or a passed lint gate. Once the workflow was terminal, a failed-job rerun on the unchanged head passed the mandatory full Clippy and packaging checks. Preserve the strict lint command and other gates. #1061's reviewed fallback subsequently passed protected queue validation and merged; its healthy-cache PR path and synthetic failure path pass, but a live backend outage was not induced.

Retain real PostgreSQL coverage for atomicity, locking, tenant isolation, recovery, and expiry after lock waits. Retain real TLS, signals, shutdown, and packaged-runtime coverage where those are the obligation. Controlled Tokio time applies to isolated Tokio scheduling, not database clocks or separate processes.

Replace an expensive assertion only after documenting its lower-level equivalent and the remaining integration proof. Preserve all unique cases and negative/security expectations. Keep independent expected observations independent: DRY must not make a test calculate its expected answer with the production implementation under test.

### A5: historical reference qualification

Fresh startup evidence candidate (2026-10-06): the existing startup acceptance test emits a run-specific record after the unchanged published-corpus comparison, native replay, and owned cleanup succeed. The record binds the main SHA, GitHub run/attempt/job, test executable digest, current capture-input pins and graph, corpus digest, pinned issuance/PostgreSQL images, observed Python/module hashes, and migration revisions checked by the existing harness. Upload requires a successful full Canvas job on scheduled/manual main and uses fourteen-day retention. External use must also verify the complete workflow result for that run and attempt. This is fresh-run startup evidence; it neither retroactively attests the original raw captures nor authorizes qualification reuse or additional skips. Six isolated Rust helper tests pass without compiling the entire acceptance stack, including rejection of an existing record without overwriting it; the assembled integration and first live record still require hosted validation.

Identify the complete reference closure: historical image digest, capture code and helpers, scenarios, schema/migrations, expected corpus, and relevant execution environment. Native comparisons remain responsive to native changes.

Initial source audit: `contracts/canvas-worker-consumer-range-oracle.json` records the historical issuance and PostgreSQL image digests, source and repository hashes, migration revision, and observation digest. Individual worker oracles also record capture-source hashes. The historical tests in `canvas_published_schema_contract.rs` start a pinned image/database through `support/canvas_published_database.rs`, check the migration report and worker source hash, then compare the live observation with embedded corpora. They return early without `MARTY_CANVAS_PUBLISHED_SCHEMA_TEST=1`; the CI runner sets this and requires explicit named tests. `scripts/ci/run-published-canvas-contracts.sh` pulls both pinned images before its full group. These provenance checks are useful, but the complete capture helper/scenario/schema closure has not yet been proven from one manifest. Do not reuse old qualification evidence or reduce reference frequency until that closure is complete and checked for staleness.

Lease-expiry case audit (2026-10-03): `run_canvas_worker_lease_expiry_oracle.py` validates its scenario's source hashes, environment, two cases, and scheduled body offsets. Its `capture_source_sha256` includes the lease script and scenario plus the body-timeout oracle's helper/script/contract list; `prepare_canvas_published_schema.py` additionally validates historical worker and migration inputs. The failing #1044 observation occurred *after* the reference worker reached idle and the delayed response handlers joined. The source closure is spread across Python, the Rust database harness, mounted helpers, pinned images, migrations, and runtime dependency versions. A single provenance field or unchanged lease script therefore cannot authorize skipping this qualification; the observed failure must be understood independently of A5 optimization.

Capture-closure breadth check (2026-10-03): of 39 committed `canvas-worker-*-oracle.json` corpora, only body-timeout and lease-expiry expose `capture_source_sha256` maps. A read-only AST traversal of their pinned local Python scripts found no unpinned static local import after #1055's guard; this is evidence only for those two captures. Other corpora expose differing provenance fields, often `source_sha256` for installed worker code rather than a complete capture-helper closure. Do not generalize historical-qualification reuse to the entire worker suite from the two guarded corpora. Inventory each remaining capture's scenario, helper, runtime, image, and schema inputs before proposing narrower triggers.

Field census on the current acceptance-owner base: 37 of those 39 corpus files contain a `source_sha256` field somewhere in their JSON, but only two contain `capture_source_sha256`; `canvas-worker-configuration-oracle.json` and `canvas-worker-result-oracle.json` lack the former field. The common `worker_source_sha256()` helper in `run_canvas_worker_startup_oracle.py` hashes installed `issuance.canvas_worker` and `issuance.infrastructure.api.canvas_routes` modules, not the capture script or its transitive helpers. Therefore the common source hash is evidence for published implementation identity, not sufficient evidence for capture-code reuse. This is a field-presence audit, not a complete provenance classification of all 39 corpora.

Shared-capture dependency check (2026-10-03): 17 `run_canvas_worker_*oracle.py` scripts statically import `run_canvas_worker_startup_oracle.py`. The startup script reads `canvas-worker-startup-scenarios.json` and supplies process/database helpers as well as `worker_source_sha256()`, but `canvas-worker-startup-oracle.json` records only the two installed-module hashes and the Python version, not hashes of that script or its scenario input. This is a concrete shared input that an eventual qualification-reuse key must include or conservatively invalidate; it does not authorize a narrower current CI trigger.

Startup-input guard candidate (2026-10-06, based on merged #1121): `canvas-worker-startup-current-inputs.json` pins normalized source hashes for the startup script, its scenario, and the conditional single-cycle child script. All eight current startup scenarios omit `observe_cycle_result`, so this child is a conservatively tracked *potential* input, not an observed execution path. A focused test expands the #1121 script-import/process/scenario graph and rejects a changed input, new direct local helper, or changed closure. The startup script and child currently have no directly imported local helper; a new one would require an explicit hash. This is current-repository input evidence only, **not** proof that the existing historical startup corpus was captured with these exact bytes. The corpus, expected observations, live qualification frequency, and release gates are unchanged. The new Rust evidence reader requires graph and sidecar changes to select both Rust and release checks. A future reuse decision still needs a live recapture or independently verifiable historical input attestation, pinned image/database and runtime closure, and run-bound output evidence.

Producer-mapping census (2026-10-03, current main): 39 `canvas-worker-*-oracle.json` corpora coexist with 26 `run_canvas_worker_*oracle.py` scripts and 37 `canvas-worker-*-scenarios.json` files. Only 26 corpus basenames map directly to a same-named runner; the others include metadata/reference corpora and multiple OAuth-revocation variants emitted by one runner. The OAuth producer also recursively loads `base_scenario`, then `reference_scenario` and `shared_seed` JSON from the selected matrix. A qualification-input manifest therefore needs explicit corpus-to-producer and transitive scenario edges rather than deriving them from names. This count is an inventory, not proof that all transitive helpers, images, or runtime inputs have been found; live historical qualification remains required.

Producer-inventory implementation (2026-10-03): UI [#1073](https://github.com/ElevenID/marty-ui/pull/1073), head `df4232a09`, records the 26 direct runner corpora, nine additional variants of the shared OAuth runner, and four copied upstream Credentials fixtures with provenance-document links. A focused test fails on unowned corpora or runner scripts and checks the OAuth runner's declared ten-kind dispatch set. An independent reviewer traced all ten variants through the Rust published-process launcher and Python dispatcher and found no mapping mismatch; one local test and Ruff pass. Full PR CI and protected combined-head [run 37158251847](https://github.com/ElevenID/marty-ui/actions/runs/37158251847) passed, including Canvas and final gate, and the PR merged into main as `f023168ca` at 2026-10-03 23:24:09 UTC. The protected Canvas job took 59m18s, including 22m34s in the database group; this inventory-only change has no attributable speedup. The manifest explicitly disclaims complete capture-input closure or permission to reuse qualification; no check frequency changes.

Preparer-dispatch closure [UI #1110](https://github.com/ElevenID/marty-ui/pull/1110) merged: the producer inventory checks that its 25 preparer-owned worker runners match the actual static dispatch in `prepare_canvas_published_schema.py`, and records the logging runner's separate CI launcher. This guards one previously unverified producer-to-execution edge; it does not establish complete capture inputs, authorize historical-evidence reuse, alter native regression, or reduce live qualification frequency. The PR passed protected CI.

Scenario-closure follow-up [UI #1076](https://github.com/ElevenID/marty-ui/pull/1076), reviewed head `61cb23258`, adds explicit owners for the two scenario files without same-named corpora (final-completion race and image startup), so all 37 `canvas-worker-*-scenarios.json` files have an inventory owner. Its test recursively validates JSON filenames and JSON-pointer targets, detects scenario cycles, and covers references such as `base_scenario`, `reference_scenario`, `shared_seed`, and the final-completion-race pointers. A reviewer caught an initial pointer-discovery gap before the rebase; the corrected implementation passes its three focused inventory tests and Ruff on the new main. Independent exact-head review found no blocker; full PR [run 37161785874](https://github.com/ElevenID/marty-ui/actions/runs/37161785874) passed, including Canvas and final gate, and the head entered the protected merge queue at 2026-10-04 00:27:47 UTC. At that observation point, protected combined-head validation and merge had not completed; the linked PR is authoritative for its later outcome. This still does not prove capture-script, image, migration, runtime, or environment closure, nor authorize a qualification skip.

CI gate telemetry incident (2026-10-03): #1071's protected combined-head run passed mandatory lanes, including Canvas, but `CI Gate` failed when its later performance-summary call to the GitHub Actions API returned HTTP 503. The queue entry was removed and its next candidate required another full run. UI [#1074](https://github.com/ElevenID/marty-ui/pull/1074), reviewed head `7692dc933`, retries only transient 502/503/504 responses for the two telemetry API calls and makes only the reporting step non-fatal. The preceding `Require every CI lane` assertion, required gate job, and merge-group all-success policy remain strict. All 98 workflow-policy tests, Ruff, and diff checks pass locally; an independent reviewer found no blocker. Full PR CI and protected combined-head [run 37161534388](https://github.com/ElevenID/marty-ui/actions/runs/37161534388) passed, including Canvas and final gate; the PR merged into main as `246ec57e2` at 2026-10-04 00:17:49 UTC. Protected Canvas took 54m14s, including 19m00s for database contracts. The new reporting fallback was not exercised by a live API outage, and no turnaround saving is measured yet.

At the #1044 failure, the post-join assertion combined `assert_schedule(...) == chunks` and `observe() == outcome` under one failure message. That failure could not identify whether the HTTPS write ledger or durable snapshot changed. The later #1055 diagnostic split retained both equality requirements and updated the capture-source provenance because the oracle script participates in the historical closure.

The diagnostic follow-up merged in [UI #1055](https://github.com/ElevenID/marty-ui/pull/1055). Sequential `require` calls preserve the original short-circuit order and both equality checks while naming body-schedule versus durable-observation drift. Only two lease-script source-hash values changed in the frozen lease corpus; an exact reverse-migration test reconstructs the pre-diagnostic corpus hash and earlier independent A/B capture. Native replay pin and documentation were updated. Focused local tests, independent review, and hosted published-process regeneration passed. This diagnostic does not explain the earlier intermittent observation by itself.

At the initial audit, one concrete closure gap was that `canvas_worker_https_fixture.py` imported `create_loopback_certificate` from `test_canvas_lti_https.py`, while `run_canvas_worker_body_timeout_oracle.verify_sources` omitted that helper. Lease-expiry provenance inherited the omission through `body.verify_sources`. The next paragraph records the merged #1050 repair: current main pins the helper in both body and lease capture provenance. This historical finding must not be reopened as a current gap.

Merged [UI #1050](https://github.com/ElevenID/marty-ui/pull/1050) implements that first closure repair. The two frozen corpora change only by the helper pin and updated capture-script hash; exact reverse-migration tests reconstruct both prior byte hashes and the earlier independent A/B hashes. Native replay pins and input counts were updated. A reviewer worker identified and verified fixes to those consumers and stale documentation; 479 focused local tests passed (504 in the independent review run). Protected CI, including live published-process regeneration, passed. This does not yet justify reusing or skipping historical qualification.

Merged regression-prevention follow-up [UI #1055](https://github.com/ElevenID/marty-ui/pull/1055) walks every pinned Python script in both body and lease corpora and checks statically imported flat `scripts/*.py` helpers are also pinned. Relative/local-package imports and common dynamic-import calls fail closed for manual review. Synthetic tests cover direct, transitive, relative, dotted-package, and dynamic cases; 771 focused body/lease tests passed and an independent exact-head reviewer cleared the change. Full PR and protected combined-head CI passed, including live published-process qualification. This is not proof of every possible dynamic Python import mechanism or full image/environment validity; preserve live qualification until the broader closure is established.

Current-input REST follow-up (2026-10-07): the
shared `run_canvas_worker_rest_oracle.py` helper is directly imported by 18
capture runners. A normalized-hash sidecar and focused drift tests pin its
bounded static import/child graph: five scripts, the REST/startup scenario
files, and the REST default's transitive issued-review shared seed. This
reuses the startup input verifier and the scenario inventory's JSON-reference
discovery instead of maintaining separate hashing or reference algorithms.
Startup's scenario file and single-cycle child are
conservatively included as potential graph inputs; caller-selected scenarios
outside the REST default are not attested by this sidecar. Changes to a pinned
byte sequence, newly imported helper, or newly discovered literal/template
scenario require review. The sidecar is excluded from runtime image contexts
and selects Rust plus release checks; its exact test-only source selects the
release owner. This is current repository input evidence, not historical
capture attestation, complete image/schema/runtime closure, a changed frozen
observation, or permission to reduce live qualification frequency.
[UI #1144](https://github.com/ElevenID/marty-ui/pull/1144) passed full
[PR](https://github.com/ElevenID/marty-ui/actions/runs/37600734527) and
[protected](https://github.com/ElevenID/marty-ui/actions/runs/37605210608)
CI, including 144 composition and 101 worker tests (two intentional ignores)
and 602 successful Canvas timing rows in each run, then merged as
`2300a8582d`. Its exact preflight-test source selector has no measured
scoped-PR saving yet.

Separate reference qualification first without skipping it. Reduce its frequency only after evidence is bound to the complete closure and stale/missing evidence forces verification. Reference input changes trigger requalification; preserve periodic full comparison to detect environment drift. A version label alone is not evidence validity.

### A6-A7: rollout and fast feedback

During rollout, keep broad merge validation while proving selection. The intended steady state is affected package tests and contracts during development, broad checks for shared/unknown inputs, and qualification of actual release artifacts. Periodic exhaustive compatibility runs supplement required change-specific checks. Full validation must not wait for a major version increment.

Concrete broad-classifier cost (2026-10-03): [UI #1065](https://github.com/ElevenID/marty-ui/pull/1065) changes only runner-registration PowerShell, its focused policy helper/tests, and runner documentation, but the current `tests/*|scripts/*` rule sets `all=true`; its PR therefore runs the entire Rust, UI, Python, release, browser, and security matrix. The repository release-check step actually executed all eight new PowerShell cases and 5,405 tests, while the Rust Canvas lane set the PR critical path at 58m56s. This is a plausible later A6 path-selection candidate, not permission to omit lanes now: first prove every transitive consumer of these scripts/tests, keep unknown/shared inputs broad, land the planned-versus-unexpected skip gate, and retain all-success protected merge-group validation. The present full run proves the baseline cost, not a speed gain from selection.

Ensure cheap failures can be reported promptly. Additional lanes must justify their compilation/setup cost and retain every required obligation. For Core, examine the 14m23s preflight before separating work; preserve its feature/security matrix and avoid merely duplicating builds.

Current Core evidence supports deferring a preflight split. In protected #348, preflight completed in 11m43s while affected Rust tests took 13m56s and Rust CodeQL took 12m25s. Its cheap Python/release, advisory, and formatting checks already precede compilation. Within preflight, exact KMS graphs took 369s, trusted-list client 136s, clippy 104s, and WASM serial fallback 63s. Parallelizing these into another runner would duplicate setup/compilation without reducing this run's 13m56s test critical path. Revisit A7 if repeated normal runs place preflight on the critical path or if evidence shows an independently cacheable setup; keep the full feature/security matrix.

A7 refresh (2026-10-05, pre-incident runs): Core PR [37098640425](https://github.com/ElevenID/marty-core/actions/runs/37098640425) ran preflight in 11m43s versus affected Rust tests in 13m56s; PR [37101783100](https://github.com/ElevenID/marty-core/actions/runs/37101783100) took 16m53s versus 18m29s. Protected [37099476951](https://github.com/ElevenID/marty-core/actions/runs/37099476951) ran preflight in 14m29s versus the Windows platform lane in 19m10s. These parallel-lane samples do not put preflight on the critical path; its expensive steps compile Rust and offer no independently cacheable setup proven by this audit. Keep A7 deferred, without counting the 2026-10-05 hosted-runner assignment incident as execution time.

A7 refresh (2026-10-07): Core PR [#352 run 37419154761](https://github.com/ElevenID/marty-core/actions/runs/37419154761) ran preflight in 10m52s versus affected Rust tests in 13m41s; [#353 run 37460823351](https://github.com/ElevenID/marty-core/actions/runs/37460823351) took 12m30s versus 18m30s. Protected [#352 run 37420390043](https://github.com/ElevenID/marty-core/actions/runs/37420390043) ran preflight in 15m02s versus Windows in 16m49s; [#353 run 37463564302](https://github.com/ElevenID/marty-core/actions/runs/37463564302) took 12m43s versus Windows in 18m26s. Across these four completed runs preflight is not the critical path. A new runner split would add setup and compiler work without a measured turnaround benefit, so the full feature/security matrix stays intact and A7 remains deferred.

A7 refresh (2026-10-08): The latest normal CI for draft Core #355, [run 37844023348](https://github.com/ElevenID/marty-core/actions/runs/37844023348) at `d41d87c`, ran preflight for 14m07s (21:06:33–21:20:40 UTC), versus affected Rust tests 9m08s and Native ZKP security 8m23s; the CI gate started three seconds after preflight ended. Earlier successful #355 revisions [37841791644](https://github.com/ElevenID/marty-core/actions/runs/37841791644) and [37839304785](https://github.com/ElevenID/marty-core/actions/runs/37839304785) also ended on preflight: 12m37s versus 9m59s affected tests / 10m39s ZKP, and 18m16s versus 10m08s / 10m32s, respectively. These are three revisions of **one** security PR, not independent workload samples. In contrast, #354's [normal run 37826531572](https://github.com/ElevenID/marty-core/actions/runs/37826531572) ended on affected tests (18m06s versus 12m54s preflight); its [protected run 37828982922](https://github.com/ElevenID/marty-core/actions/runs/37828982922) ended on the protocols feature lane (17m04s versus 16m52s preflight). In #355's latest preflight, KMS graphs took 7m03s, its new OpenBao issuer proof 2m39s, workspace Clippy 1m47s, WASM fallback 1m03s, and EUDI client 1m02s. Cheap policy/format/setup checks already lead the job; the expensive steps share Cargo inputs and compiler cache on its runner. Splitting them into another job would add runner/toolchain/cache startup and potentially repeated compilation, while a same-runner split cannot shorten the gate. No independently cacheable or no-extra-cost split is demonstrated, and no speedup is claimed. Keep A7 deferred and all feature/security gates intact; remeasure across independent normal PR workloads before authorizing a split.

A7 refresh (2026-10-10): Two independent normal dependency PRs now provide the requested workload check. [UUID run 38029628248](https://github.com/ElevenID/marty-core/actions/runs/38029628248) finished preflight at 06:19:56 UTC, after affected Rust tests at 06:19:23; its KMS graph step took 8m09s, workspace Clippy 2m18s, and EUDI client 3m39s. [cc run 38029635868](https://github.com/ElevenID/marty-core/actions/runs/38029635868) finished affected tests at 06:22:16, after preflight at 06:17:51; its KMS graphs took 6m33s, Clippy 2m16s, and EUDI client 3m22s. Thus preflight can be last, but is not consistently the gate tail even across two dependency inputs. These checks deliberately share a Cargo target/cache within their job and test different feature/security obligations. A separate runner has no demonstrated reusable compiled artifact or duration advantage; preserve all checks and defer splitting until a same-obligation, comparable pilot proves faster feedback or completion.

### A8: release-tier E2E and demo strategy

Classify release authority from an authenticated claim/manifest and exact version/tag, not from a mutable dispatch input or a guessed substring. The tag parser in this branch validates syntax only; it does not authorize deployment or publication. Unknown, missing, or inconsistent classifications fail closed. Keep routine PR/unit/integration/security checks and deployment preflights independent of this tier decision.

2026-10-05 planning update: apply release tiers to **every test layer**, not just E2E. The desired nightly qualification is a deliberately small happy-path slice of affected unit, contract/integration, and released-stack E2E tests on one Linux target. The exhaustive negative/error/recovery and cross-platform matrices at lower layers belong to major-version qualification, while the user confirmed that *every* official stable release, including minor and patch, retains complete E2E evidence. This is a target structure, not permission to skip an existing required check before its obligation is mapped and an equivalent gate is proved.

| Trigger | Intended test shape | Required evidence and transition rule |
| --- | --- | --- |
| Development PR | Fast affected unit tests and focused contract checks first; keep lint, security, and high-risk negative tests that directly guard changed behavior. | Report cheap failures before expensive image/process work. Existing protected merge-group validation remains full until exact affected-input selection and fail-closed skip behavior are proven. |
| Nightly prerelease | Happy-path cases only at unit, integration/contract, and E2E layers; few released-stack journeys on one Linux target. | Each selected layer must execute and publish case IDs/results tied to the immutable nightly tag and exact artifacts. No denial/error/recovery E2E, full historical qualification, recording, or YouTube dispatch in the nightly release transaction. Independent repository/security checks are not reclassified as nightly release tests. |
| Major-version qualification | Complete applicable matrices at every layer, including happy, negative, error/recovery, security, compatibility, historical-oracle, real database/process, and justified platform checks. | Bind results to the exact candidate artifacts before promotion; fail closed on missing cases or evidence. Maintain a small independent E2E cap by moving most case variation to lower layers, not by losing scenarios. |
| Official minor/patch release | Complete happy, denial/error/recovery, and other applicable released-stack E2E journeys; lower-layer exhaustive matrices need not repeat solely because the stable version is minor/patch, except for affected, security, or release-critical obligations. | Preserve exact-artifact full E2E evidence, release preflights, and official-only YouTube policy. A nightly result cannot qualify an official release. |

Implementation batches: (1) inventory and label existing cases across repositories by layer, tier, owner, and unique obligation; (2) move redundant behavioral matrices into owned fast unit/contract suites with realistic mocks and retained real-boundary sentinels; (3) make cheap affected checks report first while shadow-comparing selection with full runs; (4) add authenticated nightly/major manifests and fail-closed dispatch; (5) route E2E/demo jobs and verify exact-artifact evidence, then measure normal PR, nightly, and major runs. Batch related code, tests, policy, and documentation by owner so each reviewed PR pays for one CI cycle where practical. Do not use a major-only schedule as a substitute for change-specific security or regression checks.

Nightly E2E prerequisite audit (2026-10-05): the integration repository's artifact-only OSS stack suite has four positive availability/discovery smoke cases, but no fail-closed released-stack credential issuance-and-verification journey. Its issuer happy-flow test needs auth/organization/template fixtures absent from the OSS Compose gate, can report failure outside pytest, and stops before verification; its passport E2E skeleton may skip when endpoints are undeployed. A selected smoke subset therefore cannot be labeled nightly product qualification. Build a real positive journey against the digest-pinned stack with disposable fixtures and no skip, then bind per-case results to the immutable nightly tag, manifest digest, and deployed artifacts before a separate qualification or promotion transaction is considered. The no-write nightly claim in this batch authorizes neither. Keep the official full suite unchanged.

Nightly journey follow-up (2026-10-05): integration [#425](https://github.com/ElevenID/marty-integration-tests/pull/425) merged a five-case positive selector by adding one real Flow-to-Issuance-to-gateway credential-receipt case to four existing smoke cases; the official eight-case OSS suite remains intact. The new case checks JWT-VC structure and event correlation, not cryptographic verification. A local feasibility audit found that the released Flow verifier endpoint requires an authorized `verification:execute` principal, while the OSS-stack fixture provides only static OIDC discovery, not a login/session provider. Its configured `oss-ci-credential-login` policy alias also does not match the released Open Badge UUID policy seed. Do not label #425 a verified nightly product journey or substitute a mock/bypass. Provision a real disposable principal and matching policy through the released stack, then execute wallet presentation and verifier acceptance against exact pinned artifacts; retain full official E2E qualification.

Recorder boundary audit (2026-10-05): `marty-demo-recorder`'s external and release qualification paths force video capture, require video evidence for the portfolio, and accept only stable official deployment identity; the underlying UI audit scripts include denial/recovery steps even when video is disabled. Do not reuse those workflows by toggling a recording flag. After the real nightly artifact and positive journey exist, expose a separate assertion-only runner with strict nightly identity and case evidence; retain the official full/recorded qualification path unchanged.

- Nightly releases use a distinct immutable SemVer prerelease tag with a date and unique run component, such as `v1.2.1-nightly.20261005.123456789`. Run representative, owned happy-path E2E/demo assertions against the exact released stack on one Linux target, retaining machine-readable results and artifact lineage. Do not dispatch release-bound recording or YouTube staging/publication. This is not complete product evidence.
- Official production releases retain the complete applicable E2E inventory: happy, denial/error/recovery, external-device/provider, and release-bound evidence checks on the exact release artifacts before promotion. Only this tier may create, approve, or publish release-bound YouTube recordings. Beta, RC, and other prerelease identities are not silently reclassified as official or nightly.
- Map scenario and evidence owners across `marty-ui`, `marty-integration-tests`, and `marty-demo-recorder`; keep justified OS-specific unit, packaging, and portability checks even though nightly E2E uses one Linux target. Separate lower-level owned assertions, nightly happy journeys, and official full journeys without using video as an assertion substitute.
- Test manual, scheduled, retry/resume, and repository-dispatch routes so nightlies cannot invoke official-only error/full-suite or YouTube paths and official releases cannot accept a partial nightly result. Bind each path to verified release identity and fail closed on missing evidence.

Bundle related code, policy, tests, and documentation into reviewed PRs to limit redundant CI runs. First establish exact release identity and release-time qualification; then implement authenticated nightly claim/dispatch and assertion-only intake; finally route the full scenario and YouTube jobs. Do not relabel a partial or failed result as qualified. Measure real nightly/official runs before claiming speedup.

Repeat check (2026-10-03): in two successful Core PR runs, preflight took 11.7m versus affected tests 13.9m ([37098640425](https://github.com/ElevenID/marty-core/actions/runs/37098640425)) and 16.9m versus affected tests 18.5m ([37101783100](https://github.com/ElevenID/marty-core/actions/runs/37101783100)). The successful protected run [37099476951](https://github.com/ElevenID/marty-core/actions/runs/37099476951) took 14.5m in preflight versus 19.2m in the Windows platform lane. These three distinct runs again place another required lane on the critical path; a preflight split is not yet an evidence-backed wall-time improvement. The preflight may still be worth reorganizing for earlier diagnostic output, but that requires per-step failure timing and cannot drop the existing KMS/security/feature checks.

A6 first selective-PR observation (2026-10-04): after inventory-only selector [#1080](https://github.com/ElevenID/marty-ui/pull/1080) merged, its follow-up [#1082](https://github.com/ElevenID/marty-ui/pull/1082) completed [PR CI](https://github.com/ElevenID/marty-ui/actions/runs/37185053263) in 8m37s (07:11:50–07:20:27 UTC). Release Contract Tests and the final CI Gate passed; the Rust Canvas lane was not scheduled for those exact inventory inputs. Protected combined-head validation remained full, and #1082 merged. This is observed turnaround for that scoped PR, not a whole-repository average or a claim that the Canvas lane itself became faster.

A6 frozen-reference test-source follow-up (2026-10-05, local review): `tests/test_signing_response_reference.py`, `tests/test_token_rate_reference.py`, and `tests/test_canvas_url_template_reference.py` are exact root test sources collected by Release Contract Tests (`python -m pytest tests -v --tb=short`), with no other CI collector or service-image copy of root tests. The signing test parses pinned capture literals with standard-library AST/JSON; the token-rate test imports only its standard-library capture module; the Canvas URL test imports its capture module and standard-library mirror/output helpers, using controlled children rather than application imports. Native Rust tests consume their frozen `contracts/*` corpora, so corpus changes still select Rust; `scripts/*`, implementation, unknown paths, and protected merge groups remain broad. The PR security lane audits dependency lockfiles and scans `services/ packages/`, not root test modules, so this exact test-source routing does not drop a scanned-source or dependency-audit obligation. This is a proposed path-selection change, not a measured speedup; record hosted PR and protected evidence before making a saving claim.

Canvas critical-path recheck (2026-10-05): three successful hosted jobs ([37354695543](https://github.com/ElevenID/marty-ui/actions/runs/37354695543), [37357666719](https://github.com/ElevenID/marty-ui/actions/runs/37357666719), [37345250763](https://github.com/ElevenID/marty-ui/actions/runs/37345250763)) spent 340–378 seconds compiling workspace tests, 568–583 seconds on separate Bookworm ABI acceptance compilation, 729–771 seconds building the exact public self-host image, and 800–815 seconds in published Canvas contracts. The composition and worker executables already run concurrently within that final group; the 49-second JSON diagnostic is deliberately isolated under its own deadline. No additional overlap is justified yet: the image and ABI builds produce distinct required artifacts, and concurrent CPU/Docker load on a four-core runner could destabilize timeout-sensitive contracts. Preserve these checks; revisit only with artifact identity and resource-contention evidence, rather than claiming a speculative speedup.

## Review, validation, and coordination

1. Start each implementation PR from current upstream main in an isolated worktree. Claim its tracker row and list affected paths; avoid overlapping ownership of manifests, fixture helpers, and workflow selectors.
2. Write the behavioral and coverage invariants before editing. Identify shared Rust code to reuse and any temporary compatibility layer to remove later.
3. Run package-scoped checks, targeted tests, and relevant workflow/packaging validation. Reserve expensive full runs for meaningful milestones and existing protected CI; do not rerun them after every small edit without a reason.
4. Self-review the complete diff and dependency/test-selection changes. Have a reviewer worker examine implementation PRs for regressions, missed inputs, boundary leaks, and coverage loss, following the user's established review loop.
5. Resolve findings and review again. Record validation against the reviewed commit; invalidate affected evidence after subsequent changes. Do not merge with unresolved correctness, security, or coverage findings or failed required checks.
6. Merge ready maintenance PRs through the existing protected process. Preserve tests, features, environment approvals, and the open-source/free-tier constraint. Record PR, merge SHA, checks, reviewer disposition, and any justified deviations here.
7. Verify normal post-merge behavior at milestones and compare equivalent job/step timings. Distinguish execution time, compilation, setup, queue/approval delay, and runner work; report warm/cold conditions and uncertainty.

Self-review specifically checks error paths, tenant/security boundaries, feature combinations, ownership/cleanup, public interfaces, dependency changes, and whether a test really executed its intended scenario. For selection changes, it also checks negative cases and conservative fallback behavior.

## Progress and decisions

| Date | Item | Decision / result | Evidence |
| --- | --- | --- | --- |
| 2026-10-02 | Plan | User requested a coordination document and active implementation goal, with self-review, regression prevention, and Rust reuse/DRY | Conversation authorization |
| 2026-10-02 | Baseline | Architecture investigation complete; implementation and speed estimates remain unverified | Baseline above |
| 2026-10-03 UTC | A1 first slice | 100 policy checks; selected Rust compile/list; Docker chef filtered planner; real disposable Redis/OpenBao/OpenSSL acceptance passed locally. Reviewer worker found no blocking issue. | UI #1044, source blob unchanged; full CI pending |
| 2026-10-03 UTC | A3 Core first slice | 104 script tests passed, including actual Git deletion/rename and Unicode-path checks; actual locked Cargo metadata probes select fixture/native-code consumers. Reviewer found no blocking issue; full gates retained. | Core #348, `e877f8c`; Git/metadata failures still fail closed, non-Cargo relationships remain future work |
| 2026-10-03 UTC | A2 first slice | Six existing lossless text/JSON modules moved to an independently testable crate with an optional PostgreSQL adapter and issuance module re-exports. Existing 16 unit tests pass under default features; issuance library check with PostgreSQL and three focused protocol tests pass. First CI run exposed the separate feature-probe lock; corrected with a minimal lock update and locked offline resolution. Reviewer found no blocking issue on either slice. Fresh PR checks passed, including the Canvas lane. The reviewed head entered the required merge queue at position 1; combined-head validation is running. | [UI #1045](https://github.com/ElevenID/marty-ui/pull/1045), `7502053e9`; [queue CI](https://github.com/ElevenID/marty-ui/actions/runs/37102861640); no timing claim yet |
| 2026-10-03 UTC | A2 merged | #1045's protected merge-queue CI passed, including the Canvas lane (60m37s) and final CI gate, then merged into main as `d9947b312`. This is a maintainability boundary; no compile-time saving is yet measured. | [UI #1045](https://github.com/ElevenID/marty-ui/pull/1045), [queue run](https://github.com/ElevenID/marty-ui/actions/runs/37102861640) |
| 2026-10-03 UTC | A1 integration review | Merged current UI main into #1044 and resolved the sole workspace-member conflict by retaining both `response-compat` and `service-acceptance`. Locked offline metadata recognized both; main and feature-probe locks include the response-compat edge; 125 workflow/release policy tests passed. Independent reviewer found no integration defect. The Windows host defaults to Rust 1.93 while the workspace requires 1.95; a 1.95 targeted test compile was stopped during a cold dependency rebuild. Full protected CI is pending on updated head `45faa5219`. | [UI #1044](https://github.com/ElevenID/marty-ui/pull/1044), `45faa5219` |
| 2026-10-03 UTC | A3 Core first slice merged | Required PR checks and merge-queue checks passed; main contains the hardened selector and bounded OB2 extension. The merge-queue critical path was the Windows platform job (19m10s); fast Rust preflight took 14m29s. | [Core #348](https://github.com/ElevenID/marty-core/pull/348), merge `466278aa`; [queue run](https://github.com/ElevenID/marty-core/actions/runs/37099476951) |
| 2026-10-03 UTC | A3 UI shadow observation | The planner ran in ordinary CI and conservatively selected all 23 Rust packages for its own workflow change, reporting `external or unknown input: .github/workflows/ci.yml`. This demonstrates the fallback, not selective-gate agreement; full gates remain active. | [UI #1046](https://github.com/ElevenID/marty-ui/pull/1046), [lint job](https://github.com/ElevenID/marty-ui/actions/runs/37100105547/job/111137825084) |
| 2026-10-03 UTC | A3 UI shadow queue | The reviewed #1046 head passed all PR checks, including Canvas, and entered the required merge queue at position 2 behind #1045. Combined-head validation and main merge remain pending. | [UI #1046](https://github.com/ElevenID/marty-ui/pull/1046), `fec8b0848` |
| 2026-10-03 UTC | A3 UI shadow merged | #1046's protected merge-queue CI passed, including Canvas (64m11s), and the final CI gate; main contains the conservative shadow planner. It reports candidate affected packages but cannot omit a check. Non-Cargo closure and observed decision agreement remain prerequisites to promotion. | [UI #1046](https://github.com/ElevenID/marty-ui/pull/1046), merge `cafdd4a7`; [queue run](https://github.com/ElevenID/marty-ui/actions/runs/37103393732) |
| 2026-10-03 UTC | A1 CI investigation | UI #1044's Canvas group failed 269 passed / 1 failed in unchanged `worker_lease_expiry_reference_matches_published_process`: the historical oracle reported that its post-join observation changed. The relevant Rust/Python oracle files are unchanged by #1044. The failed jobs were rerun as attempt 2; independently running UI #1045 will exercise the same group. Keep #1044 unmergeable until a green validation and cause assessment; do not relax the historical assertion. | [UI #1044 run](https://github.com/ElevenID/marty-ui/actions/runs/37097869187), first failed Canvas job `111131416212` |
| 2026-10-03 UTC | A1 Canvas retry | The unchanged lease-expiry historical oracle passed on attempt 2; the Canvas group finished 270 passed / 0 failed / 2 ignored. This establishes a non-deterministic observation, not a cause. Keep the oracle assertion and the full gate; investigate its post-join timing and independently validate the assembled PR before merge. | [UI #1044 rerun](https://github.com/ElevenID/marty-ui/actions/runs/37097869187), Canvas job `111141165631` |
| 2026-10-03 UTC | A4 candidate check | `canvas_legacy_ingest_behavior.rs` already runs its feature/tenant/template/status failure matrix against a mock repository and asserts no commit. This is a fast behavioral level *within* the large issuance test target; moving or deleting it without a narrower production boundary would not remove a duplicate system obligation. Keep it intact while evaluating a justified crate split. | `marty-ui/rust/services/issuance/tests/canvas_legacy_ingest_behavior.rs`, `runtime_binding_feature_tenant_template_status_and_requirement_failures_are_exact` |
| 2026-10-03 UTC | A3 classifier gap and fix | UI's top-level PR classifier used line-delimited `git diff --name-only` in process substitution. Rename detection could hide the old endpoint, newline-bearing names were not preserved, and process-substitution failures might not propagate to `mapfile`. [UI #1047](https://github.com/ElevenID/marty-ui/pull/1047) now uses a checked NUL-delimited `--no-renames` diff; 92 workflow-policy tests passed locally, including newline, real rename, and diff-failure cases. Reviewer worker found no blockers. Protected CI and merge pending; full existing gates remain active. | UI #1047, `5c3f3e8a4` |
| 2026-10-03 UTC | A3 classifier protected validation | UI #1047's full PR CI passed, including the Canvas lane, required CI gate, CodeQL, and workflow policy. The independently reviewed head entered the protected merge queue at position 3. Combined-head validation and merge remain pending. | [UI #1047](https://github.com/ElevenID/marty-ui/pull/1047), `5c3f3e8a4` |
| 2026-10-03 UTC | UI integration preview | `git merge-tree --write-tree` found one content conflict between #1044 and #1045: the workspace member line in `rust/Cargo.toml` must contain both `service-acceptance` and `response-compat`. The lockfile and issuance manifest auto-merge in this preview. #1044+#1046 and #1046+#1047 preview without conflicts. Do not push a base update while #1044's failed-job rerun is live; resolve and revalidate after #1045's queue result. | Reviewed heads `d05d5f0b6`, `7502053e9`, `fec8b0848`, `5c3f3e8a4` |
| 2026-10-03 UTC | A4 duplicate-run triage | Issuance has 49 integration-test targets, one being `canvas_published_schema_contract`. The contracts lane's existing workspace+database step completed in 1m22s on #1045 (05:26:28–05:27:50 UTC), while the separate Canvas lane dominated that PR's feedback. Excluding the Canvas target from the default workspace run would require target enumeration and execution parity proof but has no demonstrated critical-path payoff; keep the tests and prioritize the larger boundary. | [UI #1045 contracts job](https://github.com/ElevenID/marty-ui/actions/runs/37099418344/job/111135952854), local locked Cargo metadata |
| 2026-10-03 UTC | A0/A3 non-Cargo dependency probe | Cargo reverse closure labels `marty-notification` a leaf, but Applicant sends notification events over HTTP (`NOTIFICATION_EVENT_INGEST_URL` / `NOTIFICATION_SERVICE_URL`), Gateway routes `/notifications` to the service, and rendered self-host/Kubernetes profiles wire its URL. A notification change cannot safely select only its Cargo package; map and prove the HTTP/deployment consumers before narrowing any gate. | `rust/services/applicant/src/main.rs`, `providers.rs`; `rust/services/gateway/src/config.rs`; `rust/crates/selfhost-bundle/tests/support/resolved_selfhost_runtime.rs` |
| 2026-10-03 UTC | Free-tier cache pressure | UI had 10.73 GB of active Actions caches across 4,877 entries, near the repository's 10 GiB default allowance. PR-scoped uv and Playwright caches occupied about 3.0 GiB, with no corresponding main-branch entries. [UI #1049](https://github.com/ElevenID/marty-ui/pull/1049) makes PR/queue cache use restore-only and warms shared Python/Chromium entries on trusted main; Python runtime variants remain distinct, and the warmer only triggers on dependency/runtime/CI input changes. No build/test/security gate is skipped. Local workflow-policy and release-contract tests passed (124). Independent reviewer found and verified fixes for Python cache-key parity, runtime-path invalidation, and unrelated Rust-push runner overhead. Full PR and protected merge-queue CI passed, including Canvas and final gate; queue Canvas took 59m58s. The PR merged into main as `5a46fc966`. The new dependency-cache warmer passed, and three main-scoped entries appeared: two ~58 MB uv variants and ~108 MB Chromium. This confirms reuse is available, not an observed time saving; the API snapshot totaled 10.114 GiB, slightly above the nominal 10 GiB allowance, so eviction and normal-run impact still need observation. | [UI #1049](https://github.com/ElevenID/marty-ui/pull/1049), [queue run](https://github.com/ElevenID/marty-ui/actions/runs/37108875689), [dependency warmer](https://github.com/ElevenID/marty-ui/actions/runs/37112295005); [GitHub cache scopes](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching) |
| 2026-10-03 UTC | Main cache persistence | A later cache API snapshot showed all three new main-scoped uv/Chromium entries still present while aggregate cache occupancy had fallen to 9.856 GiB. This is evidence that shared restore candidates survived the first eviction cycle, but it is not yet a measured hit rate or PR duration saving. | GitHub Actions cache API snapshot at 09:43 UTC; [dependency warmer](https://github.com/ElevenID/marty-ui/actions/runs/37112295005) |
| 2026-10-03 UTC | Shared cache first reuse | In #1050's protected merge-queue run, completed Service Tests logs show a hit and successful restore for the main-warmed Python 3.12 cache, and the completed lifecycle browser gate logs show a hit and successful restore for pinned Chromium. Both jobs passed. This proves the new shared entries are usable by a subsequent queue run; comparable before/after duration evidence is still needed before claiming speed. | [#1050 queue run](https://github.com/ElevenID/marty-ui/actions/runs/37112551126), jobs `111173150386` and `111173150469` |
| 2026-10-03 UTC | A3 classifier merged | UI #1047 passed its protected combined-head checks, including Canvas, and merged into main. The selector still runs in shadow mode; no existing test or security gate was skipped. | [UI #1047](https://github.com/ElevenID/marty-ui/pull/1047), merge `e333dc243` |
| 2026-10-03 UTC | A1 first slice queued | The updated #1044 head passed all PR checks, including its 270-test Canvas lane, after the earlier unchanged lease-oracle flake had passed on rerun. Independent worker review cleared the integration. The PR entered the protected merge queue; main merge still pending. | [UI #1044](https://github.com/ElevenID/marty-ui/pull/1044), `45faa5219` |
| 2026-10-03 UTC | A1 tracker reconciliation | A docs-only tracker update changed #1044's head to `ca9dbb909`, removing it from the queue and restarting PR checks. Independent reviewer verified the delta contains no code/test/workflow/manifest/gate change and found no blocking documentation defect. Renewed full PR checks, including Canvas and final CI gate, passed; the reviewed head re-entered the protected queue at position 2 behind #1050. A second combined-head queue run started at 09:23 UTC while #1050's run remained active; it is in the published-worker preflight. Merge remains pending. | [UI #1044](https://github.com/ElevenID/marty-ui/pull/1044), `ca9dbb909`; [queue CI](https://github.com/ElevenID/marty-ui/actions/runs/37112907655) |
| 2026-10-03 UTC | A5 provenance closure merged | Added the imported loopback TLS helper to body and lease capture-source pins without altering behavioral observations. Exact reverse-migration tests prove both previous corpus hashes and original A/B hashes. Reviewer found and verified corrections to native replay pins, expected input count, and five historical docs. 479 focused tests passed locally; reviewer ran 504. Full PR and protected merge-queue CI passed, including published-process Canvas regeneration and final gate. #1050 merged into main as `c93b9205f`. | [UI #1050](https://github.com/ElevenID/marty-ui/pull/1050), [queue CI](https://github.com/ElevenID/marty-ui/actions/runs/37112551126) |
| 2026-10-03 UTC | A3 classifier false negative | Auth's Rust executable test embeds `services/entrypoint.sh`, but a path-only PR previously skipped Rust checks. Updated the classifier to select Rust along with existing Python/security lanes and added actual-Bash execution coverage. 93 workflow-policy tests pass; reviewer worker cleared. Full PR CI, including Canvas and final gate, passed; the reviewed head entered the protected queue at position 3. Combined-head validation and merge remain pending. | [UI #1051](https://github.com/ElevenID/marty-ui/pull/1051), `e24181829` |
| 2026-10-03 UTC | A3 service runtime-edge guard | Notification and Trust Profile reveal service consumers outside Cargo. A reviewed shadow-planner change broadens any affected service-package closure to all Rust packages until runtime mappings are complete; no checks are skipped. Rebasing onto current main preserved the narrow diff; eight focused tests and locked-metadata Notification/Trust Profile probes pass. Independent PR reviewer confirmed the planner remains observational and found no defect. Full PR CI passed, including Canvas and final gate; the reviewed head entered the protected queue at position 4. Combined-head validation and merge remain pending. | [UI #1052](https://github.com/ElevenID/marty-ui/pull/1052), `6e709ac71` |
| 2026-10-03 UTC | A5 static import-closure guard | Both frozen corpora's pinned scripts are checked for statically imported local helpers, with conservative review failures on relative/package/common dynamic imports. A subsequent reviewer commit covers aliased `import_module` calls. This remains a static/common-form guard, not complete dynamic/environment provenance. The branch is rebased on #1050's merge; 771 focused body/lease tests, Ruff, and diff checks pass. The independent exact-head reviewer found no regression, and protected auto-merge is enabled while full PR CI continues. | [UI #1055](https://github.com/ElevenID/marty-ui/pull/1055), `2cfe1264d` |
| 2026-10-03 UTC | A5 lease diagnostic split | On the same #1055 branch, split the post-join lease check into separate body-schedule and durable-observation messages without changing order or pass criteria. Updated only the lease-script provenance pin in the frozen corpus and its native replay/documentation hash; exact reverse-migration test preserves prior corpus bytes. Earlier reviewer cleared the split; live published-process regeneration on the final PR head remains pending. | [UI #1055](https://github.com/ElevenID/marty-ui/pull/1055), `2cfe1264d` |
| 2026-10-05 UTC | A4/A5 fast Canvas milestone | #1100 and #1102 merged after independent review and full protected queue checks. #1102 retains owned native PostgreSQL, HTTPS, worker, timeout, and lease checks; two long native matrices and 33 pinned historical replays moved to weekly/manual full qualification. On the observed protected runs, Canvas elapsed fell from 57m08s (#1100) to 31m34s (#1102), preflight from 8m08s to 2m01s, and the database group from 20m52s to 7m26s. These are different combined-head runs with cache/load variance, not a controlled benchmark or guaranteed saving. The full-run release requirement was not enforced at this milestone; #1106 subsequently merged the exact-main stable-tag gate. | [#1100 queue](https://github.com/ElevenID/marty-ui/actions/runs/37267226716), [#1102 queue](https://github.com/ElevenID/marty-ui/actions/runs/37276040281), merge `63431f3f7`; [#1106](https://github.com/ElevenID/marty-ui/pull/1106) |
| 2026-10-03 UTC | Contracts-lane test isolation | #1055's PR contracts lane failed an unchanged revocation-profile process test with `AddrInUse` while the real service started gRPC. The test chose HTTP and gRPC ephemeral ports through two successive bind-and-drop calls, which can return the same port; the failed log did not record the numbers, so this is a plausible cause, not proven. Reviewed [UI #1056](https://github.com/ElevenID/marty-ui/pull/1056) holds both reservations while choosing the pair and adds an unignored distinct-port test; its PR checks passed, but it was removed from the merge queue before queue validation. Draft [#1057](https://github.com/ElevenID/marty-ui/pull/1057) consolidates that fix with a bounded retry only on child bind collisions, plus an unignored retry-decision test; its exact-head CI is running. These are overlapping alternatives, not two independent obligations to merge. #1056 was closed as superseded after independent comparison; #1057 remains draft outside the merge queue until its exact-head CI passes and the passport release proof is recorded. Neither patch makes socket ownership race-free. | [#1055 failed contracts job](https://github.com/ElevenID/marty-ui/actions/runs/37116108681/job/111183168100); #1056 `076e4af36`; #1057 `fa71199ac` |

For each subsequent PR append: item ID, owner, PR link, reviewed SHA, findings/fixes, targeted checks, full-CI evidence when applicable, changed obligation mapping, merge SHA, observed timing, and next dependency unblocked.

### Protected merge outcomes (2026-10-03)

The independently reviewed audit/tracker update [UI #1054](https://github.com/ElevenID/marty-ui/pull/1054) merged as `4674895cb`. Earlier ledger rows retain their contemporaneous observations and should not be read as the current PR state.

The later tracker reconciliation [UI #1067](https://github.com/ElevenID/marty-ui/pull/1067) passed protected combined-head [run 37142613739](https://github.com/ElevenID/marty-ui/actions/runs/37142613739) and merged as `388cdb678`. This follow-up starts from that merged commit and records subsequent A0 input mapping and queue evidence without changing check selection.

The reviewed A0 tracker follow-up [UI #1069](https://github.com/ElevenID/marty-ui/pull/1069) passed protected [run 37147793271](https://github.com/ElevenID/marty-ui/actions/runs/37147793271) and merged as `5b8b3dc90`. Its input inventory does not select or skip checks.

UI #1055's exact reviewed import-closure and lease-diagnostic head passed its PR checks and protected combined-head queue CI, including the live Canvas qualification lane, then merged as `1a3578bc2790537abd8832a9bdccbd0f760c472b`. UI #1058's exact reviewed worker/composition split passed all required PR checks, including its live Canvas lane, and entered the protected merge queue. Neither result is permission to reduce qualification frequency: #1055 proves only the two guarded capture-source maps, and #1058 still runs both targets in the same lane.

Queue reconciliation (2026-10-03): the #1058 timeline records addition at 12:34:44 UTC and a manual removal at 12:37:54 UTC by the authenticated account. Its already-started [combined-head CI run 37123397984](https://github.com/ElevenID/marty-ui/actions/runs/37123397984) later passed, but the PR remains open because its queue entry is absent. No review comment or failed PR check explains the removal in the inspected PR state. Confirm intent before re-enqueueing; the local acceptance-owner follow-up remains unpublished to avoid launching overlapping full runs.

### Core OB2 lifecycle unblock

Core #348's first preflight failed because the existing temporary OB2 policy expired October 1, not because of the affected-test selector. The owner approved extending retirement. The bounded extension sets review to October 15, 2026 and retirement to November 1, 2026; OB2 remains temporary/non-default, with all existing restrictions and coverage obligations intact. Expiry enforcement is unchanged. All 105 script tests, release-contract validation, and verification-feature-boundary validation pass locally, including support on November 1 and rejection on November 2. Reviewer worker found no blockers and independently passed 75 release-contract tests. The extension merged in Core #348 after protected CI and merge-queue validation.

At `188b368`, all applicable PR checks passed, including affected Rust tests, preflight, security, CodeQL, and the final CI gate. The PR entered the required merge queue at position 1 on 2026-10-03 05:19:34 UTC. Merge-queue run [37099476951](https://github.com/ElevenID/marty-core/actions/runs/37099476951) passed and #348 merged as `466278aa01ae6e5c2b13b573265fa77c58758455`. Its Windows platform job ran 19m10s (05:22:11–05:41:21 UTC), longer than the 14m29s preflight; avoid assuming a preflight split is the next critical-path fix.

### Optional Rust compiler-cache incident

UI #1060's Rust Lint and Packaging job failed before compilation because the GitHub-backed `sccache` backend could not resolve its storage host; the unchanged mandatory lint command did not run. This is an infrastructure/cache dependency, not a source failure or evidence that lint should be optional. UI [#1061](https://github.com/ElevenID/marty-ui/pull/1061) adds a pinned-toolchain compiler probe and clears `RUSTC_WRAPPER` only if that probe fails, then retains formatting, metadata, full-workspace Clippy, and packaging checks. All 97 workflow-policy tests and Ruff pass locally; an independent reviewer found no blocker. A backend failure after a successful probe is a known limitation.
UI #1061's exact reviewed head `bd3338d14` passed full PR CI, including mandatory Rust lint/packaging, contracts, a 59m06s Canvas lane, and aggregate `CI Gate`. Its protected combined-head [run 37129988486](https://github.com/ElevenID/marty-ui/actions/runs/37129988486) also passed, including live Canvas, and it merged into main as `424d27dba` on 2026-10-03 15:18:49 UTC. This validates the workflow on a healthy cache backend; the synthetic failure branch is tested locally, but a live backend outage was not induced. No speed improvement is claimed from fallback behavior.

After #1060's Canvas and contracts lanes passed, its terminal first attempt failed only because lint never reached compilation. A failed-job rerun on the unchanged head passed full Clippy, packaging, and the aggregate CI gate; the exact head `63f6fa171` entered the protected merge queue on 2026-10-03 14:23:29 UTC. This proves the source change passed normal PR validation, not that #1061's outage fallback has been exercised during a live backend failure.

Rust service-lane reliability follow-up [UI #1063](https://github.com/ElevenID/marty-ui/pull/1063), reviewed head `ea7c98e3a`, extends the same pinned-toolchain cache probe before the mandatory workspace test compilation in both Canvas and contracts lanes. Lint and service lanes call one shared shell script; a failed probe clears only `RUSTC_WRAPPER` for subsequent steps. Independent review caught that optional `sccache --show-stats` could still fail a successful uncached job; both statistics steps now warn without failing mandatory validation, and partial sanitized evidence is removed. The full 98 workflow-policy, 146 Canvas runner/database-policy, and 2 stats-sanitizer tests pass locally, plus Ruff/Bash syntax/diff checks. Synthetic healthy/failure branches pass; a live backend outage and failures after a successful startup probe are not proven. Exact-head full PR [run 37133358874](https://github.com/ElevenID/marty-ui/actions/runs/37133358874) passed, including the 16m36s Canvas database suite and final gate. The reviewed head entered the protected merge queue at position 2 behind #1062, but account `burdettadam` removed it at 16:39:10 UTC. The detached combined-head [run 37136234398](https://github.com/ElevenID/marty-ui/actions/runs/37136234398) later completed successfully, including Canvas and final gate. The PR remains open and out of queue; do not requeue without clarifying the manual removal. This reliability guard has no measured time improvement and is not merged.

Protected runner routing incident (2026-10-03): the standalone passport producer [run 37139093870](https://github.com/ElevenID/marty-ui/actions/runs/37139093870) on merged main dispatched to `canvas-oss-wsl2-*` despite requiring the `passport-beta-wsl2` label. The in-job host preflight rejected that runner before loading plan or release artifacts, and the downstream attestation record skipped; this is not qualification evidence. The predecessor producer runs had failed for other reasons, so the passport release-proof hold remains in force. Independently reviewed [UI #1065](https://github.com/ElevenID/marty-ui/pull/1065), head `71a8303c9`, adds a fail-closed inventory of existing repository-runner labels, exact-purpose validation of new registrations, and rejected-registration cleanup without weakening the in-job guard. Fifty-eight focused local tests pass, including eight executed PowerShell policy cases. Exact-head full PR [run 37140351129](https://github.com/ElevenID/marty-ui/actions/runs/37140351129) passed, including all eight hosted PowerShell cases (not skipped), 5,405 repository tests, the live Canvas lane, and final gate; the Canvas job took 58m56s. At 19:04 UTC, protected combined-head [run 37144033946](https://github.com/ElevenID/marty-ui/actions/runs/37144033946) was running from queue position 1; this is a contemporaneous observation, not a final result. An already-routed job or independently mislabelled runner still requires operator cleanup; the code cannot retroactively correct it or qualify the failed producer run.

Subsequent protected outcomes (2026-10-03): runner-routing [UI #1065](https://github.com/ElevenID/marty-ui/pull/1065) passed [combined-head run 37144033946](https://github.com/ElevenID/marty-ui/actions/runs/37144033946) and merged as `9c91089d1`. Passport reference provisioning [UI #1066](https://github.com/ElevenID/marty-ui/pull/1066) passed [combined-head run 37146366367](https://github.com/ElevenID/marty-ui/actions/runs/37146366367) and merged as `b5966ae20`; its Canvas job took 59m16s, including 22m00s in the database-contract group. The earlier misrouted producer remains invalid; a fresh plan, correctly isolated producer, and attested record have not yet been proven. These are two distinct protected runs, not a before/after speed comparison.

A3 shipped-asset classifier follow-up [UI #1070](https://github.com/ElevenID/marty-ui/pull/1070), reviewed head `044cf110c`, corrects an A0-discovered false negative: `SELFHOST_BUNDLE.md` is in the self-host bundle manifest but the broad Markdown skip previously selected no Rust/packaging suite lanes for it. The change selects Rust/packaging lanes for that one asset and adds manifest-membership plus actual-Bash classifier regression coverage; 99 workflow-policy tests and Ruff pass locally, and an independent reviewer found no blocker. Full PR [run 37149825124](https://github.com/ElevenID/marty-ui/actions/runs/37149825124) passed, including Canvas (62m13s; database group 23m03s) and the final gate. GitHub records two manual auto-merge disables; the PR remains open and out of the queue pending direction. No speedup or merge is claimed. Merge-group full validation remains unchanged.

A0 tracker follow-up [UI #1072](https://github.com/ElevenID/marty-ui/pull/1072), reviewed head `a535dc7a59`, passed protected combined-head [run 37157087655](https://github.com/ElevenID/marty-ui/actions/runs/37157087655), including Canvas and final gate, then merged into main as `c840464e5` on 2026-10-03 22:48:54 UTC. Its Canvas job took 45m50s: reusable test compilation 4m06s, Bookworm acceptance build 6m36s, public image 9m17s, worker preflight 7m55s, and database contract suite 16m21s. A prior combined-head run on the same PR also passed but ceased to be authoritative when a preceding queue entry changed; this recorded result is the run matching the final queue head. The change is documentation-only, so this faster run is variance evidence, not an attributed speed improvement.

### A1 Canvas acceptance-owner follow-up (2026-10-04)

[UI #1083](https://github.com/ElevenID/marty-ui/pull/1083) moved the worker published-process target to `marty-service-acceptance` while retaining both full targets, exact preflight proof, and mandatory names. A 2+2 test-thread pilot made the hosted database group slower (1,602 seconds versus 871 seconds in the 4+4 comparison), so it was reverted before merge. Reviewed head `82f067e08` kept the 4+4 budget. Its first PR run failed one unchanged historical JSON-consumer probe at its 120-second timeout; the unchanged rerun passed all required checks, including Canvas and the final CI gate. Protected [combined-head run 37205221707](https://github.com/ElevenID/marty-ui/actions/runs/37205221707) passed and merged as `fcb2cd74a` on 2026-10-04. The protected Canvas job took 44m47s; cache/load variance and the failed first attempt prevent attributing that whole-job difference to the ownership move.

[UI #1086](https://github.com/ElevenID/marty-ui/pull/1086) moved the remaining 141-test Canvas composition target into the same acceptance package, with one new package-root regression test. The runner resolves the real issuance binary and both test executables from Cargo artifacts; Bookworm compatibility compiles the new target owner. Issuance no longer directly or transitively depends on Flow, Gateway, selfhost-bundle, or release-evidence for its normal/dev test closure, as confirmed by locked `cargo tree`; `cargo check --tests` for issuance passed. The first hosted attempt found three packaged-runtime child failures caused by a sparse-container root assumption and missing issuance-binary handoff. Those were fixed without dropping tests, and [exact-head PR run 37199826605](https://github.com/ElevenID/marty-ui/actions/runs/37199826605) passed all required checks: Canvas composition 144 passed, worker 127 passed with two ignored, and the formerly failing children passed. After #1083 merged, the composition commits rebased onto main and passed acceptance-target Cargo check, 411 focused Python tests with one skip, formatting, and independent exact-head review. The final protected [run 37331342522](https://github.com/ElevenID/marty-ui/actions/runs/37331342522) passed, and #1086 merged as `cf8785147` on 2026-10-05. No whole-job speedup is attributed to the ownership move.

[UI #1108](https://github.com/ElevenID/marty-ui/pull/1108) moved eleven self-host and base-runtime support modules used only by `canvas_published_schema_contract` into `marty-service-acceptance/tests/support`. Shared Canvas database/command helpers still used by issuance examples remain in their existing location. [#1111](https://github.com/ElevenID/marty-ui/pull/1111) then moved eighteen Flow, DIDComm, renewal, and Kubernetes-resolver support modules into the acceptance package as byte-identical renames. Module and Python ownership-guard paths changed; assertions, test names, target registration, process fixtures, CI triggers, and required gates did not. Both PRs passed protected CI and merged. No runtime saving is attributed to source ownership alone.

Merged A1 service boundaries (2026-10-06 checkpoint): [#1118](https://github.com/ElevenID/marty-ui/pull/1118) moved the signed Gateway-to-Issuance webhook test to cross-service acceptance with its real PostgreSQL, signature, tenant-isolation, durable-state, and named CI checks. [#1121](https://github.com/ElevenID/marty-ui/pull/1121) moved six opt-in Gateway-to-Signing cases into `gateway_signing_acceptance`, retaining their exact named CI invocations and disposable Redis/OpenBao guards. Both service-to-service development edges are removed, and all six signing cases passed the protected contracts lane before #1121 merged. These ownership moves preserve production code and required acceptance runs.

A3 Trust Profile runtime edge ([#1117](https://github.com/ElevenID/marty-ui/pull/1117), merged 2026-10-06): Presentation Policy reads `TRUST_PROFILE_SERVICE_URL`, passes it into its native control plane, and fetches `/internal/v1/trust-profiles/{profile_id}` during trust resolution, rejecting a mismatched profile or organization identity. The UI shadow planner records this non-Cargo consumer with source-backed regression assertions. This is diagnostic coverage only: every service-package change still selects the entire Rust workspace because other runtime/deployment edges remain unmapped. No CI speedup or narrower gate is claimed.

### 2026-10-06 follow-up checkpoint

[UI #1119](https://github.com/ElevenID/marty-ui/pull/1119) passed protected retry [run 37408292483](https://github.com/ElevenID/marty-ui/actions/runs/37408292483) and merged as `7ed056861`. Its first protected run failed one unchanged Canvas process-readiness case; the retry passed. [#1121](https://github.com/ElevenID/marty-ui/pull/1121) passed full PR [run 37407242994](https://github.com/ElevenID/marty-ui/actions/runs/37407242994) and is queued, with protected validation still pending at this checkpoint. The dependency audit finds that its six-case Gateway-to-Signing move would remove the last service-to-service development dependency in UI service manifests. The remaining Signing Keys-to-Core Verification development dependency supplies independent CSCA interoperability fixtures and is retained.

This proposed maintenance batch records static test ownership for 23 public-protocol vectors, including rejection of ignored owners and comment-only references. It does not prove per-vector dynamic execution; the Rust workspace lane remains authoritative. It also records the source-backed Credential Template-to-Flow gRPC consumer in the shadow planner while preserving full-workspace selection for service changes. The Canvas review-main readiness helper retries within the caller's existing ten-second deadline, preserving the exact healthy JSON and live-child assertions and reporting the child exit status on failure. A focused Rust regression is added; hosted CI must compile and execute it. The assembled Python checks passed 139 tests and 17 subtests, with Ruff and direct Rust formatting checks passing. No whole-pipeline speed improvement is attributed to these pending changes.
A1 dependency-surface inventory (2026-10-06): locked offline `cargo tree -p marty-gateway --edges normal,build,dev --prefix none --format '{p}'` on main `7ed056861` and merged #1121 branch head `98912cdc2` yields 699 versus 668 unique package entries after removing display deduplication markers and normalizing local worktree paths. Thirty-one entries disappear with no additions, including Signing Keys and its AWS KMS/SSO/STS and Smithy dependencies. This supports the package-scoped compile-boundary benefit of the ownership move; it is not a build-time measurement, and the full workspace CI still compiles the acceptance owner.

### A6 Canvas compilation scope candidate (2026-10-06)

The follow-up to the separate Canvas acceptance package narrows only the Canvas
lane's host compilation: two Canvas acceptance targets, the issuance library and
two HTTPS test targets, and real issuance, Canvas worker, Gateway, and Flow
binaries. The contracts lane retains full workspace compilation, but excludes
`marty-canvas-acceptance` from its workspace test execution: the mandatory Canvas
matrix leg is the sole execution owner for both of that package's test targets.
The package has no additional library, example, binary, or benchmark tests. This
avoids duplicated support assertions and environment-guarded no-op passes; the
33 historical cases already did not execute their process assertions in contracts
and retain their unchanged full-qualification owner. Both matrix legs share the
same selection and are required by the aggregate CI gate.
Bookworm compatibility, public Docker builds, published-process preflights, and
all Canvas test execution remain unchanged. A fail-closed artifact guard checks
package, target, kind, explicit boolean test profile, unique executable, expected
path, and executable presence before expensive acceptance setup. Independent
review corrected missing/nonboolean profile acceptance and permits Cargo to
report a worker test harness alongside its separately verified real binary.

This is a reviewed local candidate, not a merged or measured speed improvement.
Targeted policy tests and a synthetic Cargo artifact-selection experiment support
the selectors; hosted Canvas validation is still required to prove package-scoped
feature unification and all runtime consumers. The complete contracts lane remains
the non-Canvas workspace execution authority; the two mandatory matrix legs
together retain the complete declared qualification coverage.

Combined-head validation detected that the new compiled-test inventory guard
also consumes the producer manifest. Producer metadata and the new tier inventory
therefore select both Rust and release validation, with exact consumer regression
checks; they cannot retain a release-only shortcut. The tier inventory is CI-only
and excluded from all three service-image contexts, preventing an unnecessary
container payload/cache input. The guard records discovery and exact selection,
not proof that every selected case executed or complete historical provenance.

## Latest validation checkpoint

### 2026-10-06 parent merged and follow-up prepared for hosted validation

UI #1124 merged at 10:28:13 UTC as `e9f140e00ab5a3b2c6e54a901e7360f817e2475e` after normal, manual full, and protected queue workflows passed. Its layered Retry-After/validation tests, PostgreSQL terminal persistence assertions, image-only configuration oracle, narrowed host Cargo invocations, test-only Docker exclusions and source-backed Gateway shadow edges are now on main. No whole-pipeline speedup is attributed from these runs.

The independently reviewed follow-up rebased onto that exact merged main as `9ce7979735013486cb27ca94ccc2282325637ec3`; comparison with pre-rebase `023c958b4` proved a byte-identical complete tracked file tree. The following milestone entry changes tracking documentation only. This batch is ready for one hosted PR/full qualification cycle; routine ten-case and full twenty-case native validation still require real Linux execution before merge. Fresh complete-main qualification is reserved for the next meaningful merged milestone rather than dispatching redundant parent runs while this batch is validated. Stable release prerequisites remain unchanged and cannot use the earlier failed main run.

### 2026-10-06 assembled follow-up review and Python milestone

Final assembled source `002b4ad3d8aa3df230a65f7f21fd783830109dd3` passed the complete local root Python suite under explicit full qualification with the SHA-verified CI dependency: 5,794 passed, 29 existing platform/opt-in skips, and 32 subtests in 580.06s. Independent assembled review cleared the cross-interactions. This validates the corrected local batch, not hosted Linux native selection, production image builds, protected merge or release eligibility; hosted routine/full pilots remain required after rebasing onto merged parent main. This following update changes tracking documentation only.

UI #1124 final source `5448ad90d` passed both normal `37437829353` and full `37437847991` workflows. Protected queue run `37444430694`, synthetic head `e9f140e00ab5a3b2c6e54a901e7360f817e2475e`, remains live; no merge or release qualification is claimed yet.

The unpublished follow-up now combines reviewed worker-binary provenance, the guarded ten-routine/twenty-full native-validation pilot, and exact-once passing harness-row checks for its PostgreSQL and unit replacement owners. Ignored, failed, missing, duplicate or substituted owner results fail closed. All twenty native cases remain in full qualification; historical qualification is unchanged. The processor's fifteen unit tests moved into a same-directory cfg(test) source leaf, preserving namespace, all fifty helper/test function names, 536 quoted literals and seven fixture paths. Production text outside the module replacement is unchanged. All fifteen moved tests and 43 relevant producer/closure/context policy checks passed; the leaf is excluded from all three release Docker contexts.

A separately reviewed PR-only classifier can narrow feedback only for a nonempty set of the nine exact proven test leaves. Contracts execution, Rust lint/supply-chain, CodeQL and public/release checks remain; mixed/unknown inputs, proof failure and protected merge groups retain the full plan. CI Gate validates the runtime/matrix tuple, not merely aggregate matrix success. This has no measured hosted speed benefit yet and must not be described as selective service validation.

The assembled full-mode local Python milestone with the digest-verified CI `marty_common` wheel finished with 5,779 passes, 29 existing platform/opt-in skips, 32 subtests, and four failures in 593.12s. Three failures were old policy assumptions about the former static matrix/runtime selector; reviewed corrections retain explicit affected-input, mandatory-contracts-owner and protected-full-plan checks, including negative plan mutations. The fourth exposed an existing Windows child-output cleanup race: the intended output-limit rejection was masked by an open-file cleanup error. Its reviewed correction reaps the child and closes owned handles before bounded directory cleanup; transient PermissionError retries remain bounded, exhaustion fails, and any original child failure is retained with cleanup failure chained. All four observed failures are resolved in the assembled targeted rerun: 138 tests passed under full mode. This is not a replacement claim that the earlier whole-suite run passed; hosted exact-head routine/full qualification remains required. The failed run's leftover local fixture remains untouched and is not committed. Keep the batch unpublished until the parent is merged and then rebase it onto current main.

### 2026-10-06 next local maintenance batch (unpublished)

The reviewed #1124 final source is `5448ad90d744bce86df62bbc7a775e82954be3bb`; normal run `37437829353` and full run `37437847991` target that same source. Earlier failed candidate runs are obsolete, not qualification evidence. Keep this next batch unpublished until the parent is merged and rebase onto then-current main before opening its maintenance PR.

Two independently reviewed follow-ups are assembled locally. The worker binary's roster environment lookup now has one private injectable seam at the unchanged initialization point; production still uses `env::var(...).ok()`, the existing lossless parser, and deferred errors. Two new unit tests pin exact environment keys/order, independent default/explicit bounds, invalid-input diagnostics, and no payload disclosure. All nine binary unit tests passed. This closes a fast wiring-coverage gap, but does not authorize dropping native roster cases. A concrete Event Stream-to-Gateway gRPC dependency is now recorded in the shadow planner, backed by configuration, the active SSE handler, client subscription, server registration and the optional-listener condition. All service changes remain full-workspace validation; this is not a complete runtime graph. The assembled Python contracts/planner checks passed 36 tests and 32 subtests.

Main full run `37429957800`'s Canvas job succeeded in 63m06s: host compile 11m18s, Bookworm compile 9m30s, public image 11m16s, preflights 8m08s, and database suites 21m15s. Startup artifact `11399272409` matches its exact main source/run/attempt/job, normalized inputs, executable and pinned image identities; live comparison, native replay and owned cleanup passed. Its required enclosing workflow success is absent, so it remains ineligible for external qualification/reuse. These full-tier timings are not a comparison with routine-tier timings or an attributed speedup.

The thirteen-case repository test now retains independently isolated databases while reusing one verified disposable PostgreSQL server and a pristine migrated template. Independent source/lifecycle review, scoped compilation and strict target Clippy passed. The author's exact opt-in test passed in 7.18s; the same test on the assembled batch passed in 6.05s (1 test, 139 filtered), versus the prior per-case-server local run's 52.83s. This measures only local test runtime, excluding compilation; no hosted whole-pipeline saving is attributed. All frozen job/target/OAuth/facts, issued-row/ciphertext and lease/failure-port assertions remain. Case pools close before non-FORCE database drops, the admin pool closes before exact owner cleanup, and both newly observed assembled-run container IDs were confirmed absent. Failure cleanup remains bounded by the owned tmpfs server. The assembled dependency/closure/validation/planner sweep passed 52 tests and 32 subtests; the roster binary separately passed all nine tests and strict Clippy. Native case selection is unchanged.

A8 transport investigation found that Flow forwards the outer VP without the stored presentation query/submission, and Presentation Policy attempts credential verification of that outer VP. The intended correction must authenticate the VP, select the exact embedded credential against server-bound query evidence, and reuse existing issuer-trust/status/policy checks. Core #352 supplies an additive authenticated-proof API on merged Core 0.2, but UI's 0.1.62 pin is not compatible with a rev-only refresh: consumed crypto features and authority-issuance APIs changed. Core's proof generation and HAIP key-generation/decryption helpers used by UI production are now test-only; migration requires managed signer/session ownership rather than simply removing feature names. The pinned Core's old VP verifier returns proof checks but no authenticated claims or signer, while its separate JOSE API lacks VP transaction policy and complete algorithm parity; combining them in UI would duplicate security composition. A coordinated compatibility/ownership change is required, not duplicated cryptography or unchecked extraction. Existing bearer defaults remain unchanged; holder-key policy remains a separate user decision. Nightly cannot be qualified solely by existing health/discovery cases.

Residual A1 audit: the service-to-service test dependency boundary is achieved: three Passport/Gateway acceptance targets and two Canvas acceptance targets have dedicated package owners, and UI service manifests have no service-to-service development dependencies left. Canvas composition still combines deployment, DIDComm/renewal and Canvas responsibilities in one executable; independent target compilation is deferred pending a demonstrated useful fixture/artifact boundary, not silently counted as completed. Its existing complete compile/execution obligations remain intact.

Next A4 investigation is the renewal authcrypt/anoncrypt versus private-IP allowed/refused matrix repeated across Gateway, Envoy and Kubernetes composition. A credible fast proof must use the real endpoint validator and native encryption/delivery ports, not a stub that returns pending. The existing library test owner can reach crate-private claims without changing production visibility and reuse native fixtures; integration tests and all real process/database/profile cases remain unchanged while this future slice is prepared separately.

### 2026-10-06 08:40 UTC assembled-batch follow-up

UI #1124 remains unmerged. Its normal run `37434750297` and full run `37434812239` both failed the older packaged-documentation assertion, which rejected any Docker-ignore rule containing `src` rather than checking the compiler-consumed document. The reviewed correction reuses the bounded context matcher, requires `canvas_sync_processor_contract.md` in every owned context, and retains negative controls for exact-file and broad-source exclusions. The root ignore file explicitly re-includes that one compile-time Markdown input. All 64 focused checks and 32 subtests passed under full mode; independent review cleared the correction. This does not permit excluding production sources or weakening test discovery.

The same necessary correction batch includes two independently reviewed slices: seven real worker-cycle processor-error handoff cases reuse the existing spy and require terminal-port identity, accounting and heartbeat observations; twelve source-backed Gateway upstream edges extend the shadow planner. These do not establish durable processor writes or a complete runtime dependency graph. Service changes still select full workspace validation, and all twenty native validation cases remain retained.

Merged-main full run `37429957800` finished with Canvas successful but overall failure from the previously identified qualification-mode fixture assertion. It cannot authorize release or evidence reuse. Broad local Python validation with the CI package path and full mode finished with 5,725 passes, 29 existing environment/platform skips, 32 subtests, and nine failures, all from absence of the published `marty_common` wheel installed by CI. After downloading that exact wheel and verifying its CI-pinned SHA-256, all 155 deployment/documentation/context tests passed. The shadow planner separately passed 17 tests and 32 subtests. These scoped reruns resolve the nine observed environment failures; they are not a complete CI-environment qualification. Current-head hosted normal and full validation remain required after the correction push.

### 2026-10-06 merged-main and assembled-batch milestone

Full-run follow-up: merged-main run `37429957800` and initial candidate full run `37430688278` both failed one existing release-policy test while their other lanes remained live. `test_preflight_evidence_requires_both_successes_and_same_executable` implicitly recorded the ambient qualification mode, then assumed setting mode 1 must invalidate it. During full qualification the recorded mode was already 1, so the assertion was wrong; the evidence implementation correctly retained matching evidence. The reviewed fix explicitly tests recorded modes 0 and 1 and switches to the opposite mode before restoring the original; all sixteen file tests pass under either ambient mode. No runtime guard is relaxed, and neither failed workflow is qualified release evidence.

The necessary correction push also includes two independently reviewed maintenance slices: the existing thirteen-case PostgreSQL validation owner now performs real lease/validation/terminal-failure persistence against frozen job/target/OAuth/facts observations while preserving issued rows and ciphertext (one opt-in test passed in 52.83s; strict Clippy passed; exact owned resources absent), and eight individually verified `#[cfg(test)]` Rust leaf modules are excluded from all three release Docker contexts. They remain in the checkout test lane; no production source, manifest, lock, protocol, asset or test tier is removed. The bounded ownership/context guard covers all six current Rust-copying Dockerfiles, rejects hashed byte-raw fake owners and unsupported raw delimiters, and retains representative production inputs. Hosted builds must still validate actual Docker contexts; no cache hit or timing saving is claimed. All 177 combined policy tests passed under ambient full mode before the final scanner hardening, and all twenty focused database/context tests passed after it.

UI #1123 merged at 07:28:41 UTC as `d649fd4e15cbeb1df5e7fe6d45ad21849a3bd86c` after protected [run 37424618886](https://github.com/ElevenID/marty-ui/actions/runs/37424618886) succeeded. Its Canvas job took 52m13s: host test compilation 11m50s, public image 13m21s, and database suites 13m46s. These are observations with cache/load variance, not attributed savings. The tier inventory, source-backed Flow consumer edges, narrow compilation and one Canvas execution owner are now on main; complete full-main startup qualification remains pending in [run 37429957800](https://github.com/ElevenID/marty-ui/actions/runs/37429957800). A redundant pending dispatch `37429996182` was cancelled only after verifying the existing live run's same main SHA, workflow path and full-qualification event.

On assembled source head `51b3d8af3`, all ten focused issuance Rust tests and three configuration-oracle tests passed, including the real pinned-image oracle (12.17s); scoped strict Clippy for the composition target passed. Independent final review cleared that exact source. Rebasing the batch onto merged main produced `0109845e3` with a byte-identical complete file tree (`git diff --exit-code` against the reviewed head passed). The following tracking update changes documentation only. Current-head hosted routine and full qualification remain required before promoting the nested Retry-After tier; neither the local results nor the earlier main run qualify this new batch.

### 2026-10-06 06:40 UTC validation checkpoint

UI #1122 merged as `b0e3696cb363eae627948fb09d98a759073f6e1e` after protected validation. Core #352 merged as `d949f65362b63157e4e4ecee23ea4610a6411089`; its additive authenticated VP-proof API is a prerequisite, not a completed UI holder-binding or credential-trust fix. UI #1123's exact head `8e89bd58ae6b4374f5a8fa4f394298a629a00ba1` passed PR [run 37419803227](https://github.com/ElevenID/marty-ui/actions/runs/37419803227), including contracts (18m24s), Canvas (52m56s), and the aggregate gate. Its protected merge-group run `37424618886` is still live at this checkpoint. The fresh full-main startup artifact and complete full-main workflow remain required after merge. These timings are observations, not an isolated before/after speed comparison.

The next unpublished A0/A4 batch passed seven focused Rust Retry-After tests, the separately invoked worker failure-port test (covering hints 0/60/86400), and the named real PostgreSQL contract (97.08 seconds). The disposable PostgreSQL container was verified by exact identity and purpose label, stopped, and confirmed absent; no deployed database was used. The routine two-case/full seven-case process-tier candidate also rejects routine selection during explicit full qualification before spawning a child. Independent combined review passed 220 focused policy tests with one platform-specific skip. A broader run passed 335 tests but found three stale exact-command assertions; after binding those assertions and the negative mutation to the tier-prefixed command, all 119 workflow-policy tests passed, and independent review confirmed that the mutation cannot pass vacuously. No current Linux acceptance executable was available locally, so a real native tier pilot has not been demonstrated; focused harness tests do not substitute for it. Current-head hosted routine/full qualification remains required before promotion. All seven historical/native full-qualification cases remain available; no whole-pipeline saving is claimed.

Two additional reviewed local candidates join that unpublished batch. The seven processor-dispatch validation cases now have a fast owner using the existing processor simulator, independently enumerated error codes, frozen summaries, exact target shapes, and tracked-state/provider-read assertions. Review corrected duplicate registration handling and explicitly excluded no-op patch ports, durable writes, and the template-removal race from this unit proof. The scoped Rust test and strict Clippy passed; the complete twenty-case native/historical validation matrices remain unchanged. Canvas host test compilation also combines the acceptance and issuance selectors into one Cargo invocation, while keeping all three real-binary build invocations separate to preserve their prior feature resolution. A tiny dependency-free Cargo 1.95 experiment demonstrated cross-package test target/profile selection; 151 policy tests passed before the binary-build fidelity correction and all 32 compile-scope tests passed after it. Independent review cleared the corrected four-command candidate for hosted validation, not as proof of actual-repository feature parity or time savings. The artifact guard, complete contracts lane, Bookworm check, and mandatory runtime owners remain intact.

The same batch now also reuses one test-only worker spy for retry and terminal handoff, avoiding a second implementation of the OAuth trait boilerplate. Thirteen independently enumerated repository-error names/codes/summaries are injected at the validation port; the real worker cycle must pass the terminal marker, absent retry hint, exact job/worker/generation identity, dead-letter accounting, and scheduling/processing/idle heartbeats. This proves port handoff, not real SQL validation or target disablement. Review restored the original three-hint retry test's independent literal job-ID assertion after fixture generalization. Both qualified worker tests passed (566 filtered), and independent review cleared the corrected `1b3e87d5c` source. All twenty native/historical validation cases and their race, issued-row, and ciphertext guarantees remain in their existing tiers. A fresh combined policy run passed 172 tests after the four-command correction; hosted qualification remains pending.

The provider-configuration historical oracle now has an image-only candidate owner rather than starting PostgreSQL and migrations it never uses. Its direct inputs are the digest-pinned `observed_image` in `canvas-worker-consumer-range-oracle.json`, `scripts/run_canvas_provider_configuration_oracle.py`, `contracts/canvas-provider-configuration-scenarios.json`, and the existing compiled frozen expected report. The unchanged Python oracle verifies the published adapter source SHA, twenty secret-configuration cases, nineteen timeout cases, and nineteen fresh full-module imports. Local exact pinned-image qualification passed in 11.72 seconds after hardening; this is not a before/after CI timing comparison. A specialized test-only owner reuses bounded Docker/inspect helpers, enforces no network, read-only filesystem and exact bind sources, and verifies UUID label/container identity before access or cleanup. Independent review cleared digest/tag/option rejection and foreign-source negative tests at `78eb769f2`; all owned containers were confirmed absent. Real migration/constraint owners remain unchanged. The combined source-policy sweep found an unrelated-owner cleanup-name collision in the bounded database-builder inventory; its reviewed correction scopes uniqueness to `PublishedDatabase`, retains ambiguous/missing-boundary failures, and does not claim to inventory image mounts or complete historical input closure. After the correction, the combined producer/closure/harness/validation/startup/compile/tier/workflow policy sweep passed all 218 tests in 15.79 seconds.

## Goal completion criteria

- Accepted changes are reviewed, validated, and merged; each queue item has a documented final disposition.
- Tests have explicit owners and inputs; cross-service acceptance no longer requires unjustified service development dependencies for the moved scenarios.
- At least one justified narrow Rust boundary is independently testable, with shared implementations and no untracked duplicate logic.
- Selective validation is supported by dependency and regression evidence; unproven exclusions remain broad.
- No unique behavioral/security obligation, feature, test case, or protected release requirement is lost.
- Historical reference and native validation responsibilities are explicit, with any evidence reuse checked for validity.
- Normal GitHub runs demonstrate the resulting feedback behavior. Record actual savings or absence of savings without extrapolating from code size.
- Release-tier tests prove nightly single-Linux happy-path qualification and no YouTube activity, while official production releases run the complete happy/error E2E inventory with release-bound evidence and official-only YouTube publication; unknown tier and missing evidence fail closed.
- The test inventory demonstrates a genuine pyramid across unit, integration/contract, and E2E layers, with explicit tier/trigger ownership and no lost unique assertion; nightly executes only its declared happy-path cases at each layer, major-version qualification executes the complete mapped matrices, and every official stable release retains complete E2E qualification.

2026-10-06 local A0/A4 inventory candidate (not merged): `contracts/python-value-fast-obligations.json` maps the four pure `marty-response-compat` `python_value::tests::*` cases to distinct assertions and inline/frozen Unicode inputs, and links the retained 12 signing-detail and seven loopback-HTTP signing cases to their source, target, and fixture owners. The source/target guard checks source declarations and input wiring, not compiled discovery or current execution. Historical #1060 contracts [job 111220161059](https://github.com/ElevenID/marty-ui/actions/runs/37125503856/job/111220161059) logged all four, all 12, and all seven as `ok` under `cargo test --locked --workspace`; this is execution evidence for that run only, not a no-Postgres feature qualification. `marty-response-compat` permits standalone validation without Postgres; issuance activates its Postgres feature in workspace validation. No skip or production behavior changes in this inventory slice.

Review correction for that local candidate: the 12 signing-detail names are distinct within the integration target, but `signing_error_detail::scalar_api_remains_a_projection_of_the_shared_owner` is source-included there and also runs in the issuance library target. The historical contracts log has 13 signing-related `ok` lines across those two targets, not 13 unique obligations or independent oracles. The static guard rejects ignored/conditional test attributes and commented-out ownership wiring; it does not discover current Cargo runtime execution. The combined batch makes manifest-only changes select release checks in addition to the existing conservative Rust lane, and excludes this CI-only manifest from service images. Helper/test changes remain broad. No new execution exclusion or release-only shortcut is authorized.

## Current routine feedback observation (2026-10-06)

#1126's [normal PR run 37454314639](https://github.com/ElevenID/marty-ui/actions/runs/37454314639)
passed all 23 jobs at source `ce70c40bd07f0629db2549d5a39af94d2fc1b7ea`.
Its Canvas log executed the ten declared routine validation cases, including all
three retained lock races and the privacy case, and named the real PostgreSQL
validation owner as passing. Full run `37454308609` also passed all 23 jobs,
including the twenty declared full-tier native validation cases. Protected queue
run `37462723875` remains live at this checkpoint; no merge or release authority
is claimed from PR qualification alone.

| Observed normal PR run | #1124 `37437829353` | #1126 `37454314639` |
| --- | --- | --- |
| Workflow created-to-final-update | 53m33s | 31m43s |
| Canvas job | 51m32s | 30m25s |
| Host acceptance compilation | 10m42s | 6m28s |
| Bookworm acceptance compilation | 10m14s | 5m46s |
| Public selfhost image build | 12m56s | 8m00s |
| Isolated database contract group | 13m52s | 6m50s |

This is observed routine feedback roughly 22 minutes shorter in these two
successful runs (about 41% for workflow wall time), not a controlled benchmark.
Cache state, runner load, source and validation work differ; do not attribute
the entire difference to one refactoring or extrapolate steady-state/official
release savings. The full tier and protected queue must still qualify independently.

## Assembled next test-layer batch (unpublished, 2026-10-06)

Exact combined source `4b2bd952511bc8818954db43fecdcc6d95f36f65`, based on
#1126's corrected `e18d9c9d0`, passed independent assembled review and all
16 `canvas_sync_processor::tests` plus 41 `initiation_didcomm::tests` library
tests. Their harness execution took 0.01s and 0.06s respectively, excluding
compilation (the first invocation compiled for 1m14s). These are current local
results, not a comparative benchmark or a hosted turnaround saving. Direct
formatting and diff checks passed. The renewal/context classifier component
passed 125 Python checks before assembly; the roster component passed 37 related
policy checks. Parent #1126 still requires exact-head hosted qualification and
protected merge; this follow-up remains unpublished until that parent merges.

The additional roster owner is
`canvas_sync_processor::tests::roster_failure_processor_dispatch_preserves_tracked_state`.
It injects five existing provider error variants into the real processor's
BackgroundRoster path, checks independent literal error/retry expectations
against the frozen scenario/oracle names, and observes one run-scoped roster
call with no tracked simulator-state mutations. It does not exercise the real
OAuth/HTTPS provider, worker handoff, durable job retry/dead-letter transitions,
target disablement, issued rows/ciphertext or process/idle/SIGINT behavior.
All five native roster-failure cases and historical qualification remain intact.
Separate real database/provider evidence is needed before any native tier cut.

## Roster component experiment disposition (2026-10-06)

The real five-case worker/provider/OAuth/PostgreSQL component draft is deferred,
uncommitted and unpublished in `worktrees/a4-roster-failure-component-20261006`.
Two owned HTTP-loopback experiments failed before worker execution: the pinned
published schema requires `canvas_oauth_connections.canvas_base_url` to start
with `https://`. Owned fixture containers were verified absent after those
failures. Neither schema nor production trust policy was changed to admit HTTP.

A single-child TLS draft reuses the existing acceptance executable and HTTPS
fixture. Cached Windows compilation, scoped Clippy and ten Python driver controls
passed, but these do not qualify real Linux Rust TLS/SQL execution. Its proposed
240s internal deadline and 1080s outer limit are not an absolute cleanup guarantee:
the outer timeout cannot prove Docker CLI descendants and pending daemon creates
are terminal. Existing exact UUID recovery verifies topology, but safe reuse also
needs the closed-endpoint and pending-operation protocol already implemented in
`selfhost_packaged_runtime.rs`. Merely widening timeouts is not a substitute.

Retain all five native roster cases and current tiers. Do not include the draft
in the reviewed unit/renewal batch or use it as demotion evidence. Revisit this
slice only with a reviewed lifecycle design and real hosted Linux qualification;
no component speedup is attributed to the failed or mocked experiments.

## A8 current API-boundary audit (2026-10-06, read-only)

Core main `d949f65362b63157e4e4ecee23ea4610a6411089` is workspace 0.2;
UI's six shared Core declarations still use 0.1.62 / `bdbd1510`; issuance also
declares `marty-emrtd-issuance` 0.2 at separate revision `83cdaeb5`. This is
already a mixed-generation graph, not six declarations covering every Core
dependency. A pin-only update would remove callable APIs and an existing opt-in
capability:

- Gateway `runtime.rs` calls `proof::create_proof_jwt`, now Core test-only.
  Adopt a legitimate production wallet/delegated signer API without changing
  authenticated caller authorization or using a test helper as a production API.
- Flow `request_object.rs` and `verification_submission.rs` generate, seal,
  persist and later unwrap private HAIP response JWKs. Core's production
  `HaipResponseDecryptionSession` is opaque and one-shot; it is not a durable
  serialization replacement. Preserve restart/session custody through a supported
  boundary, not copied cryptography or an export of Core's test helpers.
- `marty-crypto/ecdsa` becomes `ecdsa-verification`; verifier
  `authority-issuance` is removed. Preserve `passport-self-signed-test` and
  independent CSCA interoperability fixtures with a suitable test-support owner.
  This opt-in test-image capability is not the ordinary production signer.

After those prerequisites, align Core versions/features and carry verifier-owned
definitions plus wallet submissions through Flow to policy evaluation. Core's
authenticated VP proof verifies the signed payload/key and session claims, not
the embedded VC's issuer, trust or status. Verify those independently. Holder-key
comparison remains conditional on the existing profile policy; do not silently
convert `OpenBadgeLogin`'s bearer default to mandatory holder binding. Keep existing
raw-credential routes distinct from signed-VP handling and reject unverified
context flags as proof. Only then qualify the same-key wallet happy journey and
nightly release tier on real Flow/policy/issuance results. This audit changed no
pins, authentication behavior or release authority.
An integration-repository review of the five candidate nightly smoke cases
found issuance coverage but no successful verifier verdict. Its recorded
signed-presentation replay reached policy evaluation and was denied; the
observed outer-presentation forwarding needs investigation before any
qualification claim. The next narrow implementation is one serial, no-skip
disposable-stack happy journey with a real authorized principal, exact policy
and trust fixture, same-key signed presentation, and an actual `allow` verdict
against pinned artifacts. Only after that passes should a separate Linux
nightly transaction bind the case result to an immutable prerelease tag and
image digests. Existing stable release E2E and recording gates remain required.

## A6 container-input audit disposition (2026-10-06)

The dedicated event-stream and revocation-profile Dockerfiles still cook the
workspace, but neither is selected by current CI/CD or Compose. Current CI uses
shared `rust/services/Dockerfile.ci` targets; release uses `services/Dockerfile`.
Pinned cargo-chef 0.1.78 supports binary-scoped preparation and package/bin cooking,
but changing these unused recipes would not improve the current critical path.
Keep shared workspace cooking for the actual multi-service consumers. Revisit
dedicated recipe narrowing only if those builds become active, with locked image
validation rather than dependency counts as timing evidence.

A tracked-file inventory finds 335 files under service/crate `tests` trees,
totalling 5,352,231 bytes (5.10 MiB) before Dockerignore rules. The two dedicated
shared service/CI ignore policies exclude those trees; the root-context policy
does not exclude them as a class. This is an input inventory, not measured Docker
transfer, proof of complete production-input closure, or a claimed speedup.
Further exclusion requires checking actual compiler/recipe consumers and image
validation; do not replace the existing exact cfg(test) source-leaf guard with a
blanket source glob.

## A7 current-run revalidation (2026-10-06)

Core's latest successful [PR CI run 37419154761](https://github.com/ElevenID/marty-core/actions/runs/37419154761)
ran from 05:33:47 to 05:48:15 UTC (14m28s including orchestration).
Affected Rust Tests took 13m41s, including affected packages (6m57s),
private-key/session security (3m58s) and OID4VCI benchmark smoke (2m28s).
Fast Rust Preflight took 10m52s, including exact KMS/public-key graphs
(5m09s) and trusted-list client validation (2m21s).
The subsequent [complete-main run 37420390043](https://github.com/ElevenID/marty-core/actions/runs/37420390043)
had preflight 15m02s and Windows Platform Tests 16m49s; these are different
workloads, not a before/after speed comparison. Both workflows succeeded.
This fresh evidence retains A7's deferred disposition: moving preflight work
to another job is not yet shown to reduce the critical path, and no security,
feature, benchmark or platform qualification is removed on that assumption.
The newer successful [PR run 37460823351](https://github.com/ElevenID/marty-core/actions/runs/37460823351)
had a 12m30s preflight and 18m30s affected Rust tests; protected
[merge run 37463564302](https://github.com/ElevenID/marty-core/actions/runs/37463564302)
had a 12m43s preflight and 18m26s Windows lane. The jobs already run in
parallel and feed the same CI gate. A new preflight job would add runner and
cache startup without shortening either observed critical path, so A7 remains
deferred pending evidence that its position on the critical path changes.

2026-10-09 refresh: three successful revisions of Core's still-open security
[PR #355](https://github.com/ElevenID/marty-core/pull/355) now place preflight
on the *PR* critical path: [run 37946893659](https://github.com/ElevenID/marty-core/actions/runs/37946893659)
had 14.6m preflight versus 11.6m affected tests; earlier
[runs 37900258708](https://github.com/ElevenID/marty-core/actions/runs/37900258708)
and [37897508392](https://github.com/ElevenID/marty-core/actions/runs/37897508392)
had 14.6m/11.7m and 12.0m/10.2m. The latest preflight spent about 440 seconds
on the exact KMS/public-key graph and 163 seconds on disposable OpenBao
issuer signing. These are revisions of one large security PR, not independent
workloads or proof that another job reduces total time. The latest protected
[#354 run](https://github.com/ElevenID/marty-core/actions/runs/37828982922)
still had a 17.1m feature-matrix lane alongside 16.9m preflight and 15.7m
Windows. A7 remains deferred until a post-#355 representative run and a
no-duplicate-compilation split design show an actual critical-path benefit;
all security, feature, benchmark, and platform obligations remain required.

The later exact-head [#355 PR run 38001294613](https://github.com/ElevenID/marty-core/actions/runs/38001294613)
passed. Preflight took 726 seconds, affected Rust tests 472 seconds, and the
parallel Native ZKP Security Boundary 757 seconds. The latter spent 473
seconds on the disposable OpenBao issuance proof, 110 seconds on vendored
Longfellow regressions, and 64 seconds on a real prove/verify round trip.
Security started earlier and took longer, but preflight finished 32 seconds
later and was the last required job before the gate. Thus this run still puts
preflight at the PR tail, with only a 32-second observed tail to remove before
security becomes limiting; it does not establish a beneficial no-duplicate
split. A7 remains deferred. The current Core main selector includes deleted and
renamed files, package-owned non-Rust fixtures, and unknown-input fallback;
an older local checkout must not be used to reimplement those fixes.

## Next renewal decomposition: bounded obligations (unpublished)

The additive library owner is
`initiation_didcomm::tests::renewal_graph::renewal_private_ip_matrix_composes_real_didcomm_policy_and_crypto`
in `rust/services/issuance/src/initiation_didcomm/tests/initiation_didcomm_renewal_tests.rs`.
It composes the existing renewal, initiation and native DIDComm delivery services;
it does not implement a parallel renewal algorithm. Its four scenarios cross
authcrypt/anoncrypt with private-address allow/refuse. Existing private harness
repository and builder, plus a test lifecycle, remain test doubles; the endpoint
validator, peer-DID resolution and envelope encryption are production code.
Authcrypt sender resolution uses a loopback HTTP fixture, so this is a fast
service-owned component test, not a completely I/O-free pure unit test.

| Obligation | New fast owner | Retained acceptance owner |
| --- | --- | --- |
| Renewal reservation and offer composition | All four scenarios record the reservation; refusal returns a pending offer | Real SQL admission, source snapshots and offer fields in `support/renewal_fresh_main.rs` |
| Address refusal before irreversible native work | No credential-builder invocation, finalization, completion or recorded send; send fence remains Idle. An initial read-only transport-claim lookup is permitted | Actual wallet captures, unchanged source database state, no publication/events and no legacy fallback |
| Allowed encrypted delivery | Exactly one recorded send, Delivered state and decrypted recipient/message assertions; authcrypt also checks sender key identity | Packaged service, real HTTP wallet, persisted delivery/credential/event state and configured ingress |
| Deployment and process guarantees | Not proved by the new owner | Existing Gateway, Envoy and Kubernetes ingress profiles, Redis/configuration, startup and owned process cleanup |

The three proxy-ingress profiles still execute all four combinations in
`renewal_fresh_main::run_with_profile`; direct profiles retain their two allowed
encryption cases. No native case or tier is removed in this maintenance batch.
This mapping is a source-review inventory, not compiled discovery, execution
evidence, a complete dependency graph or authority to skip acceptance. Any later
tiering needs separately demonstrated database/process proof and an exact-head
hosted pilot. No hosted speedup is attributed to this additive proof.

The additive A0 renewal-profile inventory candidate records the six outer
`canvas_published_schema_contract` owners and three owned container children in
`contracts/canvas-renewal-profile-obligations.json`. Gateway, Envoy and
Kubernetes-Gateway each retain all four crypto/private-address combinations;
Kubernetes-native, rendered-native and packaged-direct retain both allowed
encryption modes. Its source guard checks exact owner-to-entrypoint wiring,
the shared case selector, frozen source fixture and fast 2×2 component owner.
The existing Canvas runner still executes the complete composition target in
routine and full tiers. Static registration cannot prove that an env-gated
test ran, a nested container child completed, or any SQL/process/image outcome;
existing owned-process and protected CI gates remain the execution evidence.
This inventory authorizes no skips or trigger narrowing. Its value is to expose
which crypto/policy cases have a fast owner and which real ingress, persistence
and cleanup obligations would still need proof before future decomposition.

An additive rendered-base configuration component test in the existing
`canvas_published_schema_contract` target exercises the actual bounded Compose
renderer for all four authcrypt/anoncrypt and private-address allow/refuse
combinations. It checks literal native private-IP, CA, policy-file, DID-web and
port settings plus Gateway legacy/native routes. The base renderer is shared
by the Gateway, Envoy and rendered-direct acceptance paths, but this one test
does not validate the Envoy sidecar, Kubernetes renderer, packaged-direct
defaults, a running service, real PostgreSQL/Redis, wallet I/O, or container
cleanup. It uses synthetic files and local addresses and needs the Compose CLI;
it is not an I/O-free unit test. The same composition target is executed by the
existing Canvas runner, with no case, tier or trigger changes. Local Windows
execution is not qualification for its Linux renderer: ordinary local tests
without the published-schema gate do not invoke Compose. The Linux runner
requires the compiled test name, successful composition executable exit and
exactly one marker emitted only after all four cases. Hosted exact-head
execution remains required before this proof can support a tier decision.

## Combined transport and dependency-boundary checkpoint (2026-10-06)

The unpublished UI assembly at `4b3433dcadf538f9ba9cc44ff2d3b8c119adb715`
combines the reviewed roster/renewal fast owners with typed OID4VP evaluation
transport. It preserves the producer-owned query, client ID, nonce, raw VP and
optional submission from Flow to policy without treating them as authenticated
credential evidence. Metadata requires workload authentication; external HTTP
cannot set it. The existing evaluator does not yet consume this metadata as
proof or activate holder binding. Historical requests without metadata and
existing raw-credential routes retain their legacy handling. Corrupted stored
query/binding is deliberately rejected before provider evaluation; this limited
fail-closed correction is not described as universally behavior-neutral.

Review cycles corrected workload authorization, verification-service consumers
and generated schema coherence. Python and Envoy outputs include the additive
policy field and current credential-template schema, with a parity guard.
Component review/test results are not assembly qualification. The assembled
reviews and targeted checks recorded below are local evidence; hosted CI and
protected merge remain required. No nightly release qualification is claimed.

Core [#353](https://github.com/ElevenID/marty-core/pull/353) merged at 12:48:16 UTC
as `a5cb567e6cd50e5a85b3b125a0a2ab6eea1d9fb7` after protected run
`37463564302` passed. It extracts the existing canonical JSON digest into a narrow
crate while retaining verification's public delegating API and exact
serialization/error semantics. The merged crate/manifests/governance code are
identical to reviewed source `fc7d029883d25a13c216756ff3e0056f2739c662`.

The unpublished UI assembly `0a64af54ae2144d2359736fefc2f1cce66dceafb` adopts
that verified main revision only for `marty-oid4vp-contract`'s digest dependency.
Existing Core pins, frozen digest profile identifiers, domain envelopes and error
mapping are unchanged. Package-scoped vectors (17 tests and one compile-fail
doctest), direct-dependency guards and strict four-consumer Clippy passed.
The reviewed consumer's distinct normal package graph entries fell from 456 to
56 (`cargo tree --edges normal`, duplicate display references removed). This is
a normal-dependency inventory, not a measured compile or CI timing saving.
Flow and policy still use heavyweight verification directly, and the additional
Core Git revision can incur fetch overhead. UI main has not adopted this batch;
hosted qualification and protected merge remain required.

## Assembled inventory and provenance checkpoint (2026-10-06)

The unpublished assembly `831e9ddd4589ba835ca8f6db04b64d88f1aaad5e`
passed independent interaction review and 165 targeted Python tests plus 44
subtests in 66.78s. It adds the six renewal-profile owners with their three
container children and the fast owner's test-only parent registration, and
source-backed EventStream publish edges to Auth and Organization. Service
changes still select the complete workspace; source markers and the hypothetical
five-package EventStream closure do not establish execution or authorize a cut.
No additional test or tier exclusion was introduced.

A fresh A5 audit found no new missing source-filename edge in the current
producer/import inventories. Original capture provenance remains incomplete:
only two of the 39 committed `canvas-worker-*-oracle.json` files contain
`capture_source_sha256`. These 39 files are not a one-to-one count of the 33
historical replay cases. Installed-worker hashes and fresh startup attestations
do not reconstruct all original helper/scenario/schema/image/runtime inputs.
Retain weekly/manual historical replay and exact-main full release qualification.
Do not reuse historical evidence without independently verifiable capture records
or a controlled, fully attested capture; neither retroactively inferred hashes
nor replacing expected outputs to match native behavior is acceptable proof.

Fresh startup attestation checkout identity (2026-10-08): the full-main
weekly/manual artifact now verifies that its claimed `GITHUB_SHA` is the actual
checked-out repository `HEAD` before writing evidence, and fails closed if Git
cannot verify that identity or the repository root differs. This tightens the
fresh artifact's run-to-source binding only; it does not attest original frozen
capture inputs, reduce historical replay coverage, alter qualification tiers,
or authorize evidence reuse. Focused tests cover a matching checkout, a wrong
but well-formed SHA, unavailable checkout, and absence of an output artifact
on either failure.

## HTTPS duplicate experiment disposition (2026-10-06)

When both Rust lanes are selected, both execute
`canvas_authoritative_https::actual_ags_nrps_https_uses_child_scoped_trust`:
the contracts workspace invocation and the Canvas lane's exact native HTTPS
step. The local candidate `00eddfbf66c0abaf48f6512851089967e8179a92` added
lane-aware exclusion, compiled substring-uniqueness discovery and execution
guards. Targeted policies passed, but independent review recommends not shipping
it: the new serial whole-workspace `--list` invocation and six-file policy delta
are disproportionate to the duplicate cost. In successful normal #1126
[Canvas job 112238131886](https://github.com/ElevenID/marty-ui/actions/runs/37454314639/job/112238131886),
that exact HTTPS step started and completed at 11:21:20 UTC (second-resolution
metadata, not a controlled benchmark). Its reported duration does not justify
adding another workspace discovery pass. Preserve the unpushed candidate for
audit and retain existing execution; no speedup or exclusion is promoted.

## Publication readiness checkpoint (2026-10-06)

Assembly `88ee6224e81119a0c8207cb743f3de7b979f412b` includes qualified main
`8d42d1bdc5cecda79947d6c7b720b83ec4091f01` and passed independent publication
review. The main merge preserved the previously reviewed tracked tree exactly.
The expanded local policy sweep passed 270 tests and 44 subtests in 61.68s.
Preflight-fixture repair passed the full file (174 passed, one skipped), followed
by focused checks for its final additive negative. The original 165-registration
fingerprint is still checked after subtracting only the new rendered-config
owner; a separate 166-registration fingerprint binds the complete new roster.
No existing registration, native case, deadline, tier or protected gate is removed.

Configured Flow clients now use the existing channel factory's mutual-TLS
capability to decide whether to send optional OID4VP metadata; other request
fields and metadata validation remain unchanged. Non-mTLS configured clients
omit that field while policy still rejects metadata without workload authority.
Public direct-client API shapes are preserved. This is wire/API compatibility,
not a claim that production plaintext evaluation works: policy's production main
already installs workload security even when its local server TLS is absent.

The Linux-only configuration test uses the existing acceptance opt-in. Its
completion marker is required after successful composition execution and all four
real-render assertions, with prefix/interleaving-safe counting. Local Windows
compilation and synthetic controls do not prove real Linux Compose execution.
Exact-head hosted CI must supply that proof before merge; no test-tier cut or
nightly release qualification is authorized by local readiness.

## Refusal and public-context follow-up checkpoint (2026-10-06)

The next unpublished batch includes independently reviewed source commits
`de0a8ec9a69bea23abc8a5673bbc708c74e04ffc` and
`504eb03b99ae3e9bd3855c62b48692c648faead0`, assembled as `bc50231e6` on
#1127 source `aaae1631482e002d063e23248be2a7bb041104c4`. It is not merged or
hosted-qualified; do not treat its local evidence as a test-tier authorization.

The renewal refusal case reuses existing Rust seed/admission/delivery fixtures
and a real owned PostgreSQL database without launching application processes.
It checks the persisted pending successor, unchanged issued source, absent
transport fence and issuance/delivery/event rows, typed `EndpointNotPublic`, and
zero builder/send calls. Both encryption modes are configured, but endpoint
refusal precedes encryption: this is not an encryption interoperability proof.
The local opted-in case passed and owned resources were verified removed.
The author passed 185 runner-policy tests with one skip; independent review
cleared its source and execution guards. All existing native cases remain.
On the assembled successor, the complete runner-policy/context sweep passed
192 tests with one skip in 331.21s; the shared service-image policies passed
another ten tests. Touched Python Ruff checks, shell syntax and diff checks passed.

The public Dockerfile's `!services/` rule admitted Python event modules into the
build context even though runtime `COPY` instructions do not use them. A tiny
BuildKit probe with the exact ignore rules confirmed baseline `COPY` success
for `services/common/events.py`, followed by missing-input failure with a later
explicit `services/common/` exclusion. Required entrypoint/auth-asset copies
still succeeded. The correction keeps the original matching helper and adds
guards against later wildcard or adapter-specific re-inclusion. Seventeen
focused policies and independent review passed. This proves a smaller input
surface, not a measured transfer/build-time saving or complete consumer graph.

A read-only follow-up found 332 files (3,936,267 bytes) under `scripts/`, but
the public Dockerfile copies only its three named scripts (about 5 KB total).
Those scripts do not source further scripts, and unrelated scripts cannot enter
their `COPY` layers. Although `!scripts/` can admit extra context inputs, no
transfer/cache critical-path cost was measured and BuildKit can request only
referenced inputs. Do not add another rule-maintenance layer for this unproven
saving; revisit only with actual transfer evidence.

#1127's CI found two test-maintenance defects: schema-parity collection imported
unavailable generated-module dependencies, and the complete Envoy descriptor
fingerprint still referred to the prior bundle. The parity test now decodes the
literal descriptor without executing generated imports. Inspection found only
the reviewed Presentation Policy/Credential Template additions changed in the
14-file bundle; the other twelve descriptors were identical. The fingerprint
was updated while retaining independent initiation RPC/type/route assertions.
Both fixes passed scoped checks and independent review. Exact-head normal CI
`37477668436` and CodeQL `37477668755` were live at this checkpoint; the Linux
rendered-config completion proof and protected merge are still required.
The contracts lane subsequently passed: its Linux log records both roster fast
owners, the real-policy/crypto renewal matrix and the independent descriptor
test as `ok` at 14:28:35 UTC. This is execution proof on #1127's exact source,
not qualification of the unpublished PostgreSQL refusal addition or main.

The same unpublished follow-up now includes independently reviewed
`23797c3624d8731c2baa659d2b2c055225cc45de`, assembled as `cfc74604d`.
It maps the real Signing Keys-to-Flow HTTP signer/key-envelope dependency through
configuration, authenticated provider startup, request-object signing and
encrypted-response callbacks to server handlers. Source-marker guards and the
hypothetical observed reverse chain are lexical inventory, not execution or a
complete consumer graph. Service changes still select the full workspace.
The assembled planner suite passed 20 tests and 63 subtests in 1.68s.

Reviewed Kubernetes source `24a51eb8f634c4a3414d9ff216a454cf14a4c851` is now
assembled as `93a779169`. It factors existing closed-spec validation and model
resolution without changing the native renderer's parent/child behavior. One
bounded real envsubst preparation supports four independently asserted literal
configuration outcomes, with opt-in discovery and a unique completion marker.
The author passed 189 preflight policies with one skip; the assembled four
Kubernetes marker controls passed. Windows compilation/discovery checks the
body but deliberately returns before rendering, so exact-head Linux execution
is still required. The six profiles and all eighteen native cases remain.

The current #1127 Canvas job recorded 10m10s of host test compilation and 9m20s
for the separate Bookworm compatibility compilation. Public release binaries
cannot replace that compatibility test executable. A single hermetic compile
could be investigated, but requires proving linker, flags, native dependencies,
cache access, artifact paths and execution on both Ubuntu and Bookworm. Keep the
two current guarantees until a bounded compatibility prototype supports reuse;
sharing a target directory alone is not proof or a measured saving.

The three renewal component owners are inventoried in reviewed source
`bc4f6fd92` plus correction `7d8448972`, assembled as `a5a9a9e6e`. Review caught
and corrected an omitted unconditional Compose helper input. Exact owner,
source/runner wiring and missing/duplicate/substitution controls passed; the
assembled ownership/planner/context/image sweep passed 72 tests and 63 subtests
in 17.91s. This inventory is lexical evidence, not execution or complete
transitive input closure, and does not authorize dropping any native case.

The reviewed OID4VP context proof (`5eb3a075`, assembled `11bb015e1`) adds
only two exact test-file exclusions to the root ignore policy. Existing scoped
test-directory exclusions remain unchanged; the bounded matcher recognizes
their directory ancestors and later negations. A tiny network-disabled BuildKit
probe with the three SHA-identical actual ignore files confirmed the production
contract corpus was copyable (3/3), both test files were excluded (6/6), and a
later explicit negation restored only its named file while retaining the other
exclusion and corpus. The owned scratch fixture was removed. This establishes
context behavior, not measured time savings or CI-selection authority.
The assembled policy sweep passed 73 tests and 63 subtests in 13.99s;
package-scoped frozen/offline Rust validation passed 16 contract vectors, the
transport matrix and the compile-fail evidence-construction doctest.

## #1127 qualification and next selection checkpoint (2026-10-06)

Exact PR source `aaae1631482e002d063e23248be2a7bb041104c4` passed normal
CI `37477668436` and all required checks. The Canvas log recorded exactly one
rendered-base completion marker and the real Linux owner as `ok` at 15:07:38
UTC; composition completed 143 tests with no failures. This does not qualify
the unpublished PostgreSQL/Kubernetes additions or a nightly release.
#1127 entered the normal protected queue at 15:12:45 UTC. Queue commit
`e2d8b37a4bfb5f913183581b1b1a0e03055cfff5` is being validated by CI
`37485559081`; no admin bypass or gate alteration was used.

The latest routine run took 51m22s, rather than #1126's 31m43s. Its Canvas lane
took 49m45s: host compile 10m10s, Bookworm compile 9m20s, public image 13m36s,
and database acceptance 12m53s. Different assembled code, build/cache state and
runner conditions make these observations unsuitable for attributing a steady
41% gain. Retain both observations and investigate rather than extrapolate.
The host cache health check succeeded, but counters were collected more than
38 minutes after compilation. With sccache's default 600-second daemon idle
shutdown, late zeros do not prove a cache bypass or describe Docker cache hits.
Capture sanitized host counters immediately after compilation before drawing
cache conclusions.

Reviewed selector source `17bd14bb3`, assembled as `ee0d2afa3`, admits only
the two exact OID4VP integration-test paths to the existing PR contracts lane,
and only after the verified-path CLI executes their ownership/context/corpus
proof. Contracts still run the workspace tests excluding Canvas acceptance;
existing lint, supply-chain and public/release policies are unchanged. Generic
Rust PR security selection remains governed by its existing policy, not a new
waiver. Unknown/mixed/deleted/renamed inputs or failed proof remain broad;
push/main, protected merge groups and full qualification retain full validation.
This batch itself changes workflow/runtime inputs and must run full CI.
The assembled compile-scope suite passed 32 tests. The three stale
completion-suffix assertions were corrected in the reviewed fail-fast source
before assembly. The later assembled sweep found three more stale renewal
ownership assertions: they assumed both configuration cases always ran in the
late composition group. Commit `560599673` updated those assertions to accept
the verified early execution followed by exactly two late skips; the
PostgreSQL refusal case still runs in the late group. All 35 renewal ownership
tests and the 200-test published preflight suite passed locally (1 preflight
skip). The combined policy sweep passed 216 tests, and an independent reviewer
cleared assembled source `e8d9f59e9` after 54 focused proof/owner/telemetry
tests and 11 shell fallback cases. Hosted Linux evidence for the early
base/Kubernetes proofs and the PostgreSQL completion marker remains required
before merge. No native process case has been removed.

## A6 shadow-planner ownership candidate (2026-10-07)

The two exact CI-only inputs `scripts/ci/plan_affected_rust.py` and
`tests/test_plan_affected_rust.py` currently select the entire PR matrix because
they fall through the general `scripts/*`/`tests/*` classifier. The shadow
planner is invoked by CI only and is excluded from the public service Docker
context. Release Contract Tests already run the complete root pytest suite on
Rust-selected PRs, including the planner tests; its own release selector also
selects that same job. This candidate routes only those two exact files to
release checks, moves the informational shadow report to that job, and removes
the duplicate planner unittest invocation from Rust Lint. Mixed Rust inputs,
unknown siblings, workflow edits, and protected merge groups retain their
existing broader lanes. No runtime/test behavior or production release gate is
relaxed. The report remains observational and does not authorize selective
Rust service execution.

Local policy validation passed 122 workflow-performance tests; planner pytest
passed 23 tests and 93 subtests. Independent review verified no other workflow
or service-image owner for the exact files and reproduced no-dependency Cargo
metadata plus all planner tests with an empty Cargo home. Existing hosted
[release-contract evidence](https://github.com/ElevenID/marty-ui/actions/runs/37550835490)
shows the same planner tests executing on the Ubuntu release runner. The
reviewed [#1134](https://github.com/ElevenID/marty-ui/pull/1134) passed all 23
exact-head PR and protected merge-queue jobs, then merged as `9b7bda36d` on
2026-10-07. Its protected [CI run](https://github.com/ElevenID/marty-ui/actions/runs/37564288453)
took 39m12s; the Canvas evidence retained 602 successful phase rows. This PR
changed the workflow itself and correctly ran the full matrix. No CI time
saving is claimed until a planner-only PR is measured under the merged rule.

## A6 bounded evidence-test ownership batch (2026-10-07)

Four exact root pytest sources for Canvas startup evidence, native validation
tier selection, Python-value fast obligations, and renewal-profile obligations
are collected by the existing Release Contract Tests job. They are test sources,
not manifests, corpora, implementation scripts, service-image inputs, or
security-scanner targets. Their manifest inputs continue to select Rust and
release qualification; implementation scripts and unknown sibling tests keep
the conservative full PR matrix. Mixed changes retain the union of their
owners, and protected merge groups still require every CI lane to succeed.

The selector changed only these four exact paths and added synthetic
tests against the real Bash classifier for their release owner, manifest and
script owners, unknown siblings, mixed Rust changes, and full merge-group
behavior. The complete workflow-policy test file passed locally (123 tests),
as did all four selected source files (90 tests) through the same
`python -m pytest` entrypoint used in CI; Ruff and diff checks passed. An
independent reviewer found no other required runtime, image, scanner, or
workflow consumer. Reviewed [#1138](https://github.com/ElevenID/marty-ui/pull/1138)
merged as `d2dcd0630` after its [PR run](https://github.com/ElevenID/marty-ui/actions/runs/37574211476)
and full protected [queue run](https://github.com/ElevenID/marty-ui/actions/runs/37577548015)
passed. Because the workflow itself changed, the #1138 PR run used the full
matrix; the protected Canvas artifact retained 602 `ok` rows. Future PRs
editing only one of these exact test sources can use the scoped release owner.
No shortened hosted run is claimed here, and implementation-input gates remain
unchanged.

## 2026-10-06 protected Canvas and feedback checkpoint

[UI #1127](https://github.com/ElevenID/marty-ui/pull/1127) passed protected
validation and merged as `e2d8b37a4` at 16:04 UTC. The subsequent reviewed
[#1129](https://github.com/ElevenID/marty-ui/pull/1129) merged as `6d9828abd`,
preserving both early configuration proofs and late required completion checks.
[#1130](https://github.com/ElevenID/marty-ui/pull/1130) merged as `18c830498`
with sanitized live timing and machine-readable evidence. Its protected
[baseline run](https://github.com/ElevenID/marty-ui/actions/runs/37532971594)
passed all 23 jobs: Canvas 51m36s, including 666s host compilation, 594s
Bookworm compatibility compilation, 780s public image build, 124s preflights,
and 811s DB contracts. Its Canvas artifact had 602 all-successful phase rows.

Reviewed [#1131](https://github.com/ElevenID/marty-ui/pull/1131) retained the
same selectors, historical pins, qualification tiers, DB connection limits,
real-time deadlines, and evidence gates. It reused one pinned Bookworm test
build for compatible host/runtime acceptance and added fixed worker/ordinary-DB
timings. Independent review caught and corrected an incomplete case-ID
allowlist; hosted evidence review caught Rust libtest's capture of successful
ordinary-DB timing prints, which was fixed without enabling broad test logs.
The corrected PR run passed all 23 jobs, and protected
[merge-queue run](https://github.com/ElevenID/marty-ui/actions/runs/37546357580)
passed all 23 again; #1131 merged as `07bfe6170` at 23:56 UTC. That queue's
Canvas job took 31m57s: 520s shared compile, 593s public image, 122s
preflights, and 560s DB contracts. The directly attributable compile-stage
reduction against the prior queue was 1,260s to 520s (12m20s, 58.7%); image
and DB differences on unchanged stages are run variation, not proven savings.
The merge-candidate Canvas artifact retained 602 all-successful phase rows,
both target exits were zero, and all three required completion markers appeared
once. Its contracts artifact retained 30 successful group totals plus all 15
successful composite phase rows. The 98.2s composite was dominated by real
renewal generation (10.2s), write-failure boundaries (30.3s), and outcomes
(51.6s); no wait was shortened. Overlapping those sections would require
independent DB ownership and measured connection headroom, with at most about
40s theoretical savings in the non-critical contracts lane. The 13 Canvas
validation cases already use isolated template clones; remaining pinned probes
require fresh database provenance, so no broad pre-migrated clone is justified.

The A0/A3/A5/A6/A8 obligations in the queue above remain active or explicitly
deferred. These protected runs establish the scoped Canvas feedback improvement,
not a complete dependency graph, nightly qualification, or a whole-pipeline
causal speed claim.

## 2026-10-07 Flow reference edges and latest timing checkpoint

Reviewed [#1132](https://github.com/ElevenID/marty-ui/pull/1132) merged as
`b0f1b1ff5` after normal [PR CI](https://github.com/ElevenID/marty-ui/actions/runs/37550835490)
and protected [merge CI](https://github.com/ElevenID/marty-ui/actions/runs/37553423042)
both passed. Their Canvas jobs took 25m59s and 37m02s, respectively. In the
protected job, shared test compilation took 592s, public self-host image build
754s, preflight 122s, and DB contracts 634s; the matching PR stages took 403s,
503s, 119s, and 435s. The unchanged stages also varied substantially, so these
runs do not establish a regression or saving from the shadow-only #1132 edit.
Both Canvas artifacts retained 602 successful phase rows and the required
published-process completion markers; the contracts artifact retained 30
successful group totals and 15 successful phase rows. The host `sccache` report
showed three non-cacheable requests and zero hits on each run; it does not
measure the hermetic Bookworm container compiler, which does not receive the
host wrapper. Do not infer a cache failure from those counters.

Flow's HTTP reference provider is constructed from the configured Issuance,
Credential Template, Trust Profile, and Deployment Profile URLs. Activation
resolves application templates, delivery destinations, trust profiles, and
deployment profiles against published HTTP routes and checks returned identity,
tenant binding, and status. This batch records those four producer-to-Flow
relationships as source-backed observations only. The Issuance native URL can
still resolve to the legacy HTTP owner in production; no runtime deployment
ownership or selective gate is inferred from the route alone. The complete
non-Cargo graph and obligation closure remain unproven.

Reviewed [#1133](https://github.com/ElevenID/marty-ui/pull/1133) merged as
`0c7f0b85f` after all 23 PR and protected CI jobs passed. Its protected
[Canvas job](https://github.com/ElevenID/marty-ui/actions/runs/37560386014)
took 31m29s; its timing artifact retained 602 successful phase rows. This is
another shadow-only graph observation, not a measured speed improvement.

Reviewed [#1135](https://github.com/ElevenID/marty-ui/pull/1135) merged as
`1101df217` after its [PR CI](https://github.com/ElevenID/marty-ui/actions/runs/37567520703)
passed in 10m56s and its full protected [merge CI](https://github.com/ElevenID/marty-ui/actions/runs/37568458712)
passed all 23 jobs in 35m42s. The PR ran the owning release suite (including
the new planner test) and final CI gate while unrelated PR lanes were planned
skips; the protected run retained full Canvas validation and 602 successful
phase rows. Against #1134's 39m50s full-matrix PR run, this exact-input
feedback cycle was 28m54s shorter. These were different changes on different
runners, so this is an observed scoped-path turnaround, not a Canvas execution
speedup or a whole-repository average.

The merged A3 change records Organization's configured gRPC membership
consumers in Compliance Profile, Deployment Profile, Revocation Profile,
Presentation Policy, and Gateway. Each edge has a concrete configuration,
client/request, and Organization server source marker; Gateway's gRPC evidence
enriches its existing HTTP edge rather than duplicating the consumer. The
planner still selects the whole Rust workspace for service changes. These
observations do not close the remaining runtime, proto, rendered-deployment,
or acceptance-test dependency graph and do not authorize a narrower gate.

Reviewed [#1137](https://github.com/ElevenID/marty-ui/pull/1137) merged as
`daaa41ecb` after its [PR CI](https://github.com/ElevenID/marty-ui/actions/runs/37572181846)
passed in 10m14s and its full protected [merge CI](https://github.com/ElevenID/marty-ui/actions/runs/37573042075)
passed all 23 jobs in 39m30s. The protected Canvas timing artifact retained
602 successful phase rows. This scoped PR result confirms feedback selection;
it is not a faster Canvas run or a complete non-Cargo dependency map.

This merged A3 observation records that Issuance, Credential Template, and the
conditionally enabled Verification Credentials compatibility resolver use
`SIGNING_KEYS_INTERNAL_URL`, defaulting to Gateway's authenticated
`/internal/signing-keys` route. Each requests `resolve-issuer-did`; Gateway
forwards it to Signing Keys' `/internal/compat/resolve-issuer-did` handler.
Verification can fall back to a public DID resolver when its governance policy
allows it, so that edge is conditional rather than a claim of exclusive
dependence. The planner records these three source-backed consumers but keeps
full-workspace service selection. No runtime implementation, release tier,
test execution, or CI gate changes were made.

## A6 workflow-policy feedback outcome (2026-10-07)

The protected #1137 release job spent 639 of its 713 seconds in root pytest.
Timestamp gaps in its completed log identify one synthetic Rust-leaf classifier
regression as an approximately 99-second span; those gaps are diagnostic, not
pytest per-case duration measurements. The test repeatedly classified twelve
independent immutable leaves and rebuilt the same source-ownership inventory
for each synthetic diff. The test-harness-only change retains the real Bash
classifier and a separate result assertion for each leaf, but computes the
unchanged inventory once per synthetic Bash process. Failed proof still forces
the full Rust runtime plan. The exact test passed locally in 50.96 seconds
before and 15.85 seconds after this change; the full policy file passed all
122 tests in 31.32 seconds. These were local measurements; hosted results
are recorded below.

The same exact policy-test source has only the root release pytest execution
owner. The merged selector routes edits to that source to release checks while
retaining mixed/unknown inputs and full protected merge-group validation.
Independent review found and corrected a deletion gap: the release job now
requires `pytest --collect-only` to find this file and its tests before the
normal root suite executes them once. Local collection found 122 cases in
0.23 seconds. No runtime test, image, scanner, or security obligation is
removed; the workflow edit itself passed the complete CI matrix.

Reviewed [#1139](https://github.com/ElevenID/marty-ui/pull/1139) merged as
`09ea89f6b` after its [PR run](https://github.com/ElevenID/marty-ui/actions/runs/37576733858)
and full protected [queue run](https://github.com/ElevenID/marty-ui/actions/runs/37580336046)
passed all required jobs. The workflow edit made its PR run a full-matrix
validation; a future exact policy-test-only edit can use the scoped release
owner. The protected Canvas artifact retained 602 `ok`
rows. Review caught and corrected an inherited-environment bypass, a
missing-file collection gap, and a stale policy count before merge. The
focused local proof fell from 50.96s to 15.85s. Hosted PR root pytest took
364.10s versus 549s on #1138, but protected #1139 took 495.91s; runner and
suite variation prevent treating that comparison as a guaranteed whole-CI
gain. The exact policy-test-source route retains release collection and the
complete protected matrix.


## A0 public-vector execution proof (2026-10-07)

The existing public-protocol guard inventories 23 Rust tests that load the
gateway behavior vectors and verifies their source/test registration, but that
static check alone cannot prove a current Cargo invocation executed each test.
The authenticated log of the completed
[contracts job for PR #1138 (CI run #2891)](https://github.com/ElevenID/marty-ui/actions/runs/37574211476/job/112639403441)
contained an exact successful libtest line for all 23 declared owners. This is
execution evidence for that run, not proof of each vector's dynamic assertion
coverage or of a future run.

Reviewed [#1141](https://github.com/ElevenID/marty-ui/pull/1141) added a
fail-closed post-workspace check in the existing Rust contracts job. It reads
the already-produced `rust-workspace.log`, derives
qualified test names from the same 23-owner inventory, and requires an exact
`ok` line for every owner. Ignored, failed, missing, and merely similar names
do not satisfy it. The existing static owner guard also requires the checker
to remain a contracts-lane step after the workspace run. No Cargo command,
test selection, security check, or protected merge-group gate is removed or
repeated. The checker passed against the completed hosted log after stripping
GitHub's display timestamps; 25 focused local tests and 123 workflow-policy
tests passed. Independent review caught a step-placement/lane guard weakness,
which was corrected and covered with negative mutations before PR validation.
The [PR run](https://github.com/ElevenID/marty-ui/actions/runs/37582424997)
passed all required checks. Its full protected [merge-group run](https://github.com/ElevenID/marty-ui/actions/runs/37586114017)
also passed and logged "Verified 23 public vector Rust test executions"; it
merged as `ec932e49f`. The Canvas test totals matched the preceding protected
run (144 composition and 101 worker tests passed, two capture-only worker
tests ignored). Its timing artifact contained 601 successful phase rows;
compared with the preceding 602-row artifact, the missing row was one
`postgres_ready` timing event, not a missing test. The remaining Canvas,
service-acceptance, and transitive input inventories are not closed by this
narrow proof.

## A0 published-probe timing attribution (2026-10-07, reviewed candidate)

The protected Canvas timing artifacts for [#1144](https://github.com/ElevenID/marty-ui/actions/runs/37605210608)
and [#1145](https://github.com/ElevenID/marty-ui/actions/runs/37614331029)
each contain 602 phase rows and 125 published-canvas `migration_seed` rows.
Of those 125, 121 share the name `published_probe`, hiding which fixed
constructor produced the event. This phase wraps the whole pinned probe,
including migration, seed, and oracle work; summed phase durations overlap
concurrent targets and are not wall-time savings or SQL-only costs. The
later run was slower across readiness, probe, and scenario phases, not just
one named fixture.

The next A0 slice labels only the 25 reviewed, fixed constructor script
origins; unknown scripts retain `published_probe`, and checked-in worker
matrix case labels keep their existing separate validation. Rust and Python
allowlists are compared against all current constructor origins by a policy
test, with one pure Rust test for accepted and fallback paths in the
composition-only diagnostic owner. No case selection, Docker operation,
oracle, or protected gate changes. This improves future diagnosis but does
not claim faster CI or justify database cloning without finer measurements.
The local policy file passed 26 tests; the composition-only Rust test and
package-scoped check passed on Rust 1.95. Independent review found no issue.

## A6 protocol-test source ownership follow-up (2026-10-07)

`tests/test_gateway_public_protocol_contract.py` and
`tests/test_public_vector_execution.py` are root pytest sources collected by
the existing Release Contract Tests job. The public-protocol job executes the
checker script, not these test files. Reviewed
[#1142](https://github.com/ElevenID/marty-ui/pull/1142) routes edits to either
exact test source to its release execution owner; edits to the checker, vector
corpora, Rust implementations, workflow, or unknown siblings retain their
existing broad owners. Its 148 targeted tests passed locally, and full
[PR](https://github.com/ElevenID/marty-ui/actions/runs/37590799370) and
[protected](https://github.com/ElevenID/marty-ui/actions/runs/37595339340)
CI passed. The protected Canvas job ran 144 composition and 101 worker tests
with two capture-only ignores and 602 successful timing rows, then #1142
merged as `7308713f0`. Protected merge groups remain full. This workflow-edit
PR ran the full matrix; no future scoped-PR saving is measured yet.

Canvas preflight test-source follow-up (2026-10-07, merged in #1144):
`tests/test_canvas_published_preflight.py` is a synthetic Bash/runner policy
test collected by root release pytest; it is not the shell runner or a Rust
acceptance executable. Its exact-path PR routing now selects the release
owner. The actual `scripts/ci/run-published-canvas-contracts.sh`, Rust targets,
image inputs, corpora, unknown test siblings, and mixed implementation edits
retain their broad owners; merge groups still run the complete matrix. The
real classifier is exercised for each boundary. This avoids an unrelated
Canvas build on a future edit to only that test source, but this workflow-edit
PR itself ran full PR/protected CI and has no measured scoped saving yet.

Fixture-policy test-source batch (2026-10-07, merged in #1145): eight frequently
edited, exact root pytest sources covering Kubernetes, base runtime, Envoy,
Flow startup, self-host, passport model/Compose ownership, and Canvas compile
scope have the Release Contract Tests root pytest step as their CI execution
owner. A repository reference search found no separate workflow invocation or
runtime-image copy of these Python test files; the public/CI service images
copy explicit Rust, proto, contract, service, and script inputs, not root
`tests/*.py`. Reviewed [#1145](https://github.com/ElevenID/marty-ui/pull/1145)
routes edits to those exact test-only sources to release pytest. Their
production/fixture scripts, Rust acceptance
owners, Compose and workflow inputs, unknown siblings, and protected merge
groups retain broad checks. This reduces future test-source-only PR feedback
scope, not this workflow-edit PR's full validation, and no time saving is
claimed until hosted scoped evidence exists. Its full
[PR](https://github.com/ElevenID/marty-ui/actions/runs/37609491436) and
[protected](https://github.com/ElevenID/marty-ui/actions/runs/37614331029)
CI passed; the protected Canvas group retained 144 composition and 101 worker
passes with two capture-only ignores. It merged as `9704826da`. The
protected Canvas compilation and image-build steps took 10m07s and 11m45s,
versus 7m07s and 8m55s in #1144's protected run; runner/cache conditions
were not controlled, so neither difference is attributed to this PR.

## A6 Canvas timing-relay reliability follow-up (2026-10-07)

The #1145 PR Canvas run passed the required test cases but its optional timing
artifact contained only 314 phase rows instead of the prior 602. The hosted
log reported `tail: cannot open .../worker.log` and missing optional worker
timing. The runner launches each Rust child with log redirection and then
starts a `tail --pid` relay; scheduling can start `tail` before the child
creates its log. Precreating both owned log files after registering EXIT
cleanup and before launching either child closes that race. The child waits,
exit statuses, signal handling, and raw-log reporting remain unchanged.
Four focused local tests, Bash syntax, Ruff, and diff checks passed; an
independent reviewer found no issue in the corrected two-file diff. This is
timing-evidence reliability, not a speedup or a change in required coverage.
Reviewed [#1147](https://github.com/ElevenID/marty-ui/pull/1147) passed full
[PR](https://github.com/ElevenID/marty-ui/actions/runs/37619375243) and
[protected](https://github.com/ElevenID/marty-ui/actions/runs/37624284472)
CI, retaining 144 composition and 101 worker passes and two expected worker
ignores, and merged as `099422c0`. Its PR artifact had 602 successful rows;
the protected artifact had 601, including both `canvas_target` rows, with no
tail-open or missing-target warning. In the database-group step, all 554 raw
target phase markers had matching live relay records. The one-row variation
is therefore not a dropped relay line; it is one fewer emitted
`migration_seed` marker than in #1145's protected artifact. Do not interpret
it as a removed test or a proven speed change.

## A6 HTTP timeout test pyramid (2026-10-07, merged)

Reviewed [#1148](https://github.com/ElevenID/marty-ui/pull/1148) merged as
`77d2644e8`; its protected [CI run](https://github.com/ElevenID/marty-ui/actions/runs/37636041696)
passed, including Canvas. The fixed constructor-origin labels are diagnostic,
not a measured speedup.

The 104-case Canvas timeout corpus tests several separate responsibilities.
Deadline scalar conversion, operation-scoped budgets, cancellation, and
header/body transitions are our code and should be tested with in-memory
futures/duplex I/O. Content decoding and response text have their own fast
unit owners. The historical pinned HTTPX socket corpus is independent
compatibility evidence, but repeatedly exercising HTTPX/TLS timing in routine
PR and merge-queue CI mostly tests dependency scheduling. Keep that complete
historical probe and all 104 native TLS observations in `schedule` or
`workflow_dispatch` full qualification. The stable stack-tag policy requires
a successful full-qualification run on the *exact* main SHA, so official
release evidence is retained. Routine CI should retain one real TLS
`body_timeout` case to verify client configuration, TLS transport, and timeout
error classification across the wiring seam, plus
`untrusted_certificate` as a distinct TLS security assertion. Neither is a
substitute for worker/database timeout and lease tests, which prove our own
durable behavior and remain in their existing tiers.

Reviewed [#1150](https://github.com/ElevenID/marty-ui/pull/1150) merged as
`c6503e33f` after full [PR](https://github.com/ElevenID/marty-ui/actions/runs/37644735841)
and [protected](https://github.com/ElevenID/marty-ui/actions/runs/37648996240)
CI passed. It added the in-memory body-stall test, explicit routine/full native
case selection, and a fail-closed completion marker for the full historical
probe. The protected Canvas database group took 10m28s versus 12m30s on
#1148's protected run, an observed 2m02s improvement. Composition took 549s
versus 688s; the concurrent worker target took 566s versus 549s. The known
historical probe was omitted from the routine tier, but runner/workload
variation prevents attributing the entire wall-time difference to that skip.
The protected artifact retained 598 successful rows, 144 composition and 101
worker passes, two expected capture-only ignores, and exactly two native TLS
case observations.

The exact-main [manual full qualification](https://github.com/ElevenID/marty-ui/actions/runs/37654158438)
then passed all 23 jobs. It ran the pinned HTTPX probe once (353s), all 104
native TLS observations, 145 composition and 134 worker passes, two expected
ignores, and 1,179 successful timing rows. This is the release evidence tier,
not the routine feedback baseline. Future edits to main need their own
exact-SHA full run before stable tag preparation.

## A6 root test-source ownership batch (2026-10-07, merged)

Eight frequently edited root Python test sources for Rust candidate,
Kubernetes issuance, shared image, passport provisioning/Compose, native
conformance, and Gateway cutover policies have the existing Release Contract
Tests root pytest step as their execution owner. Local collection found 265
tests across these exact files. No workflow or runtime-image Dockerfile
directly names them; image build contexts copy explicit Rust/proto/contract
inputs or isolated UI/test subdirectories. The merged rule routes edits to
only these eight test sources to release pytest. Their production scripts,
manifests, Dockerfiles, corpora, unknown siblings, mixed inputs, and protected
merge groups retain their existing broad selection. Reviewed
[#1151](https://github.com/ElevenID/marty-ui/pull/1151) passed its full
[PR](https://github.com/ElevenID/marty-ui/actions/runs/37662413147) and
[protected combined-head](https://github.com/ElevenID/marty-ui/actions/runs/37666726063)
runs and merged as `447f8ce74`. The protected Canvas database step took
10m14s, versus 10m28s on #1150's protected run; both workflow-change PRs
correctly ran the full matrix, so this is not an attributable speed saving.
The eight source files had no source-only commit in the inspected recent
history, so no scoped-run saving is claimed until such a future PR produces
hosted evidence.

A6 current-Canvas-input helper ownership (2026-10-08, local candidate): the
exact `scripts/ci/canvas_oracle_current_inputs.py` module is imported only by
the startup, REST, and producer-inventory root Python tests collected in
Release Contract Tests. It is not a Rust attestation/capture entrypoint, a
direct CI command, or an included service-image input. A helper-only PR can
therefore retain its release-test owner without selecting unrelated PR lanes.
The exact selector has source/consumer and image-context regression checks;
unknown script siblings and mixed inputs retain their other obligations, and
merge groups and weekly/manual/stable qualification remain full. The helper
was introduced in a mixed commit, so there is no comparable helper-only
normal-run timing yet and no speedup is claimed.

## A3 merge-group historical-input shadow (2026-10-07, merged)

The merge-group classifier conservatively sets `all=true` while checking the
combined head's changed paths. Reviewed [#1152](https://github.com/ElevenID/marty-ui/pull/1152)
passed full [PR](https://github.com/ElevenID/marty-ui/actions/runs/37672064740)
and [protected](https://github.com/ElevenID/marty-ui/actions/runs/37676439510)
CI and merged as `5c10abcf6`. The change checks out the
exact combined head and reports a bounded, machine-readable observation of
whether its base-to-head diff touches broad historical-oracle input families.
Missing base/history or a failed diff reports `unknown`; the required full
merge-group matrix is unchanged in every case. The same observation is logged
on PRs for comparison. This is not a complete transitive input closure, a
qualification decision, or permission to skip a test. Focused synthetic
checks cover candidate and unrelated paths, mixed diffs, failed fetch, and
missing base; the workflow-policy suite passed 127 tests locally. Its protected
classifier logged `merge_group`, `proved`, three changed paths, and
`shadow-only` authority. This observes one combined head, not a general
selective-validation proof or an attributable pipeline speedup.

The preceding protected #1150 timing artifact measured `json_depth` at
126.1s in the pinned published migration/oracle probe and the isolated
`json_consumer` diagnostic at 51.8s. The depth probe expands 64 validation
and 64 provider cases over real published app/database behavior. Native
validation, provider, and full credential-route owners exist, but moving the
historical probes out of routine CI requires complete mounted-input closure
and change-triggered full qualification, including merge-group semantics.
Those conditions are not yet established; the probes remain required.

## A4 Canvas repository-case database reuse (2026-10-07, merged)

The published Canvas worker contract has two repository-only matrices: ten
roster metadata reconciliation cases and twelve resource-race stale-write
cases. Each case previously started a fresh pinned PostgreSQL container and
ran the same schema migration, even though its mutable rows are case-local.
The thirteen-case worker-validation matrix already proves an isolated
`CREATE DATABASE ... TEMPLATE` pattern in this suite. Reviewed
[#1153](https://github.com/ElevenID/marty-ui/pull/1153) reuses
that pattern: one migrated, unseeded template container per matrix, a distinct
database clone and four-connection pool per case, and explicit verified close
and drop after each case. It does not change case lists or assertions,
PostgreSQL limits, production behavior, or the existing fresh-database probes
whose provenance matters. A panic still invokes the owning container's cleanup.

On one Windows/Docker host, passing baseline roster and race executions took
136.24s and 54.40s of test time; the rebuilt candidate executable took
71.10s and 6.20s respectively. The existing thirteen-case validation matrix
also passed in 6.90s. One earlier baseline roster attempt failed, so these
single passing samples do not establish steady-state or CI critical-path
savings. Independent review found no concrete issue. Full
[PR](https://github.com/ElevenID/marty-ui/actions/runs/37682037047) and
[protected](https://github.com/ElevenID/marty-ui/actions/runs/37686594643)
CI passed, and #1153 merged as `dbb28c1ce`. The current routine Canvas lane
still executes every named matrix. Both hosted logs report the roster,
resource-race, and validation repository tests as `ok`. Their timing artifacts
have 518 successful rows, zero failed rows, and 110 startup/migration events,
versus 130 events before the change. The PR database step took 9m05s versus
7m10s on preceding #1152 PR CI; protected took 7m13s versus 10m25s on
preceding #1152 protected CI. Unchanged composition also varied strongly, so
these contrasting wall-time samples establish less repeated setup, not a
causal CI speedup.

## A0/A6 repository-matrix timing follow-up (2026-10-07, merged)

The #1153 artifacts count database setup but have only an aggregate worker
target duration for the roster, resource-race, and validation repository
matrices. This prevents separating their test work from concurrent process
cases and runner variation. A focused follow-up uses the existing sanitized
CI phase stream to time the database/case work of exactly those three matrices,
including template setup and owned cleanup but excluding initial reference
loading. Fixed Rust enum variants emit fixed labels;
the Python collector accepts them only as `scenario` rows, not fixture or
cleanup names. It does not change test assertions, selections, databases,
runtime deadlines, or required gates. Local policy/formatting checks pass;
the package-scoped Rust test compiled, strict package Clippy passed, and a
disposable PostgreSQL resource-race run emitted the exact `scenario` marker
with `ok` after owned cleanup. No labeled container remained. Independent
review found no blocking issue and verified the existing CI relay path.
[#1155](https://github.com/ElevenID/marty-ui/pull/1155) merged as
`6b045bb8d` after the full protected
[run](https://github.com/ElevenID/marty-ui/actions/runs/37696757136)
passed. Its timing artifact contains exactly one successful `scenario` row
for each of `repository_resource_race` (19.820s),
`repository_validation` (13.499s), and `repository_roster_metadata`
(73.234s), with zero failed rows. These timings improve attribution, not
runtime by themselves.

## A4 roster-metadata case ownership (2026-10-08, merged)

The protected #1155 timing artifact measured `repository_roster_metadata` at
73.234s, but two natural 30-second lease-expiry cases account for most of its
expected duration. The original published worker repository matrix had ten
cases in one sequential PostgreSQL test. The production cursor patch now has
one pure owner for the five snapshot-value shapes (`absent`, `preexisting`,
`explicit_null`, `worker_only`, `heartbeat_only`), with literal expected JSON,
absence-versus-null assertions, and a fixed completion timestamp. The exact
case IDs are frozen in `contracts/canvas-roster-metadata-obligations.json` and
checked at both fast and database owners.

The published PostgreSQL adapter retains `absent`, `preexisting`, and
`explicit_null` to prove the real JSONB remove/merge, unrelated concurrent-key
preservation, and durable row effects. It also retains all five fence cases:
`stale_target_generation`, `wrong_owner`, `wrong_attempt`,
`expired_before_write`, and `expired_during_lock`. The latter two still await
real leases and prove different failure points. Only `worker_only` and
`heartbeat_only` stop repeating the cloned-database matrix; their production
patch paths remain covered by the fast owner. Published whole-worker process
and frozen-oracle checks are unchanged. The independent reviewer cleared the
source-preserving extraction, focused Rust checks passed, and full PR plus
protected combined-head CI passed, including the Canvas database lane.
[#1172](https://github.com/ElevenID/marty-ui/pull/1172) merged as `b5cf2ae53`.
This change does not shorten real leases or establish an attributable CI
speedup; collect comparable case timing before claiming one.

## A4 validation-decision fast owner (2026-10-09, merged)

The protected #1155 timing artifact measured the 13-case published
`repository_validation` matrix at 13.499s. The merged change extracts
its existing field, scope, and reference decisions from the PostgreSQL adapter
without changing SQL reads, error precedence, target-disable calls, or job
failure handling. A typed, literal fast table owns all 13 frozen repository
case IDs, error codes and summaries, terminal/no-retry policy, and disable
decisions; it checks the frozen oracle without deriving expected values from
the production classifier. Five PostgreSQL cases remain for the distinct real
scope JOIN, archived/stale durable disable, and application/candidate
post-read existence races. Their lease, dead-letter, target/OAuth/facts,
preservation, and cleanup assertions remain. The separate native and pinned
historical 20-case qualifications remain selected in full.

The tier-obligation inventory and run-bound contracts/Canvas guards now name
the fast and database owners explicitly; otherwise ten routine-excluded cases
would have retained a stale database-owner claim. On one local Windows/Docker
host the five-case pinned-schema boundary passed in 9.650s, while the earlier
13-case hosted sample was 13.499s. These are not comparable conditions, so no
CI speedup is claimed. Rust 1.95 package check and the fast unit test passed;
293 focused policy/preflight tests passed with one existing skip. Independent
review found no P1-P3 issue. [UI #1198](https://github.com/ElevenID/marty-ui/pull/1198)
passed full [PR run 37877894198](https://github.com/ElevenID/marty-ui/actions/runs/37877894198)
and protected [merge-group run 37880523315](https://github.com/ElevenID/marty-ui/actions/runs/37880523315),
then merged as `cdc184dba`. The fast Rust owner test and retained published
database/worker suites executed successfully. The `repository_validation`
scenario measured 22.928s in PR CI and 4.692s in protected CI, versus 13.499s
in the earlier #1155 protected run. This spread does not establish an
attributable wall-time improvement from the split. One required approval was
restored after merge.

## Product packaging and integration workstream (added 2026-10-07)

The local product plan (`artifacts/consumer-audit-2026-10-07/marty-product-packaging-and-integration-plan.md` in the coordinating workspace) defines PKG01-09, INT01-06, TST01-05, CICD01-04, BUS01-02, MKT01-02, and QA01-02. Those IDs are retained here so progress and acceptance evidence can be reconciled without duplicating the plan's full text. This tracker remains the active engineering queue; the product plan retains the detailed product and commercial acceptance criteria.

| Product-plan work | Existing architecture/CI work | Next implementation boundary and evidence |
| --- | --- | --- |
| TST01-05, CICD01 | A0, A1, A3-A6, A8 | Extend the existing test-obligation inventory to affected product/profile cases. Keep old-to-new case IDs, fixtures/assertions, required lanes, run-bound parity, and fail-closed selection; do not turn nightly discovery into a substitute for required merge/release checks. |
| INT01, PKG01, PKG02 | A0, A3, A6 | The opt-in no-Canvas Compose preview now preserves default Canvas worker behavior. Next repair the release bundle against anonymously accessible, digest-bound artifacts and clean-install evidence. The v1.1.231 release transaction confirms the image-role gap; an anonymous pull and complete installation remain unproven. |
| PKG03-07, INT02-04, CICD02 | A1, A2, A4, A6 | Define verification/issuance and adapter dependency closures, contracts, ownership, migrations, and small qualified product artifacts. Extract shared Rust behavior once; keep tenant/security/transaction proofs with their real boundary. A smaller image alone does not establish an independent verifier. |
| INT05-06, PKG08-09, TST04, CICD03-04 | A0, A4-A6, A8 | Prove installed capability authorization, existing-customer migration/recovery, documented public SDK/install paths, exact-artifact journeys and digest-preserving promotion before claiming support. Keep full official-release E2E and critical negative/security evidence. |
| BUS01-02, MKT01-02, QA01-02 | Product/commercial review alongside engineering | Inventory licenses, source/notices and demonstrable public artifact facts. Commercial/legal owners must decide pricing, license routes, hosted availability and public claims; engineering does not invent or publish these. Independent consumer handoffs must use public artifacts. |

Immediate engineering batch: INT01/PKG01/TST01/CICD01 begins with an opt-in
no-Canvas composition preview. Its pre-change obligations are the
`canvas-sync-worker` Compose launch and bundle merge contract, enabled Canvas
configuration fail-fast, the production deployment catalog, and the no-Canvas
render. Preserve the existing default and all Canvas-enabled assertions;
add a layered profile activation proof without changing the shipped worker
selection. Existing issuance services still carry Canvas secrets/code/migrations,
so an optional overlay is only a first installation-boundary step, not
completion of INT01,
PKG07, or a measured CI saving. Do not narrow required Rust/Canvas CI based
on this profile until dependency closure and affected-case parity are proven.

The first local draft placed a profile on the default worker. Product review
found that an existing Canvas installation with an older environment file
would stop selecting its worker on upgrade, while the optional post-up
preflight would not prevent interruption. That draft was not pushed or
merged. The revised change leaves the base/customer-bundle worker and
production catalog required, and adds a separate no-Canvas overlay as a
preview. The existing bundle/consumer gates retain complete worker-definition
checks and use real Compose `config --hash` to prove default-active,
overlay-disabled, and explicitly re-enabled behavior without starting a
container. The separate preflight now honors shell Canvas-setting overrides;
it does not claim to qualify the no-Canvas product. Existing Canvas-owned
tests and required CI remain. Reviewed
[#1157](https://github.com/ElevenID/marty-ui/pull/1157) passed full PR and
[protected merge-group CI](https://github.com/ElevenID/marty-ui/actions/runs/37703682469)
and merged as `bd7b0ab3c`. A fresh installed no-Canvas journey is still
required; no CI speedup is claimed. The default
switch is deferred until pre-up migration detection, rollback, and an
existing-customer upgrade rehearsal are proven. Before hosted qualification,
232 focused Python/catalog/bundle tests, both real Compose gates, and all 13
Rust `marty-selfhost-bundle` package-contract tests passed. Two Windows
`executable_bundle` tests fail on Docker Compose rendering identically on
the unchanged #1155 worktree; they are not attributed to this candidate.
Linux CI subsequently passed the required packaging and Canvas lanes;
independent review found no blocker after the migration-safe revision.

Next: finish the release artifact/installer closure and clean-install proof
(PKG02/PKG08), then select a single independent verification boundary
(PKG03/PKG06) with its test ledger.

PKG02 source check and the
[v1.1.231 release transaction](https://github.com/ElevenID/marty-ui/releases/download/v1.1.231/release-transaction.json)
confirm a concrete mismatch: `.github/workflows/cd.yml` declares release images under
`ghcr.io/elevenid/marty-ui-oss/{ui,services,migrations}`, while the self-host
bundle override defaults to `ghcr.io/elevenid/marty-ui` and expects
`services`, `db-migrate`, `cloudflared-wrapper`, and `ui-selfhost` image names.
That release also has no downloadable self-host bundle. This is release-asset
evidence, not a fresh anonymous registry/install test.
Repairing the bundle requires a coherent image/digest and separate Python
issuance contract, then release-bound clean-install proof; changing the
namespace string alone would not satisfy it. PKG02 remains the first-use
blocker for this workstream.

PKG02 implementation has merged three bounded, independently reviewed slices.
[#1158](https://github.com/ElevenID/marty-ui/pull/1158) closed all 40
Compose secret-template references and added the required example settings and
internal Flow callback. [#1159](https://github.com/ElevenID/marty-ui/pull/1159)
baked the self-host static source, runtime-config entrypoint and secret loader
into a dedicated UI image target without changing the default public target.
[#1161](https://github.com/ElevenID/marty-ui/pull/1161) added opt-in exact-digest
binding for every rendered bundle service image and a Linux Compose semantic
round-trip test; the unpinned packager mode is unchanged. Each passed full PR
and protected combined-head CI. This still does not publish the bundle's
missing image roles, authenticate a complete release image map, or prove a
fresh installed bundle. The example still needs a qualified issuance digest;
PKG02/PKG08 remain open, and no CI speedup is claimed from these slices.

PKG02 migrations-role candidate (2026-10-08): the stack release and self-host
`db-migrate` both use `services/Dockerfile.migrations`, but source identity did
not prove runtime compatibility. A reviewed draft adds a release-only,
exact-digest disposable probe for the actual migration entrypoint with
PostgreSQL, Redis, and OpenBao on an internal project network. Local execution
against the public v1.1.231 `migrations@sha256:c6098b6291e45c8a7b8de4c52771830767dc7893c7d95a66b0293a32d82757ba`
completed twice under `selfhost-production` and `ENVIRONMENT=production`,
retaining the native Notification head `20260808_0002`, Redis KMS registry,
and non-exportable OpenBao envelope key; owned disposable resources were
removed. The first probe attempt exposed a field-output delimiter defect in
the probe itself, corrected before this passing run. Self-review also found
that production-mode `db-migrate` lacked the native Notification migrator's
dedicated OpenBao token file in both Compose and the Oracle Kubernetes Job;
the draft wires the already-defined dedicated secret in both places. This
establishes compatibility of that released digest with the isolated profile,
not a published self-host image lock, least-privilege OpenBao policy, full
bundle install, or general release qualification. No ordinary PR lane is
removed and no current CI speedup is claimed. [#1167](https://github.com/ElevenID/marty-ui/pull/1167)
passed full PR and protected combined-head validation and merged as
`fc101c3ec`.

PKG02 image-lock preparation candidate (2026-10-08): a separate reviewed
offline generator derives the bundle's exact service-to-image map from the
existing Compose source and one recorded stack release transaction. It binds
the source stack lock and both Compose inputs to Git blobs at the transaction's
claimed SHA, maps shared `services` and `db-migrate` to recorded digests,
requires exact separate `ui-selfhost`/`cloudflared-wrapper` and independent
issuance/infrastructure references, and rejects missing, extra, or reassigned
service roles. This prepares the existing packager's image-lock schema; it
does not build, pull, attest, publish, or qualify an image or installed bundle.
The caller must render the supplied Compose model from the same verified
checkout and separately prove provenance, anonymous pulls, and clean-install
behavior before publication. The `db-migrate` reuse claim is limited to the
exact digest and isolated profile proven by #1167, not future releases. No CI
speedup is claimed from this generator alone.

PKG02 preparation merged in [#1171](https://github.com/ElevenID/marty-ui/pull/1171)
as `e350df8f6` after full PR and protected combined-head CI. The opt-in
official-release preparation lane builds the two
distinct self-host roles by digest only after existing stack qualification,
checks the source-bound image map and Marty attestations, anonymously pulls
each locked image, and uploads only a short-lived workflow artifact explicitly
marked unqualified; the digest-only OCI images remain in GHCR. The opt-in
official-release path itself has not yet run. It does not alter the three-role
stack transaction or ordinary PR gates. Its independent
infrastructure refs still lack a reviewed provenance/licensing policy, and it
neither signs nor qualifies an installable bundle. The next release-only gate
must bind a packaged Linux ZIP and its
embedded lock to the exact transaction, extract into a fresh directory, use
only extracted scripts/configuration with isolated disposable state and
policy-scoped OpenBao tokens, prove migrations/readiness and one representative
product journey, and verify owned cleanup. Archive/lock signing and external
image provenance remain separate publication prerequisites. These are
release-quality obligations, not claimed CI feedback savings.

The [#1161 protected run](https://github.com/ElevenID/marty-ui/actions/runs/37719253068)
measured 7m14s for reusable Rust test compilation, followed serially by
8m15s building the public self-host image, 1m58s for published-worker
preflight, and 6m13s for isolated database contracts in the Canvas lane. The
image build is a candidate for reuse or independent qualification without
dropping packaged-image acceptance; these are one run's stage durations, not
a speedup estimate. The next release slice must reconcile the published OSS
`services`/`migrations` digests with the bundle's `services`/`db-migrate`
roles, publish/attest the missing `ui-selfhost` and `cloudflared-wrapper`
roles, bind the issuance and third-party images, and qualify the exact
digest-pinned extracted bundle before any support claim.
The current stack transaction has exactly three mandatory roles and already
attests `services` and `migrations`; adding self-host-only builds to every
ordinary stack release would increase that release's work. Investigate a
separate self-host release transaction that consumes the qualified stack
digests, builds only the missing self-host-specific roles from the same source
revision, verifies all upstream and third-party references, and emits the
packager's exact service-image lock. This is a candidate architecture, not a
qualified producer or permission to omit installed-artifact acceptance.

The next PKG02/CICD01 diagnostic is the public Rust image build, not a new
cache layer. In #1162's protected Canvas run the image step took 724 seconds,
including 665.2 seconds in the release-binary builder, while the existing
warmer targeted the dependency-cook stage. The builder's exact compiler-cache
hit/miss rate was not reported. Emit only allowlisted numeric `sccache`
counters for dependency cook and release-binary phases, compare comparable
warm/PR builds, and then choose between a narrowly warmed binary profile,
less qualified-product compile surface, or artifact reuse. Keep the same
release build, exact-image acceptance, and public-cache security boundary;
do not infer a speedup from the telemetry patch itself.

The full [#1164 PR run](https://github.com/ElevenID/marty-ui/actions/runs/37727436632)
passed and reported 1,150 dependency-cook hits with zero misses, followed by
zero release-binary hits and 23 misses. Its builder took 414.5 seconds. This
identifies a cache coverage gap, not a causal saving from #1164. The
repository cache was already near the included 10 GB limit, so the next
bounded experiment warms only the same release-binary compiler outputs on
trusted main; PR and merge-group builds stay read-only and the additional
build exports no BuildKit layer cache. Measure the warmer's cost, cache
occupancy/eviction, and the next comparable PR's binary hit count and Canvas
critical path. Revert the warm step if it displaces more useful cache data or
does not improve feedback. No binary, packaged-image check, or release gate is
removed.

For A3/A6, the exact `SELFHOST_BUNDLE.md` input is a shipped asset of
`marty-selfhost-bundle`; the Rust shadow planner now records that package and
its `marty-canvas-acceptance` Cargo consumer for a packager-plus-document
change. Unknown root documents and a missing named asset still select the
entire workspace. This is observational only: PR, merge-group, and release
checks are unchanged. Further Canvas case ownership and run-bound parity are
required before using this plan to skip any PR test.

A6 planner-only PR feedback candidate (2026-10-08): #1162's PR release job
passed, but its unsharded root Python suite reported 5,590 cases and took
9m41s for a shadow-planner-and-document change. The source audit found only
the exact planner script and its test as owner inputs; the complete policy
test file also checks their workflow classification. A follow-up permits a
bounded PR path only when the entire diff consists of those two files and this
coordination document, with at least one planner source and both ordinary
source files present. That path runs both owning test files and the same shadow
report. Mixed/unknown inputs fall back to full release checks; merge groups,
manual/weekly qualification, and releases always execute the complete Python
suite and image/oracle steps. It is not a release test removal, nor a measured
speedup until the guarded path passes hosted CI. Local owning validation passed
158 tests with one Windows symlink skip; independent review and protected CI
passed in #1163. A planner-only follow-up PR is needed to measure the guarded
path itself.

The next planner-only A3 candidate checks that the same exact document remains
declared once in the bundle's source asset manifest before reporting narrow
Rust ownership. An unreadable or symlinked descriptor, invalid JSON, or a
missing/duplicate document declaration falls back to the full workspace.
Other Compose/configuration assets retain the broad fallback because their
non-Cargo runtime and test consumers are not
fully mapped. This only strengthens shadow evidence; it does not change a
required check or establish a Canvas acceptance skip.

A0/A3 Issuance consumer audit (2026-10-08, based on UI main `fc101c3ec`):
Applicant selects `ISSUANCE_NATIVE_SERVICE_URL` in its native startup, passes
that URL into `HttpTemplateProvider`, and GETs
`/v1/application-templates/{id}`. Presentation Policy constructs a credential
status URL from the same native-Issuance setting and GETs it in its control
plane. Native Issuance owns both HTTP routes, and the base Compose profile
points both consumers at `issuance-native:8005`; neither consumer declares
Issuance as a Cargo dependency. The shadow planner records these two observed
edges with source/deployment-marker regressions. The self-host
profile currently points Applicant and Presentation Policy status lookup at
legacy `issuance`, so these observations do not imply native ownership of
their self-host traffic. The planner retains its full-workspace fallback for
every service change. This is not complete non-Cargo closure, permission to
skip tests, or a measured speedup.

A3 additional service-consumer observations (2026-10-08, merged in #1174, based on
UI main `c0b6038d9`): Applicant's configured `FLOW_SERVICE_URL` feeds the
production `HttpFlowProvider`, which signs and POSTs an approved application
to Flow's registered `/v1/flows/webhooks/application-approved` route. Device
Registration's `ORG_GRPC_TARGET` feeds its production Organization membership
client; organization-scoped device routes require an active membership via
`get_member`. The base Compose profile declares Flow at port 8011 and
Applicant on the same network; Applicant's HTTP URL comes from its code default,
not an explicit Compose variable. Device Registration's Compose environment
binds `ORG_GRPC_TARGET` to Organization. Neither consumer declares that
provider as a Cargo dependency.
The shadow planner records these two edges with request, provider, call-site,
and scoped deployment-marker regressions. The Device Registration call is
conditional on organization scope. Applicant already declares Event Stream as
a Cargo dependency, so that publisher is not added as a non-Cargo edge.
Service changes still select every Rust package; no required gate or measured
turnaround changes. Other runtime consumers and non-Cargo inputs remain
unmapped.

Reviewed [UI #1174](https://github.com/ElevenID/marty-ui/pull/1174), exact
head `5ba54fc22`, passed all 29 applicable PR checks and protected
combined-head [run 37762957463](https://github.com/ElevenID/marty-ui/actions/runs/37762957463),
including the live Canvas database suite and aggregate gate, then merged as
`29988a37c` on 2026-10-08 at 10:56:06 UTC. Besides the two A3 shadow edges
above, it selects Release Contract Tests only for the exact current-Canvas-input
helper-only PR path (A6), and makes fresh full-main Canvas startup attestation
fail closed when the local checkout root or HEAD differs from the claimed SHA
(A5). Mixed or unknown inputs, merge groups, and historical qualification
retain their broad checks. The same batch pins the packaged OpenBao bootstrap
helper to a current multi-architecture digest; the named test of a freshly
extracted ZIP passed on Linux. No customer install, external OpenBao server,
official-release qualification, or new CI speedup is claimed.

The protected #1171 and #1172 Canvas timing artifacts recorded
`repository_roster_metadata` at 76.769 and 82.742 seconds; #1174's PR and
combined-head runs recorded 84.476 and 85.306 seconds. Corresponding
`published-canvas` group totals were 450.844, 576.859, 584.493, and 600.889
seconds. These different runs do not establish a causal saving from moving
two value-shape cases into fast unit tests; the real lease-expiry fences remain.
The #1174 queue run is a full-gate outcome, not evidence that the new
helper-only PR selector has been exercised on GitHub.

A4 next roster-expiry overlap candidate (2026-10-08): the remaining published
PostgreSQL roster matrix has six short cases and two natural 30-second lease
expiry cases. Keep the exact eight-case obligation roster, all frozen
assertions, real database clocks, and row-lock wait; give each expiry case its
own required test, pristine cloned database, owned published PostgreSQL
container, and verified cleanup. The existing four-thread worker test runner
can then overlap those independent waits. A local Docker pilot passed the
six-case matrix. The two expiry tests passed concurrently in 39.24 seconds,
with both exact cleanup checks. Focused owner/inventory tests
passed, but the full preflight Python file was not completed locally. The
extra containers could offset savings or add load on hosted runners; require
PR and protected Linux CI with per-case/group timings before claiming a
speedup. No production lease interval, PostgreSQL limit, or required case is
changed.

A3 next shadow observation (2026-10-08): Auth constructs its internal
`credential-verified` callback URL and submits it in the Flow gRPC verification
request. Flow conditionally selects the organization-allowlisted URL, creates a
callback outbox message on verification submission, and its configured worker
POSTs to Auth's registered internal route. The base Compose Auth URL and Flow
destination/secret bindings agree. The planner records Auth-to-Flow as an
observed non-Cargo runtime consumer with source-backed regression markers;
Auth changes still select the full Rust workspace. This observation neither
establishes complete runtime graph closure nor narrows a required CI gate.

A0/A3 next observed edge (2026-10-08 candidate): Auth's Canvas LTI finalize
route uses a bearer-authenticated GET to native Issuance's current experience
session endpoint. The Issuance route is conditionally registered, and the base
Compose Auth service supplies its native-Issuance URL. Record startup, request,
callsite, conditional provider, and scoped deployment markers on the existing
Issuance-to-Auth non-Cargo edge; keep its marker-mutation policy test and
full-workspace fallback. Auth and Issuance have separate local behavior owners
for the request and route. These source observations do not prove the route is
enabled in every deployment, establish complete runtime closure, or authorize
selective CI for service changes.

Next measured compiler-reuse investigation (2026-10-08): #1174's PR and
protected Canvas jobs spent 10m01s and 10m32s respectively in `Compile reusable
Rust test executables`. That step starts with an empty host-visible `rust/target`
and invokes Cargo inside the pinned Bookworm container with `--network none`;
it does not pass the host `RUSTC_WRAPPER` into that container. Both uploaded
host `sccache-stats.json` snapshots have zero cache hits and misses because
they measure the host daemon, not this container compile. They are not evidence
of Bookworm cache effectiveness or a backend outage. Preserve the Bookworm ABI
check, offline dependency closure, exact target/features/toolchain, and the
existing GitHub-cache storage budget while testing any reuse design. Compare
actual container compilation time and target identity before adding a cache
layer or claiming a saving.

Acceptance split triage: the apparently separable Flow and DIDComm renewal
cases in `canvas_published_schema_contract` still call
`PublishedDatabase::start()` and exercise the pinned published schema, real
processes, or durable recovery. Moving those named cases to the ordinary
contracts lane would require its own published-image/database fixture and
run-bound parity proof; test names alone do not make the move safe or remove
the Bookworm compile prerequisite. The existing fast four-way renewal
policy/crypto matrix already uses the production endpoint validator and native
delivery ports; the Compose and Kubernetes cases retain distinct rendered
configuration obligations. No case or lane is removed on this audit.

The Bookworm command also compiles issuance's 70.7-second library-test unit
because the late Canvas TLS timeout oracle invokes its crate-private
`canvas_operation_http::tests::native_socket_case`. A direct move to an
integration test would require widening private transport APIs; that is not a
mere test-file relocation. The production HTTP operation client depends on
Canvas origin policy, streaming content decoding, timeout types, and response
text/Python compatibility modules, with tests referring back to issuance
configuration and credential protocol behavior. Any new reusable transport
crate must move that cohesive dependency closure and preserve the existing
independent socket/oracle checks; do not expose internals just to remove one
test executable or claim a 70.7-second wall saving from one Cargo unit.

Canvas code/migration extraction (INT02-04) follows explicit command/event,
authorization and data-ownership contracts, not an assumed repo split. Track
assignee, issue/PR, dependency state, exact candidate evidence and next action
for each scheduled item. Product, commercial, architecture and release-support
decisions in the product plan remain open pending their accountable owners.

A4 and compile-timing next candidate (2026-10-08): the PostgreSQL
`hinted_retry` matrix receives already-normalized `Option<u64>` values. Its
seven named header shapes collapse to three distinct persisted hints: 0, 60,
and 86,400 seconds. Keep one live lease/failure/persistence/fence case for each
effective value; assign the complete seven-shape policy table and attempt,
jitter, and cap edges to the fast worker unit owner. The independent published
HTTPS/parser matrix stays intact. In the same maintenance batch, record host
fetch/pull/container/verification durations and each offline pinned-Bookworm
Cargo command's elapsed time, target bytes, and exit status in the existing
short-retention build-evidence artifact. The #1174
Canvas compile step took 10m01s, but the current evidence does not isolate
which of its four Cargo commands or host fetch/pull dominates. This batch
must retain the exact compiler, Cargo targets, database assertions, and
published-process coverage; claim a saving only after comparable CI timing.

2026-10-08 A4/A6 outcome: [UI #1176](https://github.com/ElevenID/marty-ui/pull/1176)
and [#1177](https://github.com/ElevenID/marty-ui/pull/1177) passed protected
combined-head CI and merged. The Retry-After database owner retains three
distinct persisted values (0, 60, and 86,400 seconds); the seven header shapes
and policy edges have a fast owner, while the separate HTTPS/parser matrix
remains. The roster owner retains all eight cases, with six fast database cases
and two independently isolated real 30-second expiry cases. Their hosted PR
timings were 4.513 seconds for the six-case matrix and 34.291/33.472 seconds
for the overlapping expiry cases. The published-Canvas group varied from
382.481 seconds in the #1177 PR run to 594.846 seconds in its protected run
and 441.757 seconds in the later combined protected run. This establishes
safe overlap, not a repeatable whole-job saving. #1176's new phase artifact
recorded host fetch/pull and four pinned Bookworm Cargo commands; the
combined protected run measured 14/28 seconds for fetch/pull and 457 seconds
for the compile phase, including 187, 159, 83, and 24 seconds for its four
offline commands. Future reuse must preserve the same toolchain, target,
features, ABI, and coverage.

[UI #1179](https://github.com/ElevenID/marty-ui/pull/1179) passed PR and
protected CI and merged. Its persistent PowerShell rollback harness retains
the original 84 collected cases and adds three isolation/cleanup checks. On
hosted PR runners the module fell from about 84.62 to 3.47 seconds; the
protected run measured about 1.99 seconds. The enclosing release-check step
fell from 9m23s to 8m04s across the compared PR runs, but different runner
conditions prevent attributing all of that step change to this patch.

A5 current-input closure (2026-10-08):
`contracts/canvas-worker-retry-after-current-inputs.json` binds the current
Retry-After reference to ten exact producer/scenario inputs, using the same
normalized-hash and transitive-edge guard as existing Canvas current-input
evidence. Per-input drift tests cover all ten listed inputs; a same-set swap
test covers the REST reference edge. This is evidence about a bounded current
repository-input slice, not authentication of the frozen historical capture
or a reason to relax historical qualification. [UI #1182](https://github.com/ElevenID/marty-ui/pull/1182)
passed 148 targeted local tests, independent review, full PR CI including live
Canvas, and protected combined-head CI, then merged as `ad0cd884f`. It does
not establish complete historical capture closure.

A6 exact-file feedback (2026-10-08): [UI #1180](https://github.com/ElevenID/marty-ui/pull/1180)
added a fail-closed rollback-test-only PR selector, and
[#1181](https://github.com/ElevenID/marty-ui/pull/1181) exercised it with an
independently reviewed one-file test change. Its hosted PR CI passed in 2m09s:
all 88 rollback cases and 219 selected release/policy tests ran, security and
the aggregate gate passed, and unrelated heavy PR lanes skipped. The protected
merge group then ran every required lane and passed. This measures scoped PR
feedback, not a change in full-queue throughput or a repository-wide average.

Next A6 fail-fast candidate (2026-10-08): the required Canvas published-worker
preflights currently run after the public self-host image build, although they
consume the verified Bookworm test executables and their own pinned published
fixtures, not that newly built public image. The #1182 PR and protected runs
spent 316 and 483 seconds respectively building the public image before these
preflights. Move the unchanged two/four-case preflight step immediately after
rendered-base preparation, before the image build, in the same Canvas job.
Keep its exact executable/run-bound evidence, later public-image qualification,
full Canvas database group, and CI gate. A failing preflight could report
before that image-build wait; successful-run wall time is not expected to
improve, and failure frequency is not established. Require hosted PR and
protected proof before marking this candidate merged.

2026-10-08 A6 outcome: [UI #1183](https://github.com/ElevenID/marty-ui/pull/1183)
passed independent review, the full PR matrix, and all protected merge-group
jobs, then merged. The unchanged published-worker preflights now run before
the public self-host image build. In its protected run, the preflights took
about 2m03s and the following image build about 8m03s. This moves possible
preflight failures earlier; it does not shorten a successful Canvas run.

2026-10-08 A0/A3 outcome: [UI #1184](https://github.com/ElevenID/marty-ui/pull/1184)
passed targeted tests, independent review, scoped PR checks, and the full
protected merge group, then merged. Its shadow planner records the
Issuance-to-Auth LTI callback/runtime edge with source-backed guards but does
not use that observation to narrow any required Rust test selection.

A4 JSON-consumer attribution candidate (2026-10-08): the existing published
JSON-consumer probe checks 132 validation/provider cases within one 120-second
deadline, but its timing evidence reports only the aggregate. Record each
checked-in case's elapsed time beside (not inside) the frozen oracle, validate
the complete ordered case inventory before logging, and retain only fixed
case IDs and durations in the short-lived CI timing artifact. Keep the pinned
preparer, frozen equality, real PostgreSQL/process owner, and deadline. The
local live probe passed all 132 cases in about 36 seconds; this is attribution,
not a speedup or authority to remove the historical acceptance owner.

2026-10-08 A4 outcome: [UI #1186](https://github.com/ElevenID/marty-ui/pull/1186)
passed independent review, full PR CI, and all protected merge-group checks,
then merged. Its PR and protected timing artifacts each retained exactly 132
expected, unique, successful JSON-consumer case rows with no unexpected IDs.
The PR case durations summed to 34.738 seconds within a 39.766-second
JSON-consumer segment; the protected case sum was 32.429 seconds. These are
diagnostics from different runs, not a measured pipeline speedup.

Next A1/TST01/INT03 ownership candidate (2026-10-08, reviewed local draft):
`canvas_published_worker_contract` has a distinct published-process and
PostgreSQL obligation from the composition target, but both still share the
`marty-canvas-acceptance` dev-dependency graph. Move the worker target into
`marty-canvas-worker-acceptance` with a narrower declared dependency closure;
keep its test bodies, single-source Issuance fixture support, exact case/tier
inventory, pinned producer mapping, real worker-binary handoff, preflight
digest, and full Canvas gate. The separate composition package retains its
Flow/Gateway/self-host dependencies and Bookworm artifact owner. Update Cargo,
artifact selectors, contract-runner identities, and contracts-lane exclusions
atomically. The bounded `canvas-worker-package-migration.json` ledger records
all 147 unchanged compiled case IDs and the two ignored capture-only IDs;
the existing compiled-list guard checks for missing migrated identities without
another executable launch or new skip authority. Before publishing, prove
old/new discovered test-ID and ignore parity, locked package compilation,
focused policy regressions, and a real
hosted published-process run. This is an ownership and potential worker-only
compile-surface improvement, not a measured CI speedup or permission to narrow
required checks. Canvas adapter runtime extraction and no-Canvas qualification
remain separate INT03/PKG07 work.

Local draft evidence: the pre-split compiled worker target comes from a clean
worktree whose target-source Git blob `50879f423799ad4bd2a53ceb1458468523814f48`
matches this branch's `origin/main` source. Its `--list` and the moved package's
compiled `--list` have the same 147 ordered test IDs; `--ignored --list` has
the same two capture-only IDs. The new worker target's default local run passed
145 and ignored two, but the opt-in PostgreSQL/published-process cases return
early without hosted configuration. The new worker and unchanged composition
targets passed package-scoped locked checks, and the exact three-package
Canvas CI Cargo selection passed a locked offline `--no-run` with both
acceptance targets, Issuance behavior/OAuth targets, and all three libraries.
Its worker executable also lists the same 147 cases and two ignored captures.
Focused runner/tier/policy tests and independent review passed. On Linux,
the worker-only Cargo dependency closure has 620 unique package versions
versus 693 for the old combined acceptance package; the full CI job still
builds both packages, so this is not a measured whole-job saving. Full hosted
Canvas execution and protected validation remain required before merge.

## A1 dedicated self-host acceptance owner (2026-10-09, merged)

The public-image loader's two root cases and eight embedded support cases
have one deployment/packaging obligation. [UI #1202](https://github.com/ElevenID/marty-ui/pull/1202)
moved their unchanged assertions and exact ten libtest IDs into
`marty-selfhost-acceptance`, while composition retains its 139 other discovered
cases on the final protected #1202 head (135 routine parallel passes, four
intentionally filtered in that invocation). It moves the two self-host
support files together, reuses the original
single-source bundle, renewal, database, and bounded-command fixtures, and
shares only the generic cleanup-result combiner with composition. The
composition manifest can then drop three direct development edges:
`marty-selfhost-bundle`, `serde_yaml`, and `zip` (41 to 38); this is a declared
edge change, not an independently timed compile saving. The Canvas CI job
still builds the public image and packager exactly once, then executes the
dedicated self-host target alongside composition and worker. An exact ten-ID
runner guard, artifact verifier, timing allowlist, target status/log cleanup,
and contracts-lane exclusion retain the mandatory owner. Local locked Rust
1.95 compilation and discovered-ID checks passed for both self-host and
composition; strict package Clippy passed. The full synthetic runner policy
suite passed 221 cases with one skip after a caught preflight-closure defect
was corrected; focused selector and ownership policy tests passed. Two
independent reviews found no P1-P3 regression. The first hosted PR run exposed
26 stale release-policy expectations and one current-input pin; these were
corrected without weakening the three-target failure guard. The correction's
281 related tests passed locally, and the exact-head
[PR run 37890433024](https://github.com/ElevenID/marty-ui/actions/runs/37890433024)
passed all required checks in 32m12s. The final
[protected run 37893223551](https://github.com/ElevenID/marty-ui/actions/runs/37893223551)
passed the full combined-head plan in 28m21s, including 10/10 self-host and
111 worker cases; the self-host target took 197.9s while the worker target
took 386.7s concurrently. #1202 merged as `a9845070e`; one required review
was restored immediately. The split changes no skip or release qualification,
and these runs do not establish an overall CI wall-time saving.

## A0/A3 Gateway DID-web runtime consumers (2026-10-09 merged)

Gateway's root and organization-slug DID-web routes are consumed by two Rust
services without Cargo dependencies on Gateway. Trust Profile defaults its
issuer-key resolver to `http://gateway:8000` and the base Compose profile
binds that URL. Issuance's DIDComm recipient resolver uses the same Gateway
URL when its optional internal DID-web setting is configured; base Compose
provides that default. The change records both source-, route-contract-,
and scoped-Compose-backed shadow edges. Mutation-checked tests require the
consumer binding and call, Gateway route dispatch, published paths, and
deployment wiring. [UI #1204](https://github.com/ElevenID/marty-ui/pull/1204)
passed protected run `37898462662` and merged as `78039a29d`; the normal
review protection was restored. Gateway source changes still select the full
Rust workspace, including both consumers; this does not establish complete
non-Cargo input closure, alter any check, or claim a speedup.

## A0/A3 Auth-to-Gateway session gRPC edge (2026-10-09 merged)

The shadow planner already records Gateway's public Auth HTTP proxy, but
Gateway also connects to Auth gRPC for session validation before accepting
identity claims. #1193 enriched that existing producer-to-consumer edge with
the configured/deployed target, Gateway channel and request, nonempty user-ID
guard, and Auth server implementation/registration. A source-backed regression
checks each marker and rejects its removal. It added no second edge, changed
no runtime behavior or CI selection, and does not
prove the complete non-Cargo graph; service changes still select full Rust
validation. Its value is accurate impact evidence for later fail-closed
planning, not a measured CI speedup.
The source-backed witness and mutation regression merged in
[#1193](https://github.com/ElevenID/marty-ui/pull/1193).

## A0/A3 Flow-to-Auth credential-login gRPC witness (2026-10-09 merged)

Before #1195, the Flow-to-Auth shadow edge recorded only Auth's target and
startup connection. Auth also constructs a Flow gRPC client, supplies it to credential
login, and calls `StartVerification` when the login route starts a request.
Flow authorizes that method and registers its gRPC server; Compose deploys the
target. #1195 added source-backed witnesses for that existing edge, with a
regression that detects removal of each binding, request, callsite, provider,
registration, or deployment marker. It does not add a second edge or change
runtime behavior, CI selection, required gates, or the service-wide fail-closed
fallback. The wider non-Cargo input graph remains unmapped; no speedup is
claimed. This source-backed witness and its mutation regression landed in
[#1195](https://github.com/ElevenID/marty-ui/pull/1195); it is not a pending
implementation slice.

## A0/A3 Organization-to-Auth JIT provisioning gRPC witness (2026-10-09 merged)

Before #1195, the Organization-to-Auth shadow edge recorded only Auth's
configured target and startup connection. Auth's JIT provisioner also uses an Organization
gRPC client to add the authenticated principal to the default organization,
read membership context, and optionally read the organization name before
creating a session. #1195 recorded those request, callsite, token, server,
and deployment witnesses on that one existing edge. A source-scoped mutation
regression guards the chain while the planner remains observational and
service changes still select the full Rust workspace. This does not prove
cross-service wire compatibility or the complete non-Cargo graph, change any
CI gate or skip, or establish a speedup.
The witness and its source-scoped mutation regression landed in
[#1195](https://github.com/ElevenID/marty-ui/pull/1195), not a separate PR.

## A5 REST fresh-run provenance boundary (2026-10-08 candidate)

[UI #1186](https://github.com/ElevenID/marty-ui/pull/1186) merged the
132-case JSON-consumer timing labels without changing its frozen corpus or
qualification. [UI #1187](https://github.com/ElevenID/marty-ui/pull/1187)
merged as `4b15de493` after protected validation; it moves the unchanged
published worker target into `marty-canvas-worker-acceptance`. Its protected
Canvas job took 31m58s (19:10:49–19:42:47 UTC), including 622s host Rust
compile, 122s published-worker preflight, 484s public self-host image build,
and 596s isolated database suites. These are observations from one run, not an
attributed speed improvement. Core
[#354](https://github.com/ElevenID/marty-core/pull/354) merged as `fe8de9eec`
with source-backed Verification JWK fixture selection; no Core CI speedup is
claimed from that ownership guard. Neither change closes historical REST
capture inputs.

The four-observation `canvas-worker-rest-oracle.json` contains installed worker
and route source hashes, not hashes of its Python capture scripts and scenario
inputs. The ten-file `canvas-worker-rest-current-inputs.json` guards the
*current checkout*, including the mounted preparer and worker trust hook, and
explicitly disclaims original-capture provenance.
The unchanged REST producer is imported by many other worker producers and its
bytes are pinned in the body-timeout and lease-expiry capture maps, so changing
it merely to decorate the REST oracle would disturb independent references.

Merged [UI #1189](https://github.com/ElevenID/marty-ui/pull/1189) emits
`canvas-rest-fresh-run.json` only after the
published REST JSON equals all four frozen observations and the owned database
and probe have closed. The record is restricted to a scheduled or manually
dispatched full run on checked-out `main`; it binds run/attempt/SHA/job, exact
current input hashes, script graph, corpus, pinned image fixture, migration
revision, and test executable. Upload runs only after preceding Canvas steps
succeed, with fourteen-day retention and a missing-file failure; external use
also requires the final job and workflow to succeed. A fresh
matching capture proves reproducibility under those present inputs, **not**
the inputs used for the original historical capture, permission to reuse
qualification, or authority to skip any live case. All existing process,
PostgreSQL, historical replay, and release gates remain in force. The original
147 package-migrated worker identities remain required; three additive Rust
tests check input drift and evidence-constructor refusal. The first hosted
full-main record has now been checked.
The manual [run 37842597081](https://github.com/ElevenID/marty-ui/actions/runs/37842597081)
completed successfully on merge commit `916c75aed`. Both 14-day artifacts,
`canvas-rest-fresh-run-37842597081-1` and
`canvas-startup-fresh-run-37842597081-1`, were downloaded and checked: each
binds repository, `main`, workflow dispatch, run 37842597081 attempt 1, the
same SHA, and the Canvas job; each reports published comparison and owned
cleanup passed with pinned issuance/PostgreSQL images and migration revision.
This verifies fresh reproducibility on that commit, not original historical
capture or release qualification. A separate #1188 release-lock change
advanced `main` while the run executed, so it cannot qualify the newer tip for
an exact-current-main release claim.

## A5 JSON-depth current-input guard (2026-10-08 reviewed candidate)

The pinned JSON-depth published-producer diagnostic remains a routine Canvas
case; its preceding protected timing recorded about 125 seconds for the whole
probe, including migration, seed, and producer execution. The two native
provider/credential-route depth cases are separate guarantees. The new
`canvas-json-depth-current-inputs.json` records twelve current-checkout inputs:
the Rust probe constructor, mounted preparer/depth runner and static local
helpers, depth and shared scenario data, pinned image/PostgreSQL fixture, and
test-only recovery overlay. A release-collected guard checks their normalized
bytes, selector and mount structure, fixed image identities, static imports,
and transitive JSON references. After the hosted release-policy test exposed
a missing helper-consumer allowlist entry, the corrected classification and
image-context exclusions passed 175 focused policy/input tests; the independent
reviewer found no P1–P3 issue in the fix. This inventory
does **not** prove original capture provenance, downstream image contents, or
complete host/environment closure. It changes no tier, skip, gate, or release
rule and establishes no speedup. Historical depth selection remains required
until a stronger exact-probe closure invariant and change-triggered full
qualification are implemented and reviewed; protected merge groups retain it.

## A6 opt-in worker-only published runner (2026-10-08, merged UI #1191)

The worker acceptance target is now a separate Cargo package, but routine CI
still resolves composition and self-host artifacts and builds the public image
before its full Canvas group.
[UI #1191](https://github.com/ElevenID/marty-ui/pull/1191) added opt-in
`worker-preflights` and `worker-canvas` runner modes plus worker-only artifact
verification; no workflow selects them, and the default full runner, required
checks, and release gates are unchanged. The opt-in path keeps the same 147
compiled worker identities, four exact pinned-process preflights, run-bound
executable-digest proof before any preflight skip, routine/full historical-case
policy, real worker binary, isolated PostgreSQL, timing, and owned cleanup.
Synthetic regression tests passed (211 passed, one skipped, one existing
Windows signal test deselected after it passed alone); focused mode tests and
static checks also passed. At this stage, the local artifacts included only a
Windows test executable, not the Linux test and real worker binaries required
by the Docker-backed runner; the hosted follow-up below supplies that proof.

The next requirement was hosted Linux proof with matching Cargo JSON artifacts,
pinned images, all selected case IDs, preflight digest/cleanup and timing
evidence. Only after that proof could a separate fail-closed worker-test-only PR
selector be considered, with protected full qualification preserved.

A6 diagnostic follow-up ([UI #1194](https://github.com/ElevenID/marty-ui/pull/1194),
merged 2026-10-09): a maintainer adds the
`ci-worker-diagnostic` label **before a subsequent PR-head push**; that
`synchronize` event adds a third, worker-only Rust matrix lane. Labeling an
already-open PR alone does not start this workflow, and unrelated label
changes must not restart full CI. The diagnostic lane runs alongside the
existing Canvas and contracts lanes and aggregate gate. Its
Bookworm compile selects only the worker acceptance target and real sync-worker
binary; worker-only artifact verification precedes the unchanged pinned-process
preflights and worker suite. A merge group never selects the diagnostic lane
and retains the full two-lane plan. Three exact worker test-source files are
excluded from the four root-Dockerignore release builders; the two dedicated
Rust-image Dockerignores already exclude their test directories. A six-context
guard requires every exclusion, the exact Cargo target/support inventory, and
continued production-source inclusion. This is preparation for hosted
measurement, not a measured speedup or authority to skip any ordinary job.
The classifier's existing `--emit-verified-leaves` proof does not execute this
new worker guard or emit worker paths; extending that proof belongs to the
separate selective-validation pilot, after live diagnostic evidence.
The first labeled hosted PR had to prove live case counts, run-bound preflight
digest, pinned image/process/database and cleanup evidence. A later distinct
test-source-only pilot is still required before claiming selective PR CI; the
workspace-wide Clippy and release-policy jobs remain possible bottlenecks.
The exact initial PR head was independently reviewed after rebase onto the
merged worker-only runner; it was not live worker-only evidence.
The first labeled [PR run 37861477220](https://github.com/ElevenID/marty-ui/actions/runs/37861477220)
selected all three Rust lanes. Its worker-only job passed in 13m36s (5m56s
compile, 6m51s database/process step): both pinned-process preflights passed,
the routine worker run reported 110 passed / 2 ignored with the retained
147-case migration inventory, and every worker timing-artifact row was `ok`.
This is feasibility evidence, not a complete PR run or comparable CI speedup.
The public-protocol and contracts-vector jobs rejected the new matrix syntax
using a stale exact-string owner guard; release pytest also found structural
assertions written for only one compile/preflight lane. The reviewed follow-up
requires the active PR-only matrix and normal fallback and updates the stale
tests without relaxing full Canvas obligations. A corrected hosted run and
full-Canvas comparison were pending at that point.

The corrected [PR run 37863529515](https://github.com/ElevenID/marty-ui/actions/runs/37863529515)
passed every check and the aggregate gate. Its diagnostic worker lane took
13m20s (5m46s compile, 6m44s database/process step); both pinned preflights
passed, 110 worker cases passed with two capture-only ignores, and all 261
timing rows were `ok`. In the **same run**, the unchanged full Canvas lane
took 25m41s, including 145 composition passes and the same 110 worker passes
with two ignores; contracts took 16m33s. This establishes a 12m21s shorter
worker lane under those conditions, not a whole-PR speedup: both lanes still
ran. The protected [merge-group run 37865923534](https://github.com/ElevenID/marty-ui/actions/runs/37865923534)
passed the original full Canvas/contracts plan with no diagnostic worker lane,
and #1194 merged as `16d0072c7`. The temporary self-merge approval exception
was restored to one required approval immediately after merge. At that point,
the separate exact-test-source selector and its one-file pilot were unmerged.

## A6 exact worker-test-source PR selector (2026-10-09, merged)

The next bounded draft considers only the three tracked Rust files owned by
`canvas_published_worker_contract`: its target and two explicit support
modules. Before a pull request can select `rust_matrix=["worker"]`, the
classifier requires regular non-symlink checkout files with regular Git index
modes, executes the six-context Docker-copy guard, and compares the
NUL-delimited proved file inventory against every changed path. A mixed,
missing, renamed, deleted, unproved, or unknown path retains the full
Canvas/contracts Rust matrix. Merge groups always retain both original lanes.
The worker-only plan still requires the compiled published worker target,
pinned-process preflights, worker suite, Rust lint and supply-chain checks,
root release-policy pytest, public-protocol checks, and the aggregate gate;
only unrelated runtime/image qualification is bypassed for these test-only
sources. The gate accepts the exact worker tuple only on pull requests and
rejects a skipped selected job. [UI #1195](https://github.com/ElevenID/marty-ui/pull/1195)
merged the independently reviewed selector as `f4926bb4d` after full PR and
protected merge-group validation; the selector PR itself retained the full
Canvas/contracts matrix because it changed workflow and planner code.

The distinct one-file [pilot #1196](https://github.com/ElevenID/marty-ui/pull/1196)
changed only `canvas_startup_attestation.rs` to test rejection of a nested
checkout root before evidence or artifact creation. Its
[PR run 37874366360](https://github.com/ElevenID/marty-ui/actions/runs/37874366360)
selected only the worker Rust lane, kept release/lint/security/public-protocol
and aggregate checks, and finished green in 13m41s from run creation to gate.
The worker job took 13m21s: 5m49s compile, 6m47s real database/process step,
111 passes, two intentional capture-only ignores, both pinned preflights, and
261 timing rows all `ok`. The preceding #1195 full-PR run took 36m, an
observed 22m19s difference that includes different diffs and runner queueing,
not an attributable end-to-end percentage. The same-run #1194 lane comparison
above is the cleaner 12m21s worker-versus-full-Canvas evidence. #1196 passed
the original full Canvas/contracts protected merge-group plan and merged as
`fb93db737`; one required approval was restored immediately after merge.
This establishes faster feedback for the exact three-file class, not for
mixed/shared/runtime edits or final merge qualification.

## A6 worker roster support source ownership (2026-10-09, merged)

The reviewed change moves only
`canvas_worker_roster_metadata.rs` byte-for-byte from issuance's shared test
support into the worker acceptance package, which is its sole Rust source
consumer. It updates that target's explicit path and admits this one fourth
source file to the exact worker-only PR selector. The source-consumer and six
Docker-context proof remain fail-closed; neighboring shared support files
still select the full Rust matrix. The move preserves the six fast database
roster and two real expiry cases, all 147 migration-ledger worker IDs, and two
ignored historical captures. Local Rust 1.95 locked compilation and 237
focused policy tests passed; independent review found no P1-P3 issue.
[UI #1199](https://github.com/ElevenID/marty-ui/pull/1199) passed full
[PR run 37882465625](https://github.com/ElevenID/marty-ui/actions/runs/37882465625)
and protected [merge-group run 37884784355](https://github.com/ElevenID/marty-ui/actions/runs/37884784355),
then merged as `df93dc3f2`. The separate one-file
[pilot #1201](https://github.com/ElevenID/marty-ui/pull/1201) changed only
that fourth source and selected the worker-only PR lane. Its
[PR run 37887354111](https://github.com/ElevenID/marty-ui/actions/runs/37887354111)
passed 111 worker cases and reached the gate in 13m40s; its
[protected run 37888622587](https://github.com/ElevenID/marty-ui/actions/runs/37888622587)
kept full Canvas/contracts validation and reached the gate in 34m30s. These
are different execution plans, not an attributable end-to-end percentage.
#1201 merged as `05f6dd972`; one required approval was restored after merge.

## A6 self-host-only PR selector feasibility (2026-10-09, deferred)

The new self-host acceptance target has three tracked test-owned files: its
root `selfhost_public_image_contract.rs` and the `selfhost_packaged_runtime.rs`
and `selfhost_runtime_sidecar.rs` support modules. The root release-policy
suite also reads them, and the six Rust-copying Docker contexts currently
exclude these test sources. Shared fixtures, package manifests, scripts, and
runtime/image sources are not test-only inputs. A direct exact-file selector
is not safe yet: the CI artifact verifier has only full and worker-only modes,
the runner requires composition and worker artifacts before it runs the ten
self-host cases, and public-image/packager preparation exists only in the full
Canvas job. The aggregate gate has no self-host-only result tuple. A future
additive diagnostic lane would need to build the same image and packager,
verify the exact compiled target, execute all ten cases with owned database
cleanup, and retain timing/evidence. Only after hosted coverage and wall-time
comparison should an exact-file PR selector be considered; protected merge
groups must retain full Canvas/contracts qualification. No speedup is claimed
from this unimplemented option.

## A1 Flow admission/consumer acceptance owner (2026-10-09, merged)

A dedicated `marty-flow-acceptance` target now owns the six outer Flow/DIDComm
admission cases and three nested public-startup cases formerly discovered by
the Canvas composition target. The Bookworm compile phase, artifact verifier,
and protected Canvas runner include both executables; the contracts lane
excludes both. The runner checks the exact nine Flow IDs, duplicate IDs across
targets, and all four target statuses before the gate can pass. Shared Redis,
Gateway, and published-database fixtures retain one implementation and owned
cleanup, while their five fixture unit tests stay Canvas-owned. The eight new
test-only files are excluded from all six Rust-copying Docker contexts;
a fail-closed guard preserves runtime inputs and catches new consumers.

One local Rust 1.95 locked invocation linked both targets. On Windows the
Canvas list is 127 and Flow list nine, with no duplicate IDs; the three
unchanged Unix/Linux-only Canvas cases make the expected protected Linux
inventory 130 + 9 = the original 139. The local Flow harness ran all nine
cases successfully, with six opt-in database cases returning early outside
the Linux gate. The detailed source and platform-count mapping is in
`docs/rust-migrations/flow-acceptance-test-owner.md`. Canvas no longer has a
direct `marty-flow` dev dependency, but `cargo tree` still reaches Flow via
Gateway and deployment-profile, so this does **not** establish a compile
surface reduction. Independent review found no P1-P3 issue after fixes.
The first hosted PR Canvas job (`37905105137`, job `113737047183`) passed:
Linux discovered 130 Canvas cases (126 parallel passes and four filtered)
plus nine Flow cases (all passed), preserving the 139-case total. Flow ran
in 33.9 seconds while the other three targets ran concurrently. That job
took 30m07s, including 10m09s compilation, 8m06s public-image build, and
8m06s database suites. The earlier protected #1202 job took 26m59s with
8m10s, 7m33s, and 7m14s for those respective stages; different heads and
cache conditions make this a diagnostic comparison, not an attributable
speedup. The same PR's Release Contract job exposed stale policy guards,
which were corrected separately. The corrected final-head PR and protected
merge-group checks passed, and [#1205](https://github.com/ElevenID/marty-ui/pull/1205)
merged as `859030f8e`. No end-to-end CI speedup is claimed from this split.

## A6 exact Flow-test-source PR selector (2026-10-09, merged)

The next bounded selector accepts only a nonempty subset of the eight tracked
`marty-flow-acceptance` test-owned files. It requires the existing regular-Git-
mode, sole-consumer, and six-Docker-context proof; mixed or uncertain changes
retain the full Canvas/contracts matrix. The Flow-only pull-request lane
compiles the exact Flow test target and real Issuance/Flow binaries in the
pinned Bookworm builder, verifies those artifacts, and requires the same nine
case IDs and owned database/Redis fixtures as the full Canvas lane. Rust lint,
supply-chain, release-policy, public-protocol, and aggregate checks remain;
merge groups still run the full matrix. Independent review found no P1-P3
issue and 195 focused local tests passed. The corrected full PR run
[37917235263](https://github.com/ElevenID/marty-ui/actions/runs/37917235263)
and protected run
[37920041018](https://github.com/ElevenID/marty-ui/actions/runs/37920041018)
passed; [#1206](https://github.com/ElevenID/marty-ui/pull/1206) merged as
`f2d011211`. The one-file [#1207](https://github.com/ElevenID/marty-ui/pull/1207)
pilot selected only the Flow Rust lane on PR, passed all nine Flow cases and
the retained release/lint/supply-chain/public-protocol/aggregate checks in
[run 37923064960](https://github.com/ElevenID/marty-ui/actions/runs/37923064960),
then passed the full protected
[run 37924634057](https://github.com/ElevenID/marty-ui/actions/runs/37924634057)
and merged as `a2970c70f`. The PR reached its gate in 11m01s; the Flow job
took 10m35s, including 9m24s compiling the test and real binaries and 23s in
the database step. This proves scoped feedback for the exact test-only class,
not a general CI speedup or a controlled comparison against a same-head full
matrix.

## A0/A3 Auth-to-Applicant profile consumer (2026-10-09, merged)

The existing shadow planner records an Applicant-to-Auth non-Cargo edge but
previously cited only Auth's service URL and startup reference. The new
source-backed witness covers Auth's default `http://applicant:8006`, OIDC JIT
and Canvas provisioner registration/calls, the PATCH request with tenant
identity and response-account check, Applicant's route/handler/server, and
the base Compose default/provider-port binding. Scoped marker mutations test
each owner; the planner still selects the full workspace for service changes.
There is no new gate skip, runtime behavior change, or claimed speedup.
Independent review found no P1-P3 issue; 41 planner tests passed with one
skip and 333 subtests. The first protected run
[37928228236](https://github.com/ElevenID/marty-ui/actions/runs/37928228236)
failed one unchanged synthetic Compose renderer assertion: under concurrent
load, its 400 ms oversized-output probe timed out before Python wrote the
sentinel. The reviewed correction retained the 400 ms hang probe, 262,144-byte
output limit, real renderer bound, exact error assertion, and owned cleanup;
only the synthetic oversized-output probe now has a bounded five-second
startup allowance. [The corrected PR run](https://github.com/ElevenID/marty-ui/actions/runs/37931967220)
and [full protected run](https://github.com/ElevenID/marty-ui/actions/runs/37935430868)
both passed the named renderer case and all required checks. [#1208](https://github.com/ElevenID/marty-ui/pull/1208)
merged as `7324bf0ed`; the one-reviewer rule was restored. The original
planner/document-only PR reached its gate in 2m07s, but the corrective
test-source change required the full PR Rust matrix; no new general CI
speedup is attributed to #1208.

The protected #1208 Canvas job took 22m11s. Its compile, public-image, and
parallel database steps took 7m24s, 5m03s, and 6m09s respectively; inside the
last step the worker target was longest at 5m25s. These are one run's
diagnostics, not before/after speedup evidence or permission to shorten real
lease/deadline tests. The host `sccache` snapshot had zero hits because the
hermetic Bookworm compiler does not use that host wrapper; it is not a cache
hit-rate measurement for the container compile.

## A4/A6 image-free renderer bounds proof (2026-10-09, merged)

[#1209](https://github.com/ElevenID/marty-ui/pull/1209) moved the unchanged
synthetic renderer deadline/output-limit proof from two late composition cases
into one named test in the existing Canvas executable. The early image-free
config-proof roster runs it before image/database setup; exact same-run
executable digest, run identity, tier, named-case success, and completion marker
authorize its later skip. Missing or stale evidence falls back to the full
composition suite and requires the marker there. Both original cases still
require explicit Python and retain their real rendered-configuration and
native-process assertions. Independent review found no P1-P3 issue; the
protected [merge-group run](https://github.com/ElevenID/marty-ui/actions/runs/37946137334)
passed and #1209 merged as `7f52ade71` at 15:14:33 UTC. The exact-head early
proof passed in four seconds; the full PR Canvas job took 31m28s versus 22m11s
in the preceding protected sample. Compilation, image build, and all main
acceptance targets were slower together, so no attributable end-to-end saving
is claimed. Main's one-reviewer protection was restored and verified.

## A0/A3 Gateway base-Compose upstream parity (2026-10-09, merged)

Gateway's published `/v1/verify` route and `SERVICE_URLS` table select the
Verification upstream. Kubernetes supplies `http://verification:8012`, but
base Compose omitted `VERIFICATION_SERVICE_URL`, leaving the gateway container
with the `http://localhost:8012` development default. Since Verification runs
as a separate Compose service, that default does not target it. [#1210](https://github.com/ElevenID/marty-ui/pull/1210)
added the missing base-Compose binding and an independent exact-value
regression for all 15 configured Gateway upstream URLs, scoped to the Gateway
environment and requiring each target service stanza. The native-runtime
fixture's closed environment set followed the new binding. Local planner,
self-host, and supported-Compose checks passed (202 tests, two skips, 348
subtests); independent review found no P1-P3 issue. Full exact-head
[PR run](https://github.com/ElevenID/marty-ui/actions/runs/37951482695) and
[protected run](https://github.com/ElevenID/marty-ui/actions/runs/37955004959)
passed, and #1210 merged as `953cf5294` at 16:18:10 UTC. Main's one-reviewer
rule was restored and verified. The PR and protected Canvas jobs took 27m06s
and 24m28s; the latter included 443 seconds of container compilation and 459
seconds in published database contracts. This repaired deployment wiring and
closed one A0/A3 input gap; it did not change check selection or establish a
CI speedup.

## A0/A3 Gateway Kubernetes upstream parity (2026-10-09, merged)

The oracle Kubernetes Gateway imports `marty-config` through `envFrom`, but
that ConfigMap omitted `SIGNING_KEYS_SERVICE_URL`. Gateway's published signing
route would inherit its `http://localhost:8017` development default, which
cannot reach the separate Signing Keys Service on port 8017 when its optional
`07b-signing-keys.yaml` overlay is applied. [#1212](https://github.com/ElevenID/marty-ui/pull/1212)
added the missing binding and a parsed-YAML guard for the exact 15 Gateway
upstream targets, the actual Gateway container's ConfigMap import and explicit
environment overrides, and the optional Signing Keys Service endpoint. The
expected addresses remain independent of production configuration. The frozen
historical ConfigMap hash reconstruction removes exactly the new binding.
Focused Python checks passed (110 tests, one skip, 363 subtests); the reviewer
found no remaining P1-P3 issue. Full exact-head [PR run](https://github.com/ElevenID/marty-ui/actions/runs/37959076710)
and combined-head [protected run](https://github.com/ElevenID/marty-ui/actions/runs/37963117844)
passed. The PR merged as `f50cc7c56` at 17:32:34 UTC, and main's one-reviewer
rule was restored and verified. The PR and protected Canvas jobs took 31m06s
and 30m49s; these are not comparable evidence of an attributable saving.
This deployment-correctness slice did not narrow the shadow planner's
service-change fallback or remove any check.

## A6 published Canvas worker reference reliability (2026-10-09, merged)

Two pinned worker references missed their existing 10-second SIGINT shutdown
bound under parallel Canvas load on different exact-main runs. [#1211](https://github.com/ElevenID/marty-ui/pull/1211)
kept both required references and their original bounds, but ran them serially
before excluding them from the parallel worker target. The frozen oracles and
native preflights remain; the exact case roster and timing-phase guards were
updated. Its full [protected run](https://github.com/ElevenID/marty-ui/actions/runs/37962807792)
passed and it merged as `1afa80a5e` at 17:28:48 UTC. Its protected Canvas job
took 30m20s. This addresses observed flakiness; it does not establish a CI
speedup or authorize weaker timing semantics.

## A6 Kubernetes/consumer policy test-source ownership (2026-10-09, merged)

Six exact root Python test sources covering issuance consumer bindings,
Kubernetes service coverage and signed release selection, token-secret shell
doubles, supported passport Kubernetes, and consumer routing are collected by
the existing Release Contract Tests root pytest step (122 collected and 122
passed locally). Repository references show no second named workflow/script
invocation; the service-image Dockerfile guard rejects root test copies, while
UI and browser images build from their separate `ui` and `tests` contexts.
These test files are not runtime inputs. Route PRs changing only these exact
sources to their existing release-test owner; keep production scripts,
manifests, unknown siblings, and mixed changes on the conservative classifier
path. Synthetic classifier tests require the exact result tuple, a broad
unknown-sibling fallback, mixed source selection, and full merge-group
selection. This does not remove a test or narrow any deployed-source check.
[#1213](https://github.com/ElevenID/marty-ui/pull/1213) passed exact-head and
[protected CI](https://github.com/ElevenID/marty-ui/actions/runs/37970884691),
then merged as `5c6844d44`. The protected Canvas step spent 602 seconds on
reusable Rust test compilation, 369 seconds on the public self-host image,
and 648 seconds in its database group. Against #1212's 618/375/647 seconds,
these are different combined heads and runner conditions, not an attributable
speedup or regression.

The first actual exact-source [PR #1214](https://github.com/ElevenID/marty-ui/pull/1214)
ran all eleven `test_passport_supported_consumer_routing.py` cases and the
release owner's full root pytest; its [PR CI run](https://github.com/ElevenID/marty-ui/actions/runs/37974689079)
reached the aggregate gate in 9m17s with 6,116 passed and 19 skipped root
tests. CodeQL, open-source policy, and public protocol checks also passed.
Its full [protected merge-group run](https://github.com/ElevenID/marty-ui/actions/runs/37975973978)
passed every required check, and #1214 merged as `b44c482dc`. This proves
scoped feedback for this exact test-only path, not a general pipeline saving.

The reviewed [#1216](https://github.com/ElevenID/marty-ui/pull/1216)
selector runs all six named Kubernetes/consumer test sources plus
workflow-policy tests for a nonempty PR changing only those regular files.
It skips the unchanged frozen Credentials mirror replay and OCI archive proof
in that PR path; unknown, mixed, deleted, symlinked, and protected merge-group
inputs retain the complete release job. The exact proposed command passed
268 local cases in 93 seconds on the #1214 main base, including all five new
passport-consumer cases. The standalone workflow-policy suite passed all 141
cases. A pre-rebase 263-case run exposed and then cleared a stale policy
reference count; it is not the final validation result. Its full
[PR run](https://github.com/ElevenID/marty-ui/actions/runs/37980016444) and
[protected combined-head run](https://github.com/ElevenID/marty-ui/actions/runs/37983789543)
passed, and #1216 merged as `a6e28dbc9` with the one-reviewer rule restored.

The first source-only [pilot #1217](https://github.com/ElevenID/marty-ui/pull/1217)
strengthens the existing production Kubernetes resource guard: catalog-owned
Deployments and Services must be in `marty-prod`, duplicate production
identities fail, and an unrelated namespace decoy remains valid. Independent
review found no P1-P3 issue. Its exact-head
[PR run](https://github.com/ElevenID/marty-ui/actions/runs/37986999423)
selected Release Contract Tests plus Public Protocol Contract, skipped the
unrelated Rust/image/browser/UI matrices, executed all 273 selected cases
(273 passed in 1m48s), and reached the CI Gate 4m08s after run creation. The
release job took 2m14s. This observed gate is 5m09s shorter than #1214's
9m17s source-only gate, but the heads, runners, and changes differ; it is a
scoped feedback observation, not a controlled attribution or whole-pipeline
average. Full protected merge-group validation was still pending at that
checkpoint; it later passed and #1217 merged.

The first #1217 protected
[run 37987570280](https://github.com/ElevenID/marty-ui/actions/runs/37987570280)
failed when Docker Hub returned HTTP 429 to BuildKit's HEAD request for the
unchanged digest-pinned Debian Bookworm base during the public self-host image
build. All other job results were successful; the required CI Gate failed and
GitHub removed the entry from the merge queue. The reviewed source-only head
was requeued unchanged for a second complete protected run. That
[run 37990150422](https://github.com/ElevenID/marty-ui/actions/runs/37990150422)
also failed: logs show Docker Hub's unauthenticated pull limit on the
unchanged PostgreSQL service, cargo-deny action, and several image builds;
Nginx integration also failed during its Docker build, though its helper did
not expose the underlying registry error. The required gate failed and GitHub
removed the entry. This is an external registry failure, not a test regression or
permission to bypass the image proof; #1217 remained open at that checkpoint.

The initial [mirror PR #1218](https://github.com/ElevenID/marty-ui/pull/1218)
preserves canonical digest-pinned service references and configures a Docker
daemon/BuildKit pull-through cache for later jobs. Independent review caught
and corrected a first-draft direct-mirror service reference that would have
lost fallback on cache misses. All 223 targeted local policy tests passed.
Its first full hosted PR run `37991390398` demonstrates that this is **not yet
a complete remedy**: the pre-step PostgreSQL service still hit Hub 429, the
Passport Fence PostgreSQL tests hit 429 after the daemon mirror step, and the
Docker-based cargo-deny action hit 429 for its pinned Rust base. The separate
organization Workflow Quality job also failed pulling its pinned Python
runtime image. Nginx integration passed, but that alone cannot attribute a
cache improvement. #1218 was marked draft at that checkpoint. The follow-up
revisions covered pre-step services and repository/organization runtime-image
pulls with digest-preserving, fallback-safe distribution while retaining the
full checks.

Final October 10 UTC reconciliation: #1217 passed full protected
[merge-group CI](https://github.com/ElevenID/marty-ui/actions/runs/38006523302)
and merged at 00:16:56 UTC. #1218's exact-head
[PR CI](https://github.com/ElevenID/marty-ui/actions/runs/38004610964)
passed, including Canvas (23m20s), and its post-#1217
[merge-group CI](https://github.com/ElevenID/marty-ui/actions/runs/38006633615)
passed all required jobs before merge at 00:25:52 UTC. The implementation
preserves oracle-pinned OCI digests and canonical fallback, carries the
selected PostgreSQL image into the isolated self-host child, and pins the
rendered-base Redis pull; independent review found no P1-P3 issue. The first
#1218 queue attempt was invalidated by a subsequent source push, causing a
CodeQL upload to fail against the deleted queue ref; the final queue run
passed. Main's one-reviewer rule is restored. No attributable pipeline-wide
speedup is claimed from #1218 without comparable before/after runs.

The final #1218 [Canvas timing artifact](https://github.com/ElevenID/marty-ui/actions/runs/38006633615)
records 600 seconds compiling reusable Rust test executables, 387 seconds
building the public self-host image, and 581 seconds in database contracts.
The database phase started 106 exact-owned PostgreSQL containers, with 330
seconds of aggregate readiness and 783 seconds of aggregate migration/seed
time across concurrently executed cases. These sums are not critical-path
durations: worker, composition, self-host, and Flow targets overlap. The
three stages remain the largest observed Canvas contributors. Compared with
#1212's 618/375/647 seconds, this different combined head gives no clean
attribution for the change; investigate fixture/setup reuse with isolation
proof before changing the required case inventory.
The artifact's host `sccache` counters show zero hits and misses, but the
Bookworm compile runs inside a separate network-disabled container without
the host `RUSTC_WRAPPER`; these counters do not measure its compilations.
Do not claim a cache regression or add a new cache layer from that artifact.

Follow-up ownership audit of that same artifact: 77 of the 106
`migration_seed` events are the default `published_probe`; 14 are
`status_provider` (99.2 seconds summed, 5.3–8.4 seconds each). The latter
serve separate mutable native database/process/HTTP contracts and one
published-Python/frozen-reference comparison. The worker repository-only
matrices already use an owned migrated template with independent database
clones, so extending that pattern to every probe is neither a new general
optimization nor an isolation-safe default. In this run, the single
`json_depth` published oracle took 104.6 seconds; `json_consumer` took 44.4
seconds and `worker_startup` 41.0 seconds. Those are individual probe
durations, while the status-provider sum overlaps other test work. The
JSON-depth probe invokes both published validation and provider observations
under a 180-second bound, and its test compares the full independent frozen
observation. Do not remove or shorten that oracle merely because it is slow.
Next measure its internal validation/provider phases and the target's
critical-path overlap before proposing a fixture or qualification change;
keep the current required case inventory and exact-owned cleanup meanwhile.

Target-attribution follow-up (2026-10-10, local candidate): the #1229 and
#1230 Canvas artifacts each record 77 `published_probe` migrations in the
published-canvas group. Their worker/composition targets took 385/356 and
486/468 seconds respectively, while the overlapping migration sums were
341 and 425 seconds. The two targets are close enough that optimizing only
one may not shorten the group; summed phase durations are not wall time.
The four parallel targets already write separate owned logs. Tag only their
relayed, allowlisted phase rows with a fixed target identity, retaining raw
logs, case execution, cleanup, and all gates. Use the resulting per-target
counts before proposing database-template reuse; this candidate itself
claims no speedup.

The next local A0/A6 candidate records four bounded JSON-depth oracle
subphases—setup, published validation, published provider, and observation
encoding—beside the unchanged frozen observation. The Rust fixture admits
only the ordered payload-free rows and relays fixed labels to the existing
CI timing artifact. The current-checkout input hashes are refreshed after
source review; historical captures are untouched. Fifty-three focused
Python timing/selector tests, Ruff, rustfmt, and targeted Rust package
`cargo check` pass locally; independent review found no P1–P3 issue and its
stale-comment nit was fixed. Real published-container execution and protected
CI are still required before any phase attribution or speed claim.

Exact-head [UI #1220 PR CI](https://github.com/ElevenID/marty-ui/actions/runs/38010182064)
passed the real Canvas suite and final gate. Its JSON-depth oracle emitted
four successful, bounded phase rows: setup 4 ms, validation 29,556 ms,
provider 90,435 ms, and encoding 195 ms. The enclosing published probe took
126,817 ms and the concurrently executed database group 678,172 ms. This is
one run, not an attributable before/after improvement. The provider oracle
iterates 64 depth/shape/status cases, each exercising suspend, reinstate,
and revoke through a real app with isolated row resets. It currently creates
an app for each route (192 constructions). A network-disabled local run of
20 `create_app()` calls in the exact pinned published image took 1,753 ms
after import, suggesting avoidable repeated setup but not proving CI savings.
The next local candidate reuses one app only within each case, preserving
fresh app identity between cases, mutable database resets, the three route
assertions, and the frozen full observation. Its 55 focused tests and Ruff
pass; independent review found no P1–P3 issue after adding a three-route
wiring guard. It is folded into the timing PR so one subsequent exact-head
hosted run can check pinned-image parity and compare phase timing. That run
is still required before merge; no speedup is claimed from the local probe.

The new exact-head [#1220 run 38013171013](https://github.com/ElevenID/marty-ui/actions/runs/38013171013)
passed all required jobs and the final gate. The published JSON-depth and
status-provider frozen-oracle tests are explicitly `ok` in the Canvas log.
Provider time was 29,887 ms versus 90,435 ms on the preceding passing head
(60,548 ms, 67% lower); the enclosing JSON-depth probe was 56,664 versus
126,817 ms. Canvas job wall time was 29m05s versus 32m27s, but compilation,
image-build, scheduling, and overlapping database work vary; do not attribute
that whole-job difference solely to app reuse. Fourteen status-provider
database probes summed 81,644 versus 97,658 ms, also across different runs.
The provider oracle seeds `credential-review` and related rows consumed by
native status tests. Removing its repeated execution without separately
preserving those seed and final-state effects would change the tests; defer
that proposed deduplication until the fixture boundary is independently
proved. [Protected run 38029895146](https://github.com/ElevenID/marty-ui/actions/runs/38029895146)
passed and #1220 merged into main as `ae7cfc797` on 2026-10-10.

The same exact-head compile artifact separates the 599-second pinned-Bookworm
container phase into test targets 253 seconds, issuance binaries 206 seconds,
Gateway binary 109 seconds, and Flow binary 29 seconds. The three binary
commands therefore account for 344 seconds in this run. They deliberately
retain package-specific feature resolution; combining them is not yet a
qualified optimization. The host `sccache` counters do not measure this
network-disabled container, so they cannot justify a cache-hit claim.

The public self-host image is a distinct release-profile build of the complete
service binary list in `services/Dockerfile` and
`scripts/build-rust-service-binaries.sh`; the Canvas acceptance executables
and helper binaries are test/development-profile artifacts from a host-mounted
target directory. Copying those binaries into the production image would
change the qualified artifact, so the 402-second image build cannot be
eliminated by that reuse. The image
already uses a cargo-chef dependency stage, BuildKit cache scope, and the
repository's filtered Docker context. A narrower image or changed cache mode
needs its own runtime/packaging equivalence proof and comparable timing.

Latest protected timing comparison: #1210's Canvas run `37955004959` spent
482 seconds compiling reusable tests, 318 seconds building the public
self-host image, and 459 seconds in database contracts. #1212's combined-head
run `37963117844` spent 618, 375, and 647 seconds in those phases. The
`json_depth`, `json_consumer`, and `worker_startup` migration/seed events all
slowed together; #1211 also changed the combined head. These are different
load/code conditions, not an attributable regression or a reason to delete
one named case. A further fixture-reuse change needs case ownership and
isolation proof under comparable runs.

The #1220 timing artifact puts `json_consumer` at 27,853 ms for migration/seed
and 29,491 ms for its serial probe. Its 66 validation cases sum to 12,466 ms;
its 66 provider cases sum to 12,350 ms. Provider routes already reuse one app
within each case. Validation constructs an app per case while patching
case-specific environment, repository, file, and HTTP boundaries; cross-case
reuse is not safe without proving app configuration does not capture those
inputs. `worker_startup` took 21,902 ms in migration/seed; its oracle starts
real child processes and checks their heartbeat, which remains its purpose.
Neither is a
justified next coverage reduction or a measured end-to-end speedup.

[UI #1222](https://github.com/ElevenID/marty-ui/pull/1222) records the
source-backed Gateway-to-Credential-Template issuer-resolution consumer in
the fail-closed shadow planner. Its exact-head [PR run
38016397675](https://github.com/ElevenID/marty-ui/actions/runs/38016397675)
passed the planner-owned release tests, including the new named regression,
and the final gate in 2m08s from workflow start to gate completion. This
planner-only input legitimately selected the narrow PR lane; the protected
merge group remains full. It is one scoped observation, not a pipeline-wide
average or a speedup caused by the added edge.
[Protected run 38029925495](https://github.com/ElevenID/marty-ui/actions/runs/38029925495)
passed and #1222 merged into main as `ab721eee6` on 2026-10-10.

The same #1220 Canvas artifact has 83 default `published_probe`
`migration_seed` rows totaling 361,983 ms across concurrently run tests.
`PublishedDatabase::start_probe_with_scope` gives each probe its own
tmpfs-backed PostgreSQL container and fixed
`canvas_published_schema_test` database; the pinned Python oracles use that
same fixed name inside the container network namespace. A shared-server
template would need a new namespace/database and cleanup contract, not just
`CREATE DATABASE ... TEMPLATE`, and would alter the current isolation proof.
The 107,223 ms timeout and 111,803 ms lease-expiry preflights retain live
deadline/lease behavior. Neither aggregate sum is a sequential CI saving.

There are 14 `start_with_status_provider()` call sites in the Canvas
composition target. Only `status_provider_matches_published_python` directly
compares its oracle to the frozen reference; the other 13 use the resulting
database for native Gateway/status assertions. The constructor also applies
the review-recovery migration, and the Python oracle seeds issued/delivery
rows before exercising mutable provider and credential-route cases. A future
seed-only fixture could reuse the existing checked-in scenario SQL while
retaining the one full independent oracle, but it must prove the native
tests' exact required initial/final rows, recovery migration, pinned-input
closure, and cleanup before replacing any call. No skip or saving is claimed.

Source follow-up: a bare replay of `shared.seed` is **not** equivalent to the
current fixture. The published status oracle additionally inserts
`delivery-provider`, iterates provider cases, and can persist credential and
delivery changes (including credential-route writes). Native runtime setup
updates those same rows, while review tests snapshot the initial delivery row
and compare unaffected rows across cases. Therefore first compare the
post-oracle and seed-only database states for the columns each native case
reads, then test any narrower initializer against all 13 native cases on
disposable, isolated published-schema databases. Retain the one full oracle
and its frozen comparison; do not switch constructors based on source reading
alone.

Native-seed pilot (2026-10-09,
[UI #1223](https://github.com/ElevenID/marty-ui/pull/1223)):
a new constructor retains the pinned published migrations, review-recovery
overlay, isolated PostgreSQL
container and owned cleanup, then executes the nine existing issued-review
seed statements plus the delivery row without the provider oracle. Thirteen
native composition cases use it; the independent published-Python/frozen
comparison still runs once and now checks the seeded and published resulting
rows across all ten fixture tables, ignoring generated timestamps only.
Twelve available native cases passed on Windows, including the two packaged
process cases. The exact-head [Linux PR run 38019790357](https://github.com/ElevenID/marty-ui/actions/runs/38019790357)
passed the Unix-only mirror-worker lifecycle, independent published/frozen
oracle, Release Contract Tests, Canvas, Analyze Rust/Actions, and final gate. The comparison
and the 22 current-input hash tests also passed locally.
Separate fixed `migration_seed` and `fixture_seed` labels now cover the new
constructor; the timing collector accepts only those exact labels. Its 53
targeted policy/current-input tests and Docker-backed parity test passed
locally. The Linux timing artifact recorded one full status-provider migration
(6,810 ms), 14 native-seed migrations (69,336 ms total, including parity),
and 14 native fixture seeds (3,769 ms total). The #1220 baseline had 14 full
provider migrations totaling 81,644 ms. This proves less repeated oracle
work, not a wall-clock saving: the Canvas job was 30m48s versus 29m05s and
composition target 469s versus 350s. Unchanged scenario durations were also
1.36x higher on the new run, so runner variation prevents causal attribution.
The PR was rebased after #1220 and #1222 merged; its rewritten head still
required fresh exact-head validation and protected queue qualification.
The rebased [PR run 38032487415](https://github.com/ElevenID/marty-ui/actions/runs/38032487415)
passed all required jobs, including Canvas (31m14s), Release Contract Tests,
Rust analysis, security, and the aggregate gate. The protected [merge-group
run 38034389609](https://github.com/ElevenID/marty-ui/actions/runs/38034389609)
also passed; #1223 merged as `bd2594845` on 2026-10-10. No comparable
whole-pipeline speedup is established by these different hosted runs.

Self-host diagnostic preparation (2026-10-10,
[UI #1226](https://github.com/ElevenID/marty-ui/pull/1226)): a separate
label-triggered PR rehearsal runs the existing ten-case
`marty-selfhost-acceptance` target. The scoped artifact verifier requires its
exact Bookworm-compiled test harness; the runner reuses the full lane's ten-ID
roster, both pinned PostgreSQL and published-probe images, immutable public image ID, packager,
standalone Compose renderer, owned database cleanup, and complete test-result
check. The ordinary PR matrix and every protected merge-group lane remain
unchanged. The first hosted pilot exposed a missing published-probe image pull
in the isolated lane and stale exact CI-policy assertions; both were corrected
without weakening required gates. This remains a diagnostic, not a selective
skip or an established wall-clock speedup. Measure the additional lane before
considering an exact self-host test-source selector.

Self-host pilot result and next A6 selector (2026-10-10): #1226's exact-head
diagnostic lane passed all ten cases in 12m28s; its target run took 97.33s
and the pinned image-pull/test group took 112.18s. The same PR's successful
full Canvas rerun took 31m44s, and protected merge-group Canvas took 29m53s.
These are different hosted attempts, not a causal speedup measurement. The
initial Canvas attempt failed an unchanged ten-second issuance readiness
assertion, then passed on the same commit without a skip or deadline change.
An exact three-source PR selector is justified only while all three tracked
`marty-selfhost-acceptance` test files remain the sole target's sources and
outside every Rust-copying release image. The root release suite must still
run because its Python policy tests inspect those files; unknown, mixed,
manifest, helper, production, and protected merge-group inputs retain full
Canvas/contracts. Measure a real source-only PR before attributing a faster
feedback result to this selector.

[UI #1227](https://github.com/ElevenID/marty-ui/pull/1227) merged that exact
self-host test-source selector as `3a3d6c45d` after its 32m14s full PR run
and successful protected merge-group run. It retains the root release suite,
Rust lint, supply-chain and protocol checks on the narrow PR path; protected
merge groups still execute full Canvas and contracts. The first one-source
[PR #1228](https://github.com/ElevenID/marty-ui/pull/1228) passed its scoped
CI gate in 10m42s and all PR checks in 14m46s, including 9m24s for the exact
ten-case self-host lane and 10m03s for release contracts. Relative to #1227's
32m14s full PR workflow, this is an observed 21m32s CI-gate difference and
17m28s all-check difference between different changes, not a controlled
same-head benchmark or a whole-repository average. An independent reviewer
caught a proposed new test ID that would violate the ten-case roster; #1228
instead strengthens the existing recovery case without changing that roster.
It remains open pending the required GitHub review at this checkpoint.

The same source-only PR exposed a remaining feedback tail: production-focused
Rust CodeQL took 14m46s even though its configured `paths-ignore` excludes
`rust/**/tests/**`. The next A6 candidate limits a PR-only CodeQL skip to a
nonempty, modified-only subset of the worker, Flow and self-host test files
already proved to be sole target sources and outside every Rust-copying
release context. It must re-run all three source proofs on the checked-out
head, require the exact current production CodeQL configuration, and fall
back to analysis on any unknown, mixed, renamed, added or proof-drift input.
Protected merge-group, scheduled and manual CodeQL analyses remain full.
This is a candidate, not a measured saving, until hosted qualification.

## October 10 follow-through

The checkpoint above predates merges: [#1228](https://github.com/ElevenID/marty-ui/pull/1228),
[#1229](https://github.com/ElevenID/marty-ui/pull/1229) and
[#1230](https://github.com/ElevenID/marty-ui/pull/1230) are now on `main`.
#1229 implements the narrowly proven PR-only CodeQL skip; merge groups and
scheduled/manual runs keep analysis. #1230 reports slow release pytest cases
without changing their execution. Neither is a controlled speedup measurement.

[#1232](https://github.com/ElevenID/marty-ui/pull/1232) adds per-target
Canvas phase attribution without changing coverage and passed exact-head PR
CI. Its hosted sample found the published-canvas group at 629s, with worker
and composition targets at 488s and 471s. Their phases overlap in parallel;
the sums are not wall-clock savings. It merged through the protected queue
after full merge-group qualification.

[UI #1233](https://github.com/ElevenID/marty-ui/pull/1233) source-witnesses
the existing Applicant-to-Notification internal ingest edge (URL fallback,
token, publisher call, provider route and guards, Compose wiring) while
retaining full-workspace fallback. Its mutation-checked planner suite passed
45 local tests with one skip; independent review found no P1-P3 issue. The
exact-head [PR CI](https://github.com/ElevenID/marty-ui/actions/runs/38063818603)
reached its scoped gate in 1m37s, and the full
[protected merge-group CI](https://github.com/ElevenID/marty-ui/actions/runs/38064313124)
passed before merge. The edge is diagnostic metadata, not a narrower selector
or a whole-repository speedup claim.

October 10 residual-owner audit on `main` `1b37f12bb`: the inspected
`gateway/tests/redis_runtime.rs`, `revocation-profile/tests/runtime_contract.rs`,
`event-stream/tests/grpc_contract.rs`, and
`issuance/tests/canvas_sync_worker_behavior.rs` do not justify another A1
cross-service move. The Gateway test exercises its own Redis providers; the
Revocation Profile executable test uses a local Organization gRPC stub while
checking its own PostgreSQL/Redis, HTTP, and gRPC contract; Event Stream runs
its own process and protocol; and the Canvas worker test checks its own
configuration, frozen vectors, and shutdown. The separately owned
`service-acceptance`, `flow-acceptance`, `canvas-worker-acceptance`, and
`canvas-acceptance` targets retain the actual cross-service obligations.
This is a scoped source-ownership audit, not proof that every remaining test
has been classified or that any gate can be skipped.

An A3 candidate was rejected before editing: Applicant's
`ES_GRPC_TARGET`/`EventStreamServiceClient::publish` path is already a direct
Cargo dependency on `marty-event-stream`; the planner's Event Stream test
asserts that exact dependency and the three additional non-Cargo consumers.
Adding Applicant as a shadow runtime edge would duplicate established Cargo
closure, not improve selection. Continue the non-Cargo audit with consumers
that are absent from both Cargo and the source-witnessed graph.

## Design references

- [Cargo workspaces and package selection](https://doc.rust-lang.org/cargo/reference/workspaces.html): use package boundaries within the current workspace for independent validation.
- [The practical test pyramid](https://martinfowler.com/articles/practical-test-pyramid.html): place detailed behavior at fast levels while retaining focused integration proof.
- [Contract versus functional tests](https://docs.pact.io/consumer/contract_tests_not_functional_tests): message compatibility does not establish durable side effects.
- [Tokio testing](https://tokio.rs/tokio/topics/testing): controlled time and I/O doubles for appropriate isolated tests.
- [Semantic Versioning](https://semver.org/): version numbers express intended compatibility, not the impact of implementation changes.
