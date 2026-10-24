# Marty / ElevenID demo functionality audit — 2026-10-19

## Outcome and scope

This first audit delivers a Git-tracked engineering fix set and a continuing demo audit tracker. It covers the public demo catalog, the Canvas demo wallet's issuer contract, lifecycle-runner resource ownership, and selected recorder execution/evidence contracts. The fixes have focused automated coverage and local browser verification.

The authenticated demos still require execution against a disposable, correctly bound stack. No live beta credentials were issued or revoked during this audit, and no deployment or publication was performed. A passing local test in this report does not change a scenario's checked-in release qualification status.

The companion [audit-tracker.json](audit-tracker.json) retains stable finding IDs, positive and negative scenario requirements, source references, and separate local-test and full-stack statuses. [verification.json](verification.json) records commands, results, environment limits, and evidence scope. [browser-report.json](browser-report.json) is the final production-build browser report.

### Source baselines

| Repository | Reviewed source | Treatment |
|---|---|---|
| `ElevenID/Marty` | `c6823c6316fc0f3be051133986236913ac4dcfee` | Compatibility-only Python repository; production ownership points to `marty-ui` and Rust. No changes. |
| `ElevenID/marty-ui` | Main at `5be7d67544b9d53fe26a2edc787061a34efdebdc` | Genuine Git checkout. Fix branch: `audit/demo-functionality-2026-10-19`. |
| `ElevenID/marty-demo-recorder` | `demo-audit-hardening-20261018` at `64c9bc986185b53bdcb1dd3d383787ad94fe931a` | Authenticated read-only source access. A focused 129-file snapshot was verified against exact upstream Git blob IDs and file modes; the local baseline has synthetic ancestry. Distribute only its fix patches for the real upstream checkout. |

The recorder's synthetic baseline is `e993c8fad6d97066319dcec8777f5cbb5dae593b`. It is not an upstream commit. `UPSTREAM_SNAPSHOT.json` in the download provides the exact file provenance. Its local fix branch is `audit/recorder-functionality-20261019`.

Source ownership: [Marty README](https://github.com/ElevenID/Marty/blob/c6823c6316fc0f3be051133986236913ac4dcfee/README.md). Catalog requirements: [demo portfolio](https://github.com/ElevenID/marty-ui/blob/5be7d67544b9d53fe26a2edc787061a34efdebdc/deploy-config/catalog/demo-portfolio-v3.json) and [demo platform documentation](https://github.com/ElevenID/marty-ui/blob/5be7d67544b9d53fe26a2edc787061a34efdebdc/docs/elevenid-stack-demo-platform.md).

## Confirmed findings addressed

“Fixed locally” means the implementation and its relevant local regression checks pass. The remaining deployment and scenario gates are listed separately. High severity here means a blocked core journey, mutation of another run's resources, or a false functional success; it is not a security-vulnerability rating.

| ID | Severity | Finding | Implemented behavior |
|---|---|---|---|
| DA-001 | High | Canvas wallet expected a token nonce and sent a credential-request member rejected by the current issuer. | Obtain a fresh nonce from `POST /v1/issuance/nonce`; omit `format`; fail before holder proof or credential request when the nonce response is unusable. |
| DA-002 | High | Lifecycle setup and cleanup could delete similar drafts and revoke other runs' active credentials. | Create a unique template per run, retain its exact ID before subsequent setup, and validate current-run ownership and organization before cleanup mutations. |
| DA-003 | High | Lifecycle selection used the newest matching credential, allowing concurrent issuance to select the wrong record. | Match the exact template and issuance transaction; verify renewal's predecessor; reject ambiguous matches. |
| DA-004 | High | Any HeadlessChrome user agent bypassed served demo manifests, allowing deployment failures to appear successful in browser audits. | Compiled evidence is available only to an explicitly marked build renderer. Ordinary headless browsers fetch and validate the served JSON. |
| DA-005 | Medium | A non-public scenario with a YouTube ID could offer playback. Consent could carry into a different recording. | Play only `PUBLIC` recordings; reset consent on recording/publication binding changes and preserve it for chapter changes. |
| DA-006 | Medium | Missing assertions could pass manifest loading and later crash rendering; an invalid latest-release reference could be accepted. | Validate those required structures before rendering and show the recoverable error/retry path. |
| DA-007 | High | A recorder driver that ignored termination, or retained output pipes through a descendant, could hang beyond its timeout. | Own a POSIX process group, escalate termination after a grace period, and bound output draining. |
| DA-008 | Medium | Recording-free D04/D05/D06 reruns still required secondary videos. | Explicitly classify secondary recordings for D04, D05, D05's untrusted-issuer companion, and D06. Functional JSON evidence remains mandatory. |
| DA-009 | Medium | The built-in QR assertion accepted loaded images and arbitrary drawings without decoding them. | Decode the actual target screenshot with the existing ZXing implementation; optionally compare an exact expected payload; retain a payload digest in evidence. |
| DA-010 | Low | At 320 pixels, the header's Login control extended the document to 328 pixels. | Use the existing compact language control below the small breakpoint. The document now fits all four measured widths. |

### Issuance contracts and lifecycle ownership

The Canvas wallet regression now reads the current token and nonce contract fixtures and accepts the server's canonical `credentials` array response. Five Rust tests cover the successful sequence, missing offer code, unavailable or malformed nonces, failed credential responses, and the signing-service boundary. The signing boundary test uses a local HTTP test server; it does not exercise an external KMS. The historical report field `credential_format: "vc+sd-jwt"` remains for report compatibility, distinct from the removed request member and the current server response format.

Lifecycle selection uses the current public response contracts:

| Operation | Returned transaction identifier | Inventory correlation |
|---|---|---|
| `POST /v1/issuance` | `response.id` | `record.flow_execution_id` |
| `POST /v1/issued-credentials/{id}/renew` | `response.transaction_id` | Successor's `flow_execution_id`, plus exact `renewed_from_credential_id` |

The issuance regression reads the checked-in gateway response fixture instead of inventing a synthetic response shape. Cleanup excludes similar template names and unrelated transactions. It validates all known candidates before mutations, reports pending transactions as incomplete, and prevents readiness when cleanup fails. Creation, issuance, and renewal register an uncertain mutation before dispatch and clear it only after the exact returned ID is recorded. Lost or malformed response IDs keep cleanup incomplete; ownership is never recovered by sweeping similar names.

Relevant reviewed sources: [wallet](https://github.com/ElevenID/marty-ui/blob/5be7d67544b9d53fe26a2edc787061a34efdebdc/rust/crates/canvas-demo-seed/src/wallet.rs), [nonce contract](https://github.com/ElevenID/marty-ui/blob/5be7d67544b9d53fe26a2edc787061a34efdebdc/contracts/issuance-proof-nonce.json), [public issuance response fixture](https://github.com/ElevenID/marty-ui/blob/5be7d67544b9d53fe26a2edc787061a34efdebdc/contracts/gateway-issuance-response-projection.json), and [lifecycle runner](https://github.com/ElevenID/marty-ui/blob/5be7d67544b9d53fe26a2edc787061a34efdebdc/tests/scripts/audit-beta-credential-lifecycle.js).

### Public catalog and recording evidence

The browser checks use actual served manifests and all 20 scenario routes across the two catalog releases. Controlled responses additionally test an HTTP 503 with successful Retry, malformed evidence, and an unlisted recording. The current manifests contain no unlisted playable recording, so DA-005 is a reproduced latent state-handling defect rather than a claim that a current private recording was exposed.

The video tests verify consent, embedding, and chapter navigation using a local iframe fixture. External YouTube streaming was not qualified. The manifest repair validates the structures involved in the reproduced crashes; it is not a complete replacement for schema validation of every nested field.

Recorder timeout tests use actual local subprocesses. Both baseline failure cases reached a six-second fixture fail-safe; patched cases finished around 1.5 seconds for a 500 ms deadline. Forceful termination covers the owned POSIX process group; an escaped descendant's inherited output cannot make the parent wait indefinitely. The Windows `taskkill` branch was source-reviewed and remains unexecuted in this Linux audit.

The QR change adds no dependency. Seven action regressions pass, and a real Chrome check accepts valid IMG/SVG/CANVAS QR renderings while rejecting three corresponding non-QR renderings. No maintained top-level demo configuration directly invokes this built-in assertion at the pinned recorder revision; this repairs the framework and does not establish portfolio-wide QR execution.

Reviewed sources: [manifest service](https://github.com/ElevenID/marty-ui/blob/5be7d67544b9d53fe26a2edc787061a34efdebdc/ui/src/services/demoManifestService.js), [video player](https://github.com/ElevenID/marty-ui/blob/5be7d67544b9d53fe26a2edc787061a34efdebdc/ui/src/components/demos/DemoVideoPlayer.jsx), [recorder process runner](https://github.com/ElevenID/marty-demo-recorder/blob/64c9bc986185b53bdcb1dd3d383787ad94fe931a/src/externalQualification.js), and [recorder actions](https://github.com/ElevenID/marty-demo-recorder/blob/64c9bc986185b53bdcb1dd3d383787ad94fe931a/src/actions.js).

## Scenario coverage and remaining functional work

The checked-in `2026.08.0` manifest has **14 DRAFT scenarios and 60 NOT_RUN assertions**: 58 numbered-demo assertions and two retained-wallet assertions. It declares `coverage_state: PARTIAL`, `release_ready: false`, `public_demo_ready: false`, and `binding_state: PENDING_DEPLOYMENT`. All 14 media bindings and their evidence hashes are absent. These are source-declared statuses, not a conclusion about unpublished runs elsewhere.

The older `2026.07.0` catalog contains six scenarios, including three individually public recordings: membership, organization primitives, and credential lifecycle. Rendering those recordings' catalog pages does not qualify the latest deployment. Source snapshots: [2026.08.0](https://github.com/ElevenID/marty-ui/blob/5be7d67544b9d53fe26a2edc787061a34efdebdc/ui/public/demos/manifests/2026.08.0.json) and [2026.07.0](https://github.com/ElevenID/marty-ui/blob/5be7d67544b9d53fe26a2edc787061a34efdebdc/ui/public/demos/manifests/2026.07.0.json).

Every row below passed its catalog rendering check. Every row's full-stack positive and negative execution remains **NOT_RUN in this audit**.

| ID | Demo | Required positive behavior | Required negative or recovery behavior |
|---|---|---|---|
| D-01 | Passport Pre-Boarding Clearance | Validate passport, issue clearance, verify at gate. | Deny untrusted or invalid passport. |
| D-02 | Stable Issuer Identity with Pluggable KMS | Issue with provider A, switch provider, preserve DID identity. | Deny an unpublished signing key. |
| D-03 | Private Online Age Proof | Issue trusted mDL, request only `age_over_21`, validate trust and minimum disclosure. | Deny untrusted issuer. |
| D-04 | Employee Onboarding and Secure Access | Approve employee, issue credential, allow active access. | Deny suspended employee. |
| D-05 | Membership Badge and Login | Govern the claim, issue conformant Open Badge, complete same-device passwordless login. | Cancellation and untrusted issuer create no session; expired offer can be reissued. |
| D-06 | Credential Lifecycle | Renew, suspend, reinstate, revoke. | Deny suspended and revoked credentials. |
| D-07 | Portable Learning Achievement with Canvas | Capture real Canvas evidence, review, issue Open Badge. | Deny invalid provenance. |
| D-08 | External Evidence to Credential | Normalize evidence, evaluate policy, review and issue. | Route conflicting or insufficient evidence to review. |
| D-09 | Offline Facility Verification | Provision edge trust, verify offline, buffer audit, reconnect and synchronize. | Deny expired offline trust. |
| D-10 | Organization and MIP Primitives | Configure organization, issuer profiles, trust, and MIP primitives. | Deny unauthorized administration. |
| D-11 | External Admissions Gateway and Webhooks | Return safe scoped summary, approve, correlate signed webhook and delivery history. | Deny insufficient scope without side effects; reject invalid signatures without mutation; acknowledge duplicates without a second transition. |
| D-12 | Passport Issuance Simulator Evidence | Managed CSCA/DSC profiles, nine-step software flow, correlated bureau simulation, signed callback. | Deny unsigned or foreign-organization callbacks without changing the job. |
| Retained | First-Party Browser Wallet | Preserve first-party issuance, storage, presentation, and status control coverage. | Fresh scenario-specific qualification plan and evidence are still needed. |
| Retained | Independent Wallet Interoperability | Preserve independent-wallet interoperability qualification surfaces. | Fresh independent-client evidence is still needed; historical media is not MIP 0.5 proof. |

**D-12 is explicitly software simulator evidence.** Its slug contains `physical-passport`, but the manifest requires proof that physical issuance is not claimed and no physical booklet has been verified. The audit preserves that boundary.

### Open findings requiring a subsequent change

| ID | Severity / status | Finding and next action |
|---|---|---|
| DA-011 | High / OPEN | The legacy six-scene `demo.spec.js` can finish scenes without their intended business result. A stubbed missing-controls run completed five scenes and skipped one. Required actions are optional or errors are swallowed; three `scrollIntoView` calls pass a Locator into a string-based helper. Replace or explicitly retire this narration-oriented harness before counting it as functional acceptance. |
| DA-012 | Medium / OPEN | `record-canvas-employer-demo.js` ignores false results from several required-looking steps and can finalize a recording after they fail. The real Canvas OSS portability documentation already excludes this synthetic recording. Preserve that exclusion and make the legacy script's completion report reflect its actual step outcomes. |
| DA-013 | Medium / OPEN | D-10 passes `--record-video` to a Python driver that ignores `RECORD_VIDEO`. Metadata changes alone cannot enable recording-free execution. Define and test an explicit argument contract. |
| DA-014 | Medium / OPEN | D-12 requires `RECORD_VIDEO=1`, records unconditionally, and copies retained negative-case videos. Implement a complete unrecorded execution/evidence contract before enabling functional reruns. |
| DA-015 | High / OPEN | Shared `findCurrentCredential` still selects the newest post-start record for a template. Employee/passport consumers can select another concurrent run's record. Extend exact application/transaction correlation to these consumers before concurrent execution. |
| DA-016 | Medium / FOLLOW_UP | The existing test-wallet `/api/reset` call needs a concurrency review if runs share one wallet process. Use an isolated wallet per run until its state boundary is established. Existing revocation-profile reuse/creation also remains outside the lifecycle cleanup patch. |

Source references: [legacy narrated demo](https://github.com/ElevenID/marty-ui/blob/5be7d67544b9d53fe26a2edc787061a34efdebdc/tests/e2e/e2e-flows/demo.spec.js), [demo Playwright configuration](https://github.com/ElevenID/marty-ui/blob/5be7d67544b9d53fe26a2edc787061a34efdebdc/tests/playwright.demo.config.js), [legacy Canvas recorder](https://github.com/ElevenID/marty-ui/blob/5be7d67544b9d53fe26a2edc787061a34efdebdc/tests/scripts/record-canvas-employer-demo.js), [Canvas OSS acceptance boundary](https://github.com/ElevenID/marty-ui/blob/5be7d67544b9d53fe26a2edc787061a34efdebdc/docs/CANVAS_OSS_PORTABILITY_PIPELINE.md), [shared selection helper](https://github.com/ElevenID/marty-ui/blob/5be7d67544b9d53fe26a2edc787061a34efdebdc/tests/scripts/beta-demo-resource-helpers.js), and [recorder rerun contract](https://github.com/ElevenID/marty-demo-recorder/blob/64c9bc986185b53bdcb1dd3d383787ad94fe931a/docs/functional-reruns.md).

## Verification and practical limits

The final result counts and exact invocations are in `verification.json`; the browser report contains all 29 named checks. Successful checks include:

- Five locked Rust Canvas wallet tests, including current issuer contract fixtures.
- Twenty lifecycle cleanup/correlation tests and six provider-switch consumer tests.
- Three UI suites containing 32 tests; TypeScript validation; the complete production build with prerender enabled.
- Twenty scenario pages, four widths, served-manifest behavior, consent/chapter handling, unlisted-state behavior, and error/retry behavior: 29 production-browser checks with zero page errors.
- Forty-nine selected recorder tests and six rendered QR cases.

The environment used Node 24.19.0, npm 11.9.0, and the repository's pinned Rust 1.95.0. The local UI browser audit used Playwright 1.62.1 with an explicit Chrome for Testing 155.0.8059.84 executable after the pinned browser download returned an invalid archive. Google Fonts requests failed certificate validation, so browser layout checks used fallback fonts. The browser report retains this environment exception. Neither exception is presented as a product defect.

Authentication was an explicit unauthenticated fixture for the catalog browser test. YouTube frame content was a local fixture. Lifecycle tests ran the actual browser callbacks against scripted local fetch responses. Recorder configuration tests used synthetic drivers. These checks provide regression evidence for the fixes; authenticated issuance, real KMS switching, Android wallets, Canvas OSS portability, Windows/offline execution, and full deployment qualification remain outstanding.

The next functional run should use an isolated disposable stack and run-owned test identities, beginning with D-06. Verify real issuance and renewal IDs, status-list ownership, suspended/revoked denial, reinstatement success, and final cleanup. Then cover D-04/D-05 success and denial paths after addressing shared selection/reset boundaries. Continue with external dependencies—D-02 KMS, D-07 Canvas, independent wallets, D-09 offline, D-11 webhooks, and D-12 simulator callbacks—while retaining separate positive and negative evidence for each.

## Reproducing the local public-catalog audit

Use the repository's locked Node dependencies and an installed Playwright-compatible Chromium. The script defaults to `http://127.0.0.1:4173` and refuses non-loopback targets. It does not perform authenticated product mutations. Run the production build with prerender enabled, start Vite preview, and run the audit in a separate terminal:

```bash
cd ui
npm ci
npm run build
npm run preview -- --host 127.0.0.1 --port 4173 --strictPort
```

```bash
cd tests
npm ci
DEMO_AUDIT_UI_MODE=production node scripts/audit-local-demo-catalog.js
```

Use `PUPPETEER_EXECUTABLE_PATH` for the production build and `DEMO_AUDIT_BROWSER_EXECUTABLE` for the audit when an explicit browser is required. Set `DEMO_AUDIT_OUTPUT_DIR` to choose where `report.json` is written. Screenshots are disabled by default; `DEMO_AUDIT_SCREENSHOTS=1` enables local diagnostic screenshots. The delivered evidence contains no screenshots or video.

## Integration and Git delivery

The download contains ordered `git format-patch` series, a real-history `marty-ui` Git bundle, exact baseline metadata, the audit tracker, and patch-application verification. Its top-level `APPLY.md` gives concrete commands. The recorder series must be applied to the real upstream recorder checkout at the pinned hardening commit; do not apply its synthetic snapshot baseline.

Existing demo branches were inspected before implementing these main-based fixes. In particular, `demo-lifecycle-live-v258-20261019` already includes part of the unique-template approach plus narration/fixture changes. Applying this lifecycle patch to that branch requires reconciliation rather than assuming a clean main-based application. Existing PR 1425 and the provider/cancellation/other beta driver branches contain additional work outside this patch set; this audit does not supersede their qualification or merge them implicitly.

After integration, refresh the applicable source and deployment bindings through the existing recorder workflow and requalify the target revision. A local commit, a successful unit suite, or an older recording does not supply the fresh deployment-bound evidence required by the catalog.
