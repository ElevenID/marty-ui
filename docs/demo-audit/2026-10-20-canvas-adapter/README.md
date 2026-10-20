# D07/D08 current-run Canvas adapter

The lifecycle lineage was imported through the supplied bundle at `eefd190b7c7d31308a907ed6637c21635458ece4`; its complete source tree matched `25e9a6dd9ba93b4d41906eeee3688865fb096b39` before development. Existing worktrees and user edits were preserved. Core and verifier carryovers were imported into separate review worktrees and matched their supplied trees.

## Source behavior

`tests/scripts/audit-beta-canvas-capture.js` runs either `canvas-learning-achievement` or `external-evidence-to-credential` through the recorder's source-pinned external driver and acknowledged live-evidence IPC. It requires the stock contract's existing Compose execution boundary. Standalone report-shaped JSON cannot enable it.

The stock contract and capture driver share `prepareCanvasCaptureFixtures`: stock Canvas Developer Key screens, documented REST APIs, standard OAuth, Deep Linking, AGS, NRPS, readiness and fresh run-named fixtures. The original stock contract continues to use that same setup. Its in-progress setup state remains available for cleanup if setup fails. Imported image/bootstrap/runtime artifacts establish prerequisites only.

`canvas-capture-sequence.js` connects actual assignment navigation, its real LTI popup and Continue/bootstrap response to the exact organization, templates, platform, binding and application. Each new enqueue must match its terminal job, ownership tuple and current operation. Current authoritative evidence heads are read from the scoped application. Fresh 95-to-40-to-95 corrections must change those heads and deny/recover policy.

The unsigned pending projection and absence of an issued credential are checked before approval and again before claim. Approval uses the existing scoped Canvas management API; it is reported as an API operation. The selected transaction is read back before the ordinary claim dialog opens. The actual first-party Rust browser wallet receives the offer through its UI and performs the canonical presentation/verification flow. The stored wallet summary, exact application/template/transaction credential record and server claim completion must agree. This is first-party control capture; it does not claim an independent native wallet was operated.

D08 additionally performs a new post-issuance downgrade, requires one exact correction review while the issued credential stays ACTIVE, captures the existing administrator review card, restores the score and observes that same review resolve through `evidence_recovered`. D07 performs the current retired-ingest request and requires HTTP 410. Every assertion is assigned only after the whole selected sequence succeeds. Failures restore the exact synthetic assignment grade and leave the assertion set incomplete.

The recording context captures the Canvas assignment and real LTI popup separately; the administrator and Rust wallet have additional retained recordings. Unexpected extra launch windows fail. Beta source, marker, component revisions and images are compared before/after the sequence. Cleanup confirms revocation of this run's issued credential or exact unused transaction, closes its isolated wallet session, disconnects OAuth and deletes the run-created platform/secret. Application history is retained. Cleanup failures prevent completion of live IPC and qualification.

## Required environment

Use the existing stock Canvas Compose contract, its immutable Playwright image and file-mounted secrets. Its `CANVAS_OSS_*` execution identity variables and image/bootstrap/runtime artifacts under `tests/artifacts/canvas-oss-portability/` remain mandatory. The external recorder must run inside that reviewed container with both clean source worktrees and the recorder helper available; a host-only invocation does not satisfy the boundary.

Supply the stock contract's organization, explicit active Open Badge application/template selection where required, and mounted administrator, synthetic learner and organization API-key secrets. Supply `CANVAS_CAPTURE_ADMIN_EMAIL_FILE` and `CANVAS_CAPTURE_ADMIN_PASSWORD_FILE` for the beta administrator, `BETA_AUDIT_ORG_ID` equal to `CANVAS_OSS_ORGANIZATION_ID`, and `CANVAS_CAPTURE_PRESENTATION_POLICY_ID` selecting an active policy that requests the actual badge template. The isolated-session Rust wallet must be reachable at `http://127.0.0.1:8787` from the capture container. The source-bound recorder supplies `BETA_ORIGIN`, `RECORD_VIDEO`, `DEMO_ARTIFACT_DIR` and all live-evidence IPC variables.

The recorder's new Canvas configs require an exact product checkout, descendant driver revision/hash and fresh matching portability prerequisite. Do not replace source or deployment bindings with environment claims. Functional reruns disable all four recording streams and use the same operations.

## Focused verification and limits

The new controlled sequence tests cover foreign bootstrap/job/credential bindings, stale or replayed jobs, duplicate issuance, denial/recovery, failed worker readback, rejected verification, real popup/Continue ordering and same-origin enqueue observation. Existing stock contract tests exercise the shared setup module's surrounding contracts. One focused React case checks that the existing correction-review card exposes its real review/application/credential identity.

These local fixtures are tests of the adapter. They are not Canvas or beta results. On the read-only environment check, beta still served `beta-v259-vc-di-fe5ec5fd0751`; Canvas login returned HTTP 502; the imported source had none of the required stock-image/bootstrap/runtime artifacts; no isolated test-wallet container was running. No new deployment, live shared-resource mutation, recording or publication was performed.

Actual governed execution on a matching deployment remains required. Both current scenarios, independent-wallet requirements and all catalog qualification flags remain unqualified. The final master still needs successful source capture, voice, matching subtitles, measured crop/zoom, source-bound disclosed cursor actions and viewing/listening review. Preserve the existing lifecycle presentation profile and media-retention policy.
