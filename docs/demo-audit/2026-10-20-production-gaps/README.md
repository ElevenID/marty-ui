# Marty / ElevenID — production gap repairs

**2026-10-20 UTC. Local implementation and focused verification completed; current-release demo qualification remains pending.**

This pass implements the authorized repairs with shared Rust domain logic and thin browser/recorder adapters. It continues the [lifecycle alignment audit](../2026-10-20-lifecycle-alignment/README.md). Current-release execution remains pending: the catalog contains **14 DRAFT scenarios, 66 NOT_RUN assertions**, pending deployment binding, and no newly bound media. Every catalog entry now has a dedicated current configuration, including a bounded retained independent-wallet contract. Remaining qualification chiefly requires actual deployed services, governed fixtures, pinned native devices and source-bound recordings.

The [gap tracker](gap-tracker.json) separates source repairs from outstanding implementation and execution. [Verification](verification.json) records the focused evidence and the failed broad TypeScript command. [Source references](source-references.json) identify the reviewed implementation bytes; the archive's `BASELINES.json` contains final delivery commits and trees.

## Rust implementation and shared behavior

### Isolate the wallet before any scenario mutation

The `marty-core` test wallet now creates a separate empty wallet for each run, with a public session identifier distinct from its opaque HttpOnly cookie capability. Demo requests also carry their run identifier. A wrong run is rejected; missing, expired or closed session capability cannot fall through to the legacy interactive wallet.

Rust owns the bounded session store, six-hour expiry and concurrent lifetime handling. Each protocol operation holds a session lease. Closing waits for active operations to finish, rejects later readers, and only then removes storage and returns success. A timeout or unknown close result remains incomplete cleanup. No-cookie interactive use remains explicitly an internal compatibility control.

One shared UI browser adapter acquires, opens, checks, resets and closes these sessions. Lifecycle, credential login, organization credential paths and the new membership support lanes use it instead of global resets. Actual local Chrome and the compiled Rust server verified separate cookie jars, non-readable HttpOnly cookies, cross-run rejection, closed/missing-cookie rejection, and preservation of the other session.

The cross-driver review caught two missed callers of the common receipt helper: D01 passport clearance and D04 employee access had not acquired their browser context's session. Both are updated to acquire before owned mutations and close before context finalization. Failed or unknown session cleanup prevents success, so the shared isolation change does not strand these journeys at receipt.

Lifecycle setup now selects an exact pre-existing active revocation profile owned by the organization. It no longer creates a shared authority that cleanup could accidentally remove. Lifecycle, D03 and D05 reuse the same exact-transaction cancellation helper: authenticate the captured transaction, verify its ownership, cancel through the public API, and confirm revoked readback. Natural expiry is supported. Unknown creation IDs, an issued-credential race, foreign ownership or unconfirmed readback keep cleanup false; no broad resource sweep is performed.

The final cross-repository check also found a D06 launch blocker: its driver required recorder-owned IPC, but its configuration did not enable that transport. The configuration now pins the driver entrypoint, requires an explicit reviewed `DEMO_D06_DRIVER_REVISION`, enables live evidence, and retains `lifecycle-fixture-input.json` in both recording modes. This closes the configuration/driver mismatch without bypassing the source or evidence requirements.

### Complete D03's real age-proof evidence path

The dedicated recorder configuration and Android adapter use explicit pinned EUDI and Spruce lanes, source-specific controls, empty-wallet observations and distinct credential selection. The issuer setup is labeled API fixture setup; the holder actions and administrator result inspection use the actual application paths.

The Rust release-evidence crate validates exact native receipts and ownership rather than implementing a second credential verifier. The presentation-policy service projects only authenticated mdoc element names from native verification facts. It retains additional disclosed names instead of hiding them behind the requested policy. The UI fetches the exact terminal Flow result and rejects stale, unavailable or unrelated results. The age contract requires exactly the intended document, namespace and `age_over_21: true`, and rejects extra disclosure.

A generic “presentation failed” or `invalid_presentation` cannot prove issuer trust denial. The negative lane requires an observed issuer-specific untrusted/not-trusted message. Verifier-trust messages do not qualify it. The receipt explicitly retains an unknown typed backend reason; no native reason code is invented. If the selected build cannot expose that observation, the negative lane remains blocked.

The native template/issuer fixes already present on the lifecycle branch are included in the main variant: issuer-organization application-template lookup, optional field and badge discovery compatibility, and shared issuer assertion-key resolution independent of the login trust decision.

### Replace D05's external support-driver dependency

The expired-offer and foreign-issuer lanes now use a repository-owned driver with fixed entrypoint bytes, explicit reviewed source revision and recorder-owned live evidence transport. Shared resource and wallet helpers preserve DRY behavior; JavaScript performs transport and DTO correlation, while native services remain responsible for signature and trust verification.

The foreign-issuer case requires a real native signature-valid/trust-denied result tied to the exact login Flow, Auth `issuer_not_trusted`, visible failure, and no authenticated session. It then issues and receives a fresh trusted badge and completes actual credential login. The expired-offer case reads authoritative transaction and application expiry, waits naturally, requires public offer 410 and cached pre-authorized-code rejection, confirms an empty credential result, cancels the captured offer, and proves fresh issuance and login recovery. Failed and expired transactions must still receive confirmed cancellation.

The short expiry lane requires an explicitly isolated deployment configured for a 60- or 120-second server TTL. A returned seven-day/default lifetime blocks the lane and triggers owned cleanup; no database backdating or clock override simulates expiry. Setup is read-only except for the run-owned synthetic applications and their issuance. Configuration is compared again after cleanup.

Holder cancellation remains a mandatory native Spruce lane. The repaired contract checks the real wallet Cancel action, return to the same Chrome context, and a successful authenticated-state read showing `authenticated: false`. It removes an assertion against a nonexistent page status element. It does not claim a typed backend cancellation result or an independently checked verifier outcome beyond those observations.

### Make D09 upload success durable

The Rust Organization service now exposes `/v1/organizations/{organization_id}/offline-verification-events` using existing gateway API-key identity and the existing PostgreSQL audit store. The key must carry explicit `audit:write`; authority is derived and rechecked under the transaction. Profile-scoped keys, foreign tenants, expired/revoked keys and insufficient scope are rejected.

The receiver validates a small privacy allowlist, enforces organization-wide event/verification uniqueness, reads inserted receipts back, and commits before acknowledging. Same-producer exact retries return the original receipt. Conflicting payloads or cross-key ID reuse roll back the whole batch. A receipt proves submission and durable acceptance of a client-reported result; it is not physical-device attestation or independent credential verification.

The native reporting patch retains queued IDs until it validates the entire exact durable acknowledgement, including authenticated producer, organization, event pairing, content digest, count and timestamps. Missing/invalid/oversized 2xx responses do not erase events. Lost responses can be retried, and a concurrently queued new event survives acknowledgement of the original batch. The recorder requires the deployed HTTPS capability, absence of the receipt while offline, reconnect readback, exact duplicate replay and unchanged receipt. Queue-empty alone cannot pass. Old native binaries that ignore the new policy are rejected before the scenario.

See `docs/rust-migrations/offline-verification-ingest.md` in the UI repository and the native reporting README. The receiver, gateway, migration and native reporter changes must be deployed together for this scenario.

### Require a working signer for D10

D10 no longer has a placeholder KMS URL that can make configuration creation look like signing success. Its preflight requires actual HTTPS OpenBao origin, mount, key and token-file inputs. The UI exposes the actual OID4VP signing purpose.

The shared Rust evidence crate builds and verifies fresh ES256 challenges using `marty-crypto`, tied to the run nonce, organization, service, key reference, issuer DID, format and purpose. Both VC issuer and OID4VP request-signing purposes must pass. The adapter checks its validator bytes before and after invocation and retains public proof artifacts. No private fixture key is retained.

This is a scoped signing-capability proof; it is not an issued credential, wallet acceptance or a completed OID4VP exchange. The trace begins after provider registration and navigation, and the omitted credential-entry interval is reported explicitly. A real authorized KMS run remains pending.

## Recorder, manifest and presentation consistency

Android evidence previously emitted fields that the strict public wallet schema rejected, while the gateway could still say PASS. The producer now projects the existing public fields plus typed optional `lane_id` and `evidence_sha256`. The hash covers the exact retained evidence-file bytes. Rich device metadata, package transitions and protocol observations remain in the full hash-checked report. It is not a cryptographic attestation.

Recorder binding and gateway checks enforce the projection, preserve exact lane upsert, and reject incompatible rows. The UI and Python consumers use the canonical wallet schema rather than permissive ad hoc records; the browser consumes a checked generated projection compatible with UI-only image builds. Wallet rows display their lane and use distinct keys, so four same-build membership lanes remain distinguishable. Historical rows without the new optional fields remain valid.

The unpublished `2026.08.0` scenario revisions now match changed contracts, including the existing D11 revision-two configurations. D03's scope describes independent mdoc lanes instead of an unrelated SD-JWT claim. Published `2026.07.0` and previous audit reports are preserved.

The retained first-party wallet demo receives its own configuration and explicit internal-control contract. It reuses governed claim, actual Receive/Present and authenticated login, then checks that the closed owned session is rejected. Its scope is closed-session behavior in an internal control; public wallet and TTL claims are not inferred.

The retained independent entry now has a dedicated two-lane Spruce contract. The source review exposed real blockers in the older templates: absent browser controls, mobile logout labels, different issuance/auth wallet IDs, a nonexistent native credential-selection step, Share instead of Approve, cancellation without first provisioning the reset wallet, and expiry waits after redemption had already started. The shared flow now uses the actual product/native controls and authoritative observations. It requires a clean wallet and separate fresh synthetic account per lane, handles the product's native-intent fallback, preserves the signed request, records explicit Chrome return and reads the same browser's actual authentication state. Chooser profiles remain blocked without overriding feature detection. The supported claim does not extend to other vendors, exact formats/disclosures, automatic callback behavior or physical-device security.

The browser exposes identifiers on existing claim/open-wallet controls and the current application ID for exact correlation. A separate product fix passes the already-resolved application organization to claim dialogs, so organization-specific registry and delivery-destination entries are available through the existing services.

Each retained entry replaces one broad placeholder with four concrete observations. Together these changes increase the current assertion inventory from 60 to 66. All 66 remain `NOT_RUN`; no qualification is upgraded.

The existing `lifecycle-v1` profile remains the shared treatment for voice, narration-derived subtitles, smooth measured crops, disclosed added cursor, and numbered actor/action/outcome stories. The current plan covers all 14 scenarios and 61 beats. **All capture plans are UNBOUND.** No source coordinates, spoken timings, click events or human review are fabricated. No actual demo was rerecorded or mastered in this pass.

Final reconciliation also repaired D09's missing narration-source binding and stale loopback-receiver story. Its 12 draft cues cover the real signed synthetic DTC, offline queue, deployed receipt/readback/replay, and stale-trust rejection. The narration stays within 132 words per minute on its provisional timing grid. Source locators resolve to the current implementation; audio, measured source timing and the final master remain pending.

The retained independent scenario has eight matching draft narration/catalog cues, with a maximum of 120 words per minute. The existing narration, caption-layout, roadmap, configuration and manifest validators pass. Its raw Android recordings remain portrait. A separate labelled capture overview fits both complete recordings to the outer recorder's required landscape canvas and retains original/output hashes, media probes and font provenance. This overview is not a guided master and adds no voice, captions, crop zooms or cursor. No demo audio was synthesized and no source frames were assigned provisional click or crop coordinates.

### Correction to the previous duration finding

The previous report described 11.96 seconds as the container duration. That was incorrect: the old test interpreted the null-output progress/final-frame timestamp as duration. At 25 fps, a 300-frame clip's last frame starts at 11.96 seconds and ends at 12.00 seconds.

The repaired test encodes actual H.264 MP4 before and after padding, then uses ffprobe for frame count, stream/format duration, cadence and every frame timestamp. The padded fixture is exactly 300 frames, 25 fps and 12.00 seconds. The unpadded comparison has fewer frames. All 19 composer cases pass. The production filter did not need alteration, and this generated fixture is not a Marty release video.

## Current scope across the catalog

| Demo | Source available in this package | Remaining qualification or implementation |
| --- | --- | --- |
| D01 Passport pre-boarding | Prior real console approval/invite and native specimen path, shared wallet isolation | Actual native/deployed run; specimen scope does not claim NFC/liveness or a physical booklet. |
| D02 Stable issuer / KMS | Prior real rebind action, signatures and guarded denial | Actual configured providers and release-bound key/publication evidence. |
| D03 Private age proof | Dedicated native lanes, Rust receipt/disclosure checks, exact UI results | Pinned native builds, governed mDL fixtures, issuer-specific denial and fresh recordings. |
| D04 Employee access | Prior console approval/invite and actual suspension consequence, isolated wallet | Fresh deployed allow/deny and capture. |
| D05 Membership login | Repository-owned denial/recovery drivers and explicit native cancellation | Governed fixtures, isolated TTL lane, actual Spruce handoff/cancel and fresh media. |
| D06 Lifecycle | Pinned live IPC wiring, Rust session isolation, shared exact cleanup, existing real lifecycle UI/lineage | Fresh deployment-bound lifecycle run and exact-master voice/video review. |
| D07 Canvas achievement | Existing portability path with explicit imported supporting evidence | Actual stock Canvas and visible same-source negative execution remain unqualified. |
| D08 External evidence | Existing conversion path with explicit source attestations | Real external evidence and fresh visible failure outcomes. |
| D09 Offline facility | Durable Rust receiver/native ACK plus real backend adapter | Deploy the coordinated changes, migrate, then run actual native offline/reconnect. |
| D10 Organization primitives | Actual KMS prerequisites and Rust signing challenges | Real KMS and UI capture; signing capability alone does not prove issuance. |
| D11 Admissions/webhooks | Existing four revision-two positive/negative contracts, aligned draft | Fresh real callback, duplicate, scope and signature rejection evidence. |
| D12 Passport issuance evidence | Protected simulator receipts and explicit claim boundary | Physical booklet verification is not claimed; recording-free qualification remains unsupported. |
| Retained first-party wallet | Dedicated first-party control configuration using the shared complete path | Fresh capture; closed-session rejection does not qualify a public wallet. |
| Retained independent wallet | Dedicated pinned Spruce receipt, unchanged request, authenticated return and provisioned cancellation lanes | Fresh two-lane native capture; supported native-intent profile, distinct fresh accounts and real deployed services required. |

## What was verified

Focused evidence includes real local Rust HTTP operations, a compiled-wallet/Chrome integration, three real PostgreSQL migration/transaction tests, Rust signature verification against generated public fixtures, actual React components with controlled service responses, and recorder producer/consumer contracts. D03 has 61 named passing cases; D09 has 61 unique cases across 68 executions; D10 has 77 passing named cases. Wallet verification contains five Rust session cases, one actual HTTP case, one Chrome probe with five checks, five browser-adapter cases and 36 lifecycle cases. D05, retained-wallet and schema-consumer counts and commands are retained in their separate evidence files.

Four additional native-overview checks use actual FFmpeg and ffprobe with explicitly synthetic portrait inputs. The encoded VP9 WebM passes the existing 1920-by-1080 capture gate at 30 fps. Both raw files retain their hashes; their lane order and combined duration are checked. Low-rate sources, substituted inputs, reused output and encoder failure prevent success. This validates the media adapter, not native-wallet execution or a new demo video.

These areas overlap in shared helpers and configuration suites, so they are not added into an inflated portfolio-wide total. Generated fixtures, injected responses and native/deployed prerequisites are identified in each record.

The final [source reconciliation](evidence/source-evidence-reconciliation.json) covers 15 records and 251 hash observations. Of these, 227 match current bytes and 24 remain explicitly historical differences with reviewed later follow-ups. No source is missing and no difference is unexplained. Historical test results are preserved at their original scope; metadata-only checks do not retrospectively turn earlier records into proofs of current runtime behavior.

The **production TypeScript configuration passes**. An inadvertent broad `tsc --noEmit` using the test-source configuration failed with 1,520 diagnostics. No baseline comparison was executed, no test typing configuration was weakened, and no full test-source typing pass is claimed. The compact diagnostic record is [retained](evidence/ui-typecheck-summary.json). This pass does not claim a full application bundle build or Docker/native GUI build.

At the attribute-only checkpoint, two control identifiers and the dialog's application ID were added to existing elements; removing those three attribute lines reproduced the original component bytes exactly. Existing component suites returned eight passes and five MUI focus-restoration teardown failures. Running the same suites in a clean detached worktree at the exact pre-change revision reproduced the same five named failures and eight passes. That focused [baseline comparison](evidence/native-control-ui-verification.json) is retained separately from the broad TypeScript result. The later organization-propagation fix passes all nine ApplicationForm tests, after its new cases first reproduced two propagation failures; its before/after logs and exact source hashes are [retained](evidence/native-claim-organization-verification.json). No test configuration or production focus behavior was changed, and the failing complete component suites are not reported as passing.

## Git delivery and application

Four repositories change: `marty-ui`, `marty-demo-recorder`, `marty-core` and `marty-verifier`. The Python `Marty` repository is unchanged. Local branches preserve the previous audit and lifecycle work; nothing was pushed, deployed or published.

The download provides cumulative and incremental alternatives for main UI and lifecycle UI, recorder alternatives, and separate core/native patches. Choose one UI lineage and one cumulative/incremental option per repository. All eight supported patch series are replayed into disposable worktrees and checked against exact expected trees. Four bundles preserve genuine UI/core/native Git ancestry.

The private recorder boundary improves on the earlier selected-source snapshot: all **453 blobs and 52 directories** now match the exact upstream tree at `64c9bc986185b53bdcb1dd3d383787ad94fe931a`. Full source application is verified. Private upstream commit history was not imported, so the synthetic reconstruction baseline is excluded and no recorder bundle is delivered.

The lifecycle variant applies this pass's delta while preserving other lifecycle-branch work. Exact final heads, prerequisites, source trees, branch-preservation proof, patch lists and SHA-256 checksums are in the archive. Patches may produce different local commit IDs; recording/deployment inputs must bind the actual applied checkout revisions and bytes. Source application success is distinct from running a deployed demo.
