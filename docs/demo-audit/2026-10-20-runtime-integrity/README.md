# Marty / ElevenID — demo runtime integrity repairs

**2026-10-20 UTC. This continuation repairs additional application, recovery and recording defects. Local checks establish the behavior described below; they do not qualify a deployed demo.**

This audit continues the [production gap repairs](../2026-10-20-production-gaps/README.md). New implementation changes are in `marty-ui` and `marty-demo-recorder`. The previous `marty-core` wallet isolation and native verifier acknowledgement changes remain required where their scenarios use them; they have not changed in this pass. The Python Marty repository is unchanged.

The portfolio still has **19 recording configurations for 14 DRAFT scenarios, 66 NOT_RUN assertions and 61 UNBOUND presentation beats**. Both release readiness flags remain false. Current and published manifests are preserved. The lifecycle branch receives the same repairs while retaining its other work; the download records exact branch heads, source trees and patch replay results.

The [Codex worker handoff](CODEX_HANDOFF.md) gives the next worker the objective, Git starting points and prioritized follow-up. The [gap tracker](gap-tracker.json) records the repairs and corrects two earlier conclusions. D07/D08 require additional recorder source integration as well as live evidence. Also, the native applicant claim route does not implement holder destination selection or optional Canvas Credentials mirroring; the dialog now reflects that actual contract.

## Rust owns issuance state and lifecycle safeguards

### Withdrawal cannot hide an active offer or issued credential

Organization withdrawal previously changed an application to WITHDRAWN even when an offer or credential remained live. Reconciliation then ignored withdrawn applications, allowing an active issuance path to disappear behind application status.

The shared Rust withdrawal helper now evaluates both organization and applicant requests under the same store write lock used for state mutation. It rejects withdrawal at the approval/issuance boundary, when an offer or credential exists, or when active, retained or uncertain attempt metadata requires reconciliation. A denied request returns HTTP 409 and does not persist a status change. Safe earlier organization review/rejection withdrawal remains available; applicant withdrawal retains its stricter domain transitions.

Withdrawal does not stand in for transaction cancellation or credential revocation. The organization withdrawal endpoint lacks the authority and operations to perform those actions. The repair preserves that distinction rather than silently revoking resources. Historical withdrawn applications are not rewritten.

Evidence: [withdrawal verification](evidence/applicant-withdrawal-verification.json), subsequently included in the final [42-case applicant verification](evidence/applicant-reconciliation-verification.json).

### Claim capabilities and pending offer reuse are explicit

The previous Rust holder claim handler ignored its request body, while the dialog sent destination and Canvas consent options. The actual applicant-to-Flow issuance contract did not implement those choices.

After authenticating the holder and application, the handler now accepts an empty body or `{}`. Unsupported options or a non-object JSON value return HTTP 422 with `CLAIM_OPTIONS_UNSUPPORTED`; malformed JSON returns HTTP 400 with `INVALID_CLAIM_JSON`. Errors do not echo submitted values. Existing no-options callers continue to work.

Application read and claim responses expose the same capabilities:

| Capability | Native claim route |
| --- | --- |
| OID4VCI wallet issuance | Supported, subject to application eligibility |
| Holder delivery destination selection | Unsupported |
| Optional Canvas Credentials mirror selection | Unsupported |
| Offer reuse | Pending offer reused until consumed or expired |

Capability is not eligibility: application status, claim state, blockers and expiry continue to govern the claim. The dialog removes unsupported options and sends a no-options request. Opening the dialog or changing wallet transport no longer implies a newly generated offer.

### Late asynchronous results cannot overwrite the current offer

Two different races are repaired in Rust. First, the service shares one immutable offer identity definition between persistence and completed-attempt comparison. An exact duplicate completion may return the current application without rewriting a subsequent CLAIMED or EXPIRED projection. A changed identity or active attempt still conflicts. A late `NoActiveFlow` response must match the active attempt before it can block a claim.

Second, each asynchronous transaction read now carries the transaction ID it actually observed into reconciliation. Rust compares that ID with the application's current binding under the store write lock before any expiry, applicant or application mutation. If reissue has replaced the transaction, a delayed old revoked/issued response returns the current application unchanged and performs no persistence.

The second race was reproduced with a real local HTTP interleaving: the synthetic issuer held an old transaction read while the actual operator `/issue` route completed a replacement. Both delayed revoked and issued responses previously corrupted the replacement projection. The repaired tests preserve it. Current-transaction reconciliation still works, and a stale missing-transaction binding also cannot expire a replacement.

Pre-reservation snapshot conflicts may still return 409. This change does not promise that every simultaneous request succeeds or that all distributed operations are atomic. The dialog also coalesces its own pending claim requests.

Evidence: [claim contract and completed-attempt verification](evidence/applicant-claim-verification.json) and [transaction-bound reconciliation](evidence/applicant-reconciliation-verification.json).

## Wallet selection, handoff and receipt now agree

The claim dialog tags wallet catalogues, selections, offers and errors with the current application, organization and holder. It waits for the correct catalogue before acquisition, shares a pending request across close/reopen, and discards late results from previous scopes. Wallet selection changes the selected transport without requesting issuance again. Refresh hides the old actionable invitation while waiting and after failure; retry requires an explicit action.

The open dialog observes the authenticated application through read-only status requests. It polls every two seconds while visible and nonterminal, coalesces browser return events, and checks application and organization identity. Server-confirmed CLAIMED, EXPIRED or BLOCKED states replace the active QR. Failed or mismatched readback removes the actionable invite and exposes retry. These reads never request a new offer.

Both claim responses and raw application reads use one normalization helper. This retains `credential_offer_uri` as the displayed offer URL and `offer_expires_at` as the countdown expiry. The raw GET shape previously lost the countdown after status refresh.

Mobile and desktop use the same `useWalletOpenLink` hook. It coalesces repeated clicks before React renders disabled state and invalidates pending navigation when the view closes, unmounts, changes application, wallet or offer, or observes confirmed receipt. It preserves the existing wallet-specific fallback selection instead of replacing it with a generic protocol URI. The tests cover the actual invitation and QR components as well as the parent dialog.

Email wording now describes opening a `mailto:` draft. It does not claim that an email has been sent. Existing focus restoration is preserved; the test fixture now opens the dialog from a real focused button rather than removing the element MUI needs during teardown.

Canvas's application form separately refreshes its read-only evidence projection when the claim dialog closes or the browser returns. Concurrent reads are coalesced, late results and listeners are cleaned up, and failed reads clear stale claim availability. Only the server's `claim.status = claimed` renders completion. Returning from a canceled wallet or closing a dialog does not create a receipt.

Evidence: [19-case parent verification](evidence/claim-dialog-runtime-verification.json), [12-case real child verification](evidence/ui-wallet-open-child-verification.json), [shared opener review](evidence/ui-wallet-open-parent-review.json), and [15-case Canvas return verification](evidence/canvas-claim-return-verification.json).

## Owned cleanup preserves application history and supports D05 recovery

The safer Rust withdrawal behavior exposed an incompatible assumption in demo cleanup: revoking a credential had been followed by requiring application withdrawal. The shared resource adapter now treats these as different lifecycle operations. An issued run-owned credential must have a confirmed revoked public record, while its exact application history remains preserved. Lost revoke responses may be recovered only through authoritative readback.

For an unused offer, the helper proves exact transaction ownership and confirmed revocation, reads the transaction detail, and proves no issued credential exists. The list projection deliberately omits issuance timestamps, so list rows alone cannot establish that an offer was unused. Unknown, active, issued, foreign or ambiguous history keeps cleanup incomplete. Truly unissued applications can still use ordinary withdrawal; a refusal is not converted into success.

D01 and D04 now require confirmed credential revocation and preserved application history. D05 recovery uses the existing operator issue route on the same application. It no longer depends on withdrawing an OFFERED application so another application can be created.

D05 retains the exact old transaction tuple in a run-owned ledger and revalidates it before excluding that transaction from discovery. It requires exactly one fresh transaction with matching ownership, rejects unexplained extras or reuse, and binds the returned offer to the public offer for that transaction. The first-run duplicate guard remains strict. A lost issue response is resolved only when the observed application/transaction/offer provide the complete current binding; otherwise recovery remains incomplete. Recorder driver pins are refreshed to these exact reviewed source bytes.

These are public API transport and correlation adapters. Rust remains responsible for authorization, issuance, signing, transaction state and reconciliation. The controlled driver tests do not claim a live beta run or wallet login.

## The shared recording path handles real source geometry and clocks

### Native portrait recordings remain native inputs

The sequential composer now accepts portrait device recordings using a shared validator: at least 1080 × 1920 pixels, 9:16 and at least 24 fps. Existing primary, split and picture-in-picture source requirements remain in force. The independent capture overview shares the portrait checks while retaining its stricter exact-size requirement.

The composer uses the raw device dimensions and source clock for crop and pointer measurement. It does not infer synchronization with a browser recording. Original source hashes are retained and rechecked.

### A pointer document must identify its actual recording and event

Previously an arbitrary file with a matching hash could satisfy a pointer evidence reference. A new composition now requires a bounded, versioned `MARTY_EDITORIAL_POINTER_MEASUREMENTS` document identifying the selected recording's filename, SHA-256 and dimensions, plus the exact event ID, coordinates, control window and response bracket. Unknown fields, duplicate or missing IDs, mismatched geometry, unsafe paths and substituted sources fail. Evidence and source identity are checked before and after rendering.

The report states `SOURCE_AND_MEASUREMENT_IDENTITY_ONLY`. This establishes which source and measurement were used; it does not independently prove that the described control was clicked or that a business outcome happened. The added cursor retains its editorial reconstruction disclosure. Visual meaning still requires inspection of the original video. Existing historical pointer evidence is preserved, but it is not silently accepted for newly composed guided videos.

### Output timing uses one integer frame budget

Segment and slate durations now resolve once to whole frames at 25 fps. Chapter ranges, captions, crop/pointer mapping and final output use that same budget. Requested durations remain in the report; for example, a requested 10.5 seconds becomes 263 frames, or 10.52 seconds. Segments that round below seven frames fail with explicit minimum-duration guidance. The final encoded stream is checked against its declared duration and frame rate.

This repairs a different problem from the prior final-frame-PTS test correction. The previous implementation could declare twenty 0.26-second segments as 5.2 seconds while encoding 140 frames, or 5.6 seconds. That drift was independently reproduced before the change.

The final synthetic integration fixture encodes **176 frames at 25 fps, exactly 7.04 seconds**, with a portrait source, crop motion, an added click pulse and a reserved subtitle band. Pixel checks verify the enlarged control, pulse onset and caption placement. Its audio is a generated sine tone. It is not a human voice, native wallet recording or production feature demonstration.

Evidence: [54-case media verification](evidence/media-runtime-integrity-verification.json), exact [commands and source hashes](evidence/media-final-test-verification.json), and the explicitly labeled [synthetic fixture](evidence/synthetic-native-guided/SYNTHETIC-TEST-ONLY.txt).

## D07 and D08 still need a complete recorder adapter

The existing production Canvas controls and Rust evidence/approval paths are present. The shared recording definitions do not yet connect all of them: actual LTI Continue/bootstrap binding, evidence job completion, scoped approval between unsigned pending and ready-to-claim states, wallet receipt and verification, and fresh correction/denial/recovery operations.

Imported portability cases do not bind the application, operation or wallet receipt visible in a new recording. The recorder now rejects attempts to assign a current assertion ID to those imported cases, both during preflight and at the action boundary, with `CANVAS_CURRENT_RUN_EVIDENCE_REQUIRED`. Prerequisite-only inspection and dry-run remain available. Receipt-shaped JSON or environment values cannot bypass the guard.

The reusable stock Canvas contract contains real navigation, synchronization, approval, grade correction and protocol receipt/verification operations. Its protocol client is not a captured native wallet UI, and its assignment popup needs real recording coverage. A later adapter must reuse those actual paths and bind the resulting operations to the same recorded scenario. Adding success-only elements or reusing an old report would leave the functional gap open.

The corrected PG-15 status is **OPEN_SOURCE_AND_LIVE_EVIDENCE**. This pass closes false assertion promotion, not the missing full D07/D08 recording adapter. Evidence: [15-case prerequisite guard verification](evidence/canvas-prerequisite-guard-verification.json); detailed source mapping is included in the recorder's `docs/canvas-capture-source-gaps.md` and the download's review directory.

## Verification and remaining production requirements

The [verification index](verification.json) records exact commands, logs, source hashes, overlap and fixture boundaries. Historical before/after records remain unchanged. [Source reconciliation](evidence/source-evidence-reconciliation.json) checks 291 source-hash assertions: 271 match current bytes, 18 match verified historical revisions, and two explicitly identify one baseline test snapshot that was hashed before formatting but not retained in that exact byte form. All 56 artifact-digest assertions match, with no missing or unexplained issue. This metadata check does not turn historical tests into new runtime evidence.

The final applicant gate passes **42 cases** across application, HTTP, issuance and domain behavior. That includes all earlier 31- and 38-case gates; those totals are not additive. The final parent/real-child UI command passes **31 cases**, comprising 19 parent and 12 child cases. Canvas return has its separate 15 passing cases. Media has 54 passing cases and the Canvas guard has 15. The shared helper and D01/D04/D05 drivers pass 74 cases (33 shared, 9 passport, 8 employee and 24 membership), and the recorder configuration passes 11 cases plus two exact driver pin/schema checks. Commands and hashes are retained in the [owned retirement record](evidence/owned-retirement-verification.json). Production TypeScript passes with `tsc -p tsconfig.build.json --noEmit`.

Controlled service responses, local HTTP fixtures and generated media establish the repaired source behavior. No new full application build, broad test-source TypeScript pass, Docker/native GUI build, deployed KMS run or production wallet execution is claimed. Earlier broad TypeScript diagnostics remain disclosed in the previous audit.

Production qualification still requires matching deployed revisions and governed fixtures; real successful and negative/recovery runs; fresh source capture; measured crop and cursor binding; recorded narration and subtitles aligned to the final frame timeline; and review of the exact master by watching and listening. Native automatic server retirement remains unperformed. D10 external KMS and D12 physical-booklet/hardware requirements are unchanged. No historical or synthetic media has been promoted into a current demo result.

## Git application

The download contains this pass's incremental patches and cumulative alternatives for the main UI, lifecycle UI and recorder. It also carries the unchanged core/native prerequisite repairs for users applying from the original upstream bases. Choose one UI lineage and one cumulative or incremental series per repository. Do not apply both alternatives to the same checkout.

Every supported patch series is replayed into a disposable checkout with `git am --3way`; the result must be clean and match the expected complete source tree. Lifecycle preservation is checked by exact blob and file-mode equality outside this pass's delta. Four bundles retain genuine UI/core/native ancestry. The recorder source baseline matches all 453 private upstream blobs and the exact tree, but private commit history was not imported: no synthetic reconstruction commit or recorder bundle is delivered.

The archive's `APPLY.md`, `BASELINES.json`, commit lists, verification files and checksums contain the concrete application instructions and final identities. Applied patches may receive different local commit IDs, so subsequent capture and deployment inputs must bind the actual applied checkout. Nothing was pushed, deployed or published.
