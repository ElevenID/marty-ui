# Marty / ElevenID: lifecycle alignment and production-path audit

**Date:** 2026-10-20 UTC. **Status:** local repairs verified; current-release qualification and actual demo renders remain pending.

**No: the current catalog does not establish that every demo demonstrates a successful production path.** The `2026.08.0` manifest contains **14 DRAFT scenarios and 60 NOT_RUN assertions**. It has no release-bound media, `PENDING_DEPLOYMENT` binding, and both readiness flags are false. The older `2026.07.0` catalog has public membership, organization, and lifecycle demonstrations; their historical evidence does not automatically qualify the new release. DRAFT is an evidence state, not proof that a feature is broken.

This continues the [second functionality audit](../2026-10-20/README.md). It responds to the request to match the lifecycle demo's voice, subtitles, zoom, cursor clicks, clear scenarios, and real production paths. The [alignment tracker](alignment-tracker.json) records individual repairs and scenario gaps. [Verification](verification.json) distinguishes local tests from live qualification; [source references](source-references.json) pin the reviewed code and lifecycle recipe.

## Lifecycle reference and shared treatment

The UI reference is `demo-lifecycle-live-v258-20261019` at `50f314fdcb29f12a0a606ec3c2a8fb144111d1cf`. The recorder reference is its retained D06 campaign at `64c9bc986185b53bdcb1dd3d383787ad94fe931a`, specifically the 122-second `beta-pr1425-7406b9d5a4c3-ui-actions` edit. The UI actions and editing recipe were inspected. The actual retained master and uncut video were not downloaded or viewed.

The shared recorder profile is **`lifecycle-v1`**. Its executable adoption command and input contract are in the recorder's `docs/lifecycle-presentation-profile.md`.

| Requested feature | Implemented common behavior | Remaining evidence |
| --- | --- | --- |
| Voice | Existing local narration provenance and mastering, `marty-neutral-1` / `af_heart`, and the existing caption-speed ceiling | The reference voice is provisional. Each actual render needs listening and comprehension review. |
| Subtitles | Bind the exact narration-input VTT to its audio provenance; derive spoken cue display times and use a reserved band below the product view | Complete source-specific scripts and review the finished timing. The two corrected D05 negative cues remain draft summaries. |
| Zoom into crop | Begin with source context; require explicit measured camera transitions for every focus crop, using existing geometry/dwell checks | Measure each new recording's actual coordinates and source ranges. |
| Cursor clicking | Shared drivers retain real action landmarks; the composer requires source-bound reconstructed pointer evidence and the persistent “Guided replay - Added cursor” marker | Driver time is not video or OS-click time. Align the pointer to visible source responses before rendering. |
| Clear scenarios | Actor, business reason, before/after consequence, and ordered numbered stages; readable roadmaps with one through six stages | Each demo's drafted story still needs source footage and exact-master review. |
| Real production paths | D01/D04 main journeys now show real reviewer controls; D02 shows the real rebind control; D06 shows actual lifecycle controls and renewal lineage | Setup/API checks remain labeled. Native, external-service, wallet, and deployment prerequisites must succeed in their actual environments. |

The profile hashes the actual source recordings and run report before and after composition, checks the declared timeline, and leaves the result `DRAFT_AWAITING_EXACT_MASTER_REVIEW`. A valid composition does not establish a successful business outcome. Its report explicitly says `NOT_EVALUATED_BY_COMPOSITION`.

## Functional repairs

### Real review and issuance in D01 and D04

The passport-clearance and employee main journeys now click **Approve → enter the approval note → Confirm Approval → Display OID4VCI Invite** in the actual console. They wait for the exact response and application state, then bind the issued credential to the owned application and public issuance transaction. The same main path runs with recording enabled or disabled. Existing helper-only API entry points remain for compatibility.

The recording adapter requires the deployed issuance hook before creating the one-time offer and masks QR output before display. Fixture application creation/submission and API verification results remain explicit in the report. The D01 narration describes wallet receipt plus the issuer's passport-evidence binding; it does not claim an unexamined disclosed-claim set or a digest extracted from wallet-signed material.

### Guard every claimed result

D02 includes readable holds and action landmarks around the real provider-rebind control and confirmation. It checks the specific completed stage before displaying success language. Its negative unpublished-key attempt remains an authenticated API test.

D06 now requires initial active/allowed verification, shows both the revoked predecessor and renewed successor link, and checks each lifecycle HTTP response, exact observed state, completed wallet session, and expected allow/deny decision before success narration or another mutation. Recording explanations use the actual business reason entered into the dialog. Prior exact ownership, uncertain mutation accounting, and cleanup protections are preserved.

The lifecycle entry point now requires the recorder-owned live evidence transport and source-bound fixture inputs. A standalone run without that transport fails preflight. It cannot produce a successful live-evidence report from a local substitute endpoint. Completion is finalized only after cleanup, recording/browser finalization, and the final report.

### Product UI issues adopted and repaired

Three frontend corrections from the lifecycle branch are included: the organization reviewer uses its `/issue` endpoint; lock handling uses `ACTIVE` and `holder_user_id`; and logout cancels identity refresh work before submission.

This review found an additional issue: valid wallet-specific invitations were rejected when the backend returned a nonempty `credential_offer_uris` map without a default `offer_url`. The panel now accepts either supported shape, including regeneration, without inventing a default URL. Approval copy now distinguishes approval from creating the subsequent wallet invitation.

### Complete portfolio plan

The recorder's `demos/lifecycle-alignment.json` covers **all 14 scenarios**, the **12 numbered acceptance contracts**, and **61 ordered story beats**. Each entry identifies the actor, goal, real controls/API surfaces, positive and denial evidence, dependencies, and remaining gaps. Its 14 capture plans are explicitly **UNBOUND**. They are planning data and cannot be passed to the composer as measured footage.

Two five-second membership denial cues were reduced from 17 to 11 words, bringing each from **204 to 132 WPM** while retaining the explicit untrusted-issuer or expired-offer reason and original timings.

## Production coverage by scenario

Every row below still needs fresh evidence for the current catalog. “Implemented” refers to inspected source or locally verified changes, not a new production run.

| Demo | Implemented or retained path | Material gap or claim boundary |
| --- | --- | --- |
| D01 Passport pre-boarding | Native specimen checks, new console review/invitation, wallet and gate verification | Current specimen lane disables NFC/liveness; requires release-bound Windows/native and deployed beta evidence. |
| D02 Stable issuer / KMS | Real console rebind plus public issuance and signature checks | Needs actual configured signing providers and fresh key/publication evidence. Provider B is OpenBao transit, not an all-vendor claim. |
| D03 Private age proof | Android gateway and age-proof lane infrastructure | No dedicated current demo driver/config. Minimal disclosure and independent-wallet positive/denial paths remain unqualified. |
| D04 Employee access | New console review/invitation; actual suspension control and active/denied verification | API application setup remains explicit; requires a fresh deployed run and recording. |
| D05 Membership login | Existing positive flow and separate denial scenarios | Negative UI drivers are externally pinned; required Android lanes and complete source-bound captions/renders remain pending. |
| D06 Lifecycle | Real renew/suspend/reinstate/revoke controls, initial allow, both renewal records, guarded results | Requires the recorder-owned live transport, a fresh deployment-bound run, and exact-master/voice review. |
| D07 Canvas achievement | Existing portability report and supporting evidence paths | Imported negative attestations are not all performed onscreen; the legacy Canvas walkthrough does not qualify real stock Canvas OSS. |
| D08 External evidence | Existing credential conversion and portability evidence paths | Imported attestations/supporting evidence need same-source execution and real footage for the stated story. |
| D09 Offline facility | Native offline/queue flow with reconnect delivery | Reconnect upload currently targets a recorder-owned loopback collector, not a deployed production audit backend. |
| D10 Organization primitives | Real organization console CRUD and configuration | Default `https://kms.audit.invalid/transit` proves configuration creation, not a working external signer. |
| D11 Admissions / webhooks | Gateway and signed callback positive/negative lane definitions | Needs fresh actual callback, duplicate, scope, and invalid-signature runs plus their recordings. |
| D12 Passport issuance evidence | Source-bound simulator flow with protected positive/negative receipts | Simulator evidence does not establish physical-booklet verification. Recording-free qualification remains unsupported. |
| Retained first-party wallet | Historical internal control path | Public isolation/expiry remains unqualified and has no dedicated fresh recording configuration. |
| Retained independent wallet | Existing interoperability/Android qualification infrastructure | Historical final DCQL lane is blocked; issuance-only acceptance cannot establish full current interoperability. |

The prior audit's shared-wallet reset/revocation-profile concurrency boundary also remains open. No new work silently relaxes the cleanup, source identity, signed receipt, privacy, or publication requirements.

## Verification and practical limits

**129 unique focused local tests passed:** 31 UI tests, 33 lifecycle tests, 53 other recording/ownership/journey checks, one additional real-Chrome intercepted fixture, and 11 presentation-profile tests. TypeScript checking and whitespace/parse checks passed. The browser fixture uses actual controls with intercepted service responses; it does not contact beta.

The profile test produced an **11-second, 2560 × 1440, 25 fps generated fixture** with six stages. The roadmap, caption-band, and focused-action frames were visually inspected. The input is generated test bars and a tone; this is composition evidence, not a Marty demo or a test of the provisional voice's sound.

The retained composer/roadmap compatibility suites passed **20 of 21** cases. The remaining duration check fails identically with the original prior source: the correct 300 frames are reported as 11.96 container seconds instead of the test's 12.00 seconds. The retained baseline output is [included](evidence/baseline-compose-compatibility.txt). This inherited discrepancy remains a follow-up; the complete compatibility suite is not reported as green.

No full production build was rerun in this pass; the preceding report records its own build. No fresh authenticated beta, native, independent-wallet, external KMS, or physical passport qualification was performed. No actual demo was rerecorded or rerendered, and no voice, deployment, publication, or catalog assertion was upgraded.

## Git delivery and next recording work

The download contains cumulative and incremental patch alternatives, exact source baselines, commit lists, checksums, and patch-application verification. Use one alternative per repository. The public UI bundle preserves real Git ancestry. The private recorder changes are patches against an exact 129-file selected upstream snapshot; the synthetic local baseline is excluded, and no recorder bundle is supplied. Full private-checkout application remains unverified.

Where the package provides a patch based on the lifecycle reference, that alternative preserves the branch's additional native/backend changes. The original-main audit variant contains selected frontend and demo ports; it does not incorporate every backend change from the reference branch. See the package's `APPLY.md` for exact starting revisions.

For a real delivery sequence, first capture D06 and D04 with the repaired UI and recorder transport, then apply the measured `lifecycle-v1` recipe to those recordings. Use the existing plan to work through membership, signing/organization, callbacks, native/offline, portability, and independent-wallet cases. Keep successful positive results and intentional denials in the same clear business story. Review each exact master before upgrading its evidence state.
