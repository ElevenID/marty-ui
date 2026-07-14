# ElevenID LLC Credential Platform Demos and Release Evidence

## Status

The production application, public manifest contract, and local recorder tooling are implemented. **Credential Lifecycle Foundation** is published as a `DRAFT` evidence preview for **ElevenID LLC Credential Platform v2026.07.0**, with `PARTIAL` coverage and MIP `0.3.1` metadata.

The preview does not claim release-level public-demo approval. The ElevenID LLC YouTube channel and release playlist are configured, and the **Organization and MIP Primitives** scenario has completed ElevenID LLC publication review with privacy-enhanced playback. Remaining scenario recordings, the isolated ElevenID Demo Wallet package, independent-wallet qualification, portable Canvas execution, and a composed lifecycle video remain release evidence work.

Local media composition and privacy scanning are ready with FFmpeg, ffprobe, Tesseract, and in-process ZXing QR decoding.

## Public Routes

```text
/demos
/demos/{version}
/demos/{version}/{scenario}
/demos/latest/{scenario}
/demos/manifests/index.json
/demos/manifests/{version}.json
```

`latest` resolves only to the approved ElevenID LLC platform version recorded by `latest_approved_stack_version`. While no release is approved, it presents a link to the newest evidence preview instead of silently treating a draft as current production evidence.

## Authority Boundaries

- The ElevenID LLC platform version controls release URLs, selection, supersession, playlists, and publication.
- Every version has a descriptive `release_name`; the current release is **Credential Lifecycle Foundation**.
- MIP version records protocol compatibility and does not determine the ElevenID LLC platform version.
- The technical `stack_version` manifest field binds source revisions, container digests, deployment marker, recorder revision, wallets, assertions, media, and evidence hashes.
- Protected evidence remains authoritative. YouTube is a distribution copy whose transcoded bytes are not used as the evidence hash.
- A first-party wallet cannot satisfy independent-wallet coverage.

## Third-Party Wallet Media Policy

- Third-party wallet names, marks, and limited interface footage may be shown for interoperability testing, compatibility commentary, comparison, documentation, and product education.
- ElevenID LLC does not require vendor approval before publishing this independent coverage and does not imply affiliation, sponsorship, or endorsement.
- Demonstrations must use unmodified standards requests, accurately identify the wallet and tested build, distinguish observed results from ElevenID LLC claims, and avoid exposing private or credential material.
- Wallet providers may request review or removal through `sales@elevenidllc.com`. ElevenID LLC will promptly assess good-faith requests and may remove or revise the affected demonstration.
- This is the project publication policy for limited fair-use material; specific disputes should still receive legal review.

## Promotion Gates

1. Validate the manifest with `python scripts/validate_demo_manifests.py`.
2. Build and deploy the coordinated ElevenID LLC platform release from pinned revisions and digests.
3. Require the deployed release probe to match the ElevenID LLC platform version, MIP version, marker, and every image digest.
4. Record required impacted scenarios with no skipped outcomes or unexplained browser/network failures.
5. Complete the independent-wallet qualification lane for coverage claims; vendor permission is not a publication gate.
6. Compose 1080p video, review the single-source transcript/captions, and scan text, frames, OCR, and QR payloads.
7. Confirm every displayed offer has expired.
8. Upload to the platform-version YouTube playlist as unlisted and verify processing, embedding, captions, and thumbnail.
9. Complete editorial review and run the evidence-bound scenario approval command. It records the review-file hash and promotes only the exact unlisted scenario to `PUBLIC`.
10. After the technical release gate passes, run the release approval command to update the release manifest and version index together with rollback on write failure.
11. Set release coverage to `COMPLETE` only when all six required scenarios are public and independent-wallet evidence passes.

Run the pinned public browser gate from `tests` with `npm run test:demo-platform`. This avoids selecting a different Playwright installation from another workspace package.

## Current Blockers

- Android tooling is absent: Android SDK/ADB/emulator, Appium UiAutomator2, and a pinned EUDI reference-wallet APK/profile.
- The Google OAuth app remains in Testing mode. Its publisher refresh token is short-lived until the app completes the production-readiness process.
- Existing browser recordings predate the versioned recorder and are retained only as protected preview evidence.
- Canvas has a portable scenario contract, but the adapter implementation must expose the portable test outcomes before recording.

These blockers keep coverage `PARTIAL`; they do not change the underlying ElevenID LLC platform release decision.

## YouTube Setup

The release manifest carries a fail-closed `video_distribution` binding. ElevenID LLC Credential Platform v2026.07.0 is bound to channel `UCjUbog1b4zEdck5pV78EgCw`, handle `@elevenidllc`, and unlisted release playlist `PLH1b0jTIP3-4`. Channel phone verification is complete, and YouTube accepted the release thumbnail, reviewed captions, and 1440p rendition for Organization and MIP Primitives revision 2 at video `GK7GbqBCwQ8`. A draft may use `PENDING_CHANNEL_SETUP`; any `YOUTUBE_UNLISTED` or `PUBLIC` scenario requires a verified `ElevenID LLC` channel ID, handle, canonical channel URL, owned release playlist, privacy-enhanced embedding, and verification timestamp.

The version-controlled `marty-demo-recorder` tooling provides credential-safe status reporting, local PKCE authorization, exact channel verification, idempotent release-playlist creation, binding promotion, release/scenario-bound unlisted upload, privacy-scan hash verification, caption and thumbnail publication, processing checks, playlist ownership checks, and fail-closed `YOUTUBE_UNLISTED` scenario binding. The binding preserves the exact video, captions, thumbnail, privacy-scan, and publication-config hashes as public media-integrity evidence. Google sign-in, channel ownership, recovery, and phone verification remain owner-controlled actions and are never stored in the repositories.

`youtube:import-client` discovers only Google Desktop app credentials in Downloads, ignores Web credentials, suppresses client values and filenames, and refuses ambiguous selection or replacement of a different local credential. The owner setup sequence is `youtube:import-client`, `youtube:auth`, `youtube:setup`, and `youtube:promote`; each command must finish before the next one begins.

The current external Google OAuth app is configured for testing. Google documents that refresh tokens issued to external testing apps with non-basic scopes expire after seven days. Move the app through production readiness before unattended publication depends on a durable token; until then, reauthorization is an expected local maintenance action. Channel phone verification is separate and was completed by an owner before custom-thumbnail publication.

`npm run youtube:status -- --manifest ../marty-ui/ui/public/demos/manifests/2026.07.0.json` reports the next setup action without printing OAuth values. Upload results can only bind to an exact `VALIDATED` scenario revision. `youtube:approve-scenario` then requires complete assertion evidence and an eight-check editorial approval artifact before public scenario promotion. `youtube:approve-release` separately requires technical release readiness and updates the release manifest and latest-approved version index together with rollback on write failure.
