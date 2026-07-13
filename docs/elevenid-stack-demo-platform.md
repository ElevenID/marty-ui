# ElevenID LLC Credential Platform Demos and Release Evidence

## Status

The production application, public manifest contract, and local recorder tooling are implemented. **Credential Lifecycle Foundation** is published as a `DRAFT` evidence preview for **ElevenID LLC Credential Platform v2026.07.0**, with `PARTIAL` coverage and MIP `0.3.1` metadata.

The preview does not claim public-demo approval. YouTube publication, SpruceKit acceptance, the isolated ElevenID Demo Wallet package, independent-wallet qualification, portable Canvas execution, and a composed lifecycle video remain release evidence work.

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

## Promotion Gates

1. Validate the manifest with `python scripts/validate_demo_manifests.py`.
2. Build and deploy the coordinated ElevenID LLC platform release from pinned revisions and digests.
3. Require the deployed release probe to match the ElevenID LLC platform version, MIP version, marker, and every image digest.
4. Record required impacted scenarios with no skipped outcomes or unexplained browser/network failures.
5. Complete SpruceKit Open Badge login and independent-wallet qualification lanes.
6. Compose 1080p video, review the single-source transcript/captions, and scan text, frames, OCR, and QR payloads.
7. Confirm every displayed offer has expired.
8. Upload to the platform-version YouTube playlist as unlisted and verify processing, embedding, captions, and thumbnail.
9. Complete editorial review and run the evidence-bound scenario approval command. It records the review-file hash and promotes only the exact unlisted scenario to `PUBLIC`.
10. After the technical release gate passes, run the release approval command to update the release manifest and version index together with rollback on write failure.
11. Set release coverage to `COMPLETE` only when all six required scenarios are public and independent-wallet evidence passes.

Run the pinned public browser gate from `tests` with `npm run test:demo-platform`. This avoids selecting a different Playwright installation from another workspace package.

## Current Blockers

- Android tooling is absent: Android SDK/ADB/emulator, Appium UiAutomator2, and a pinned EUDI reference-wallet APK/profile.
- The ElevenID LLC YouTube channel, OAuth publisher, and `2026.07.0` release playlist are not configured yet.
- Existing browser recordings predate the versioned recorder and are retained only as protected preview evidence.
- Canvas has a portable scenario contract, but the adapter implementation must expose the portable test outcomes before recording.

These blockers keep coverage `PARTIAL`; they do not change the underlying ElevenID LLC platform release decision.

## YouTube Setup

The release manifest now carries a fail-closed `video_distribution` binding. A draft may use `PENDING_CHANNEL_SETUP`; any `YOUTUBE_UNLISTED` or `PUBLIC` scenario requires a verified `ElevenID LLC` channel ID, handle, canonical channel URL, owned release playlist, privacy-enhanced embedding, and verification timestamp.

The version-controlled `marty-demo-recorder` tooling provides credential-safe status reporting, local PKCE authorization, exact channel verification, idempotent release-playlist creation, binding promotion, release/scenario-bound unlisted upload, privacy-scan hash verification, caption and thumbnail publication, processing checks, playlist ownership checks, and fail-closed `YOUTUBE_UNLISTED` scenario binding. The binding preserves the exact video, captions, thumbnail, privacy-scan, and publication-config hashes as public media-integrity evidence. Google sign-in, channel ownership, recovery, and phone verification remain owner-controlled actions and are never stored in the repositories.

`npm run youtube:status -- --manifest ../marty-ui/ui/public/demos/manifests/2026.07.0.json` reports the next setup action without printing OAuth values. Upload results can only bind to an exact `VALIDATED` scenario revision. `youtube:approve-scenario` then requires complete assertion evidence and an eight-check editorial approval artifact before public scenario promotion. `youtube:approve-release` separately requires technical release readiness and updates the release manifest and latest-approved version index together with rollback on write failure.
