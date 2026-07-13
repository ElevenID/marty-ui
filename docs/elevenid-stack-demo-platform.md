# ElevenID LLC Credential Platform Demos and Release Evidence

## Status

The production application, public manifest contract, and local recorder tooling are implemented. **Credential Lifecycle Foundation** is published as a `DRAFT` evidence preview for **ElevenID LLC Credential Platform v2026.07.0**, with `PARTIAL` coverage and MIP `0.3.1` metadata.

The preview does not claim public-demo approval. YouTube publication, SpruceKit acceptance, the isolated ElevenID Demo Wallet package, independent-wallet qualification, portable Canvas execution, and a composed lifecycle video remain release evidence work.

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
3. Require the deployed release probe to match Stack, MIP, marker, and every image digest.
4. Record required impacted scenarios with no skipped outcomes or unexplained browser/network failures.
5. Complete SpruceKit Open Badge login and independent-wallet qualification lanes.
6. Compose 1080p video, review the single-source transcript/captions, and scan text, frames, OCR, and QR payloads.
7. Confirm every displayed offer has expired.
8. Upload to the platform-version YouTube playlist as unlisted and verify processing, embedding, captions, and thumbnail.
9. Complete editorial review, update the manifest with exact publication evidence, then promote the scenario to `PUBLIC`.
10. Set release coverage to `COMPLETE` only when all six required scenarios are public and independent-wallet evidence passes.

## Current Blockers

- Local video tooling is absent: FFmpeg, ffprobe, Tesseract, and ZBar.
- Android tooling is absent: Android SDK/ADB/emulator, Appium UiAutomator2, and a pinned EUDI reference-wallet APK/profile.
- No YouTube OAuth token or Stack `2026.07.0` playlist ID is configured.
- Existing browser recordings predate the versioned recorder and are retained only as protected preview evidence.
- Canvas has a portable scenario contract, but the adapter implementation must expose the portable test outcomes before recording.

These blockers keep coverage `PARTIAL`; they do not change the underlying Stack software release decision.
