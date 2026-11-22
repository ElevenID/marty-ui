# Standalone website composition checkpoint

This checkpoint continues the website extraction through the first signed
cross-owner composition. The standalone website publisher is qualified; the
composition and isolated-host gates have distinct evidence and must not be
inferred from publisher success.

## Managed full-audience cutover, November 22

The accepted private application image matches the installed v1.1.274
application. A read-only comparison of the 30 installed backend and provider
containers found that all 30 configured image references match the signed
v1.1.274 inventory. Only edge, PostgreSQL and Redis match the v1.1.273
inventory. The requested backend tag conflicts with preserving the installed
digests. Hold final composition selection for release-owner disposition.
The private producer owner still needs to qualify the signed full-audience
standalone website. [Installed release inventory](https://github.com/ElevenID/marty-ui/releases/tag/v1.1.274)

At 22:34 UTC, the original installed recovery caller still selected generation
33, local sequence 9. A read-only check found the same 31 container IDs in two
snapshots. Seven services changed runtime state. The installed expired-origin
predicate rejected the change before any credential operation was attempted.
Both public and loopback ingress served the signed application marker and
returned HTTP 502 on `/ready` and `/v1/auth/me`. The next production step
requires a stable runtime under the existing recovery owner.

The first-cutover planner landed through [#2042](https://github.com/ElevenID/marty-ui/pull/2042).
The durable journal and dependent transition work start at
[#2043](https://github.com/ElevenID/marty-ui/pull/2043). The Windows caller
rehearsal in [#2058](https://github.com/ElevenID/marty-ui/pull/2058) exercised
guarded and released selections with a synthetic runtime.
Commit `b8768c295b8d6f6772866851be4d30437ac45a7d` adds read-only rollback
planning after credential renewal. The Windows owner test exercised a
completed renewal and a subsequent journal continuation. Docker Compose
rendered both replacement credential environments.

The [rollback PR](https://github.com/ElevenID/marty-ui/pull/2059) restores the
edge under the renewed selection. It verifies combined public and loopback
routes, authenticated account and organization access, and candidate identity
before retirement. It repeats the live checks with the candidate absent.
The next rollback step is to publish the combined selection and release the guard.
Production activation still requires credential
recovery, healthy application and identity checks, the signed full composition,
and renewal and reboot rehearsal. Keep [#2017](https://github.com/ElevenID/marty-ui/pull/2017)
pending through actual routing, sign-in, application and backout acceptance.

## Qualified original releases

The following exact completed attempts and non-expired archives were rechecked
against GitHub metadata on November 19, 2026 (America/Denver):

| Selection | Website | Combined application |
| --- | --- | --- |
| Repository | `ElevenID/website` | `ElevenID/marty-ui` |
| Numeric repository ID | `1459542519` | `1140864197` |
| Run / attempt | [`44449706828` / `2`](https://github.com/ElevenID/website/actions/runs/44449706828/attempts/2) | [`42385654811` / `1`](https://github.com/ElevenID/marty-ui/actions/runs/42385654811/attempts/1) |
| Event / branch / result | `workflow_dispatch` / `main` / `success` | `workflow_dispatch` / `main` / `success` |
| Source SHA | `7ec0707aa348939a0e48e6a26b24fb1af8671b9b` | `ca58b8bec939f5b26bebecd849edf55b5c4af5ae` |
| Artifact ID | `14495945528` | `13579961165` |
| Artifact name | `web-website-44449706828-2` | `web-application-42385654811-1` |
| Archive size | 22,470 bytes | 37,222 bytes |
| Archive SHA-256 | `14ad5d27d3baa60588f76bd2f214b865c84e43b9ca4f5a55060eb00dedff5054` | `3f6311c57cadfcbf21dd33961deeaae2b3af2060e135b336c8be8ca668eeff2c` |

The application selects the existing stable backend
[`v1.1.273`](https://github.com/ElevenID/marty-ui/releases/tag/v1.1.273).
The backend assets remain published. Actual intake must authenticate their
original bytes and source; asset availability alone is not proof verification.

The website publisher's first attempt did not finish; select attempt **2**.
The first attempt's partial work and unsigned qualification artifacts cannot
replace the successful original producer evidence. The selected website source
is intentional even if website `main` advances: a new source needs a new
qualified and signed release.

## Composition entry point

The manifest at
[`../../.github/release-inputs/website-composition.json`](../../.github/release-inputs/website-composition.json)
pins the above original run IDs and attempts. Its expected parent must be the
current consumer `main` revision immediately before its own merge. The guarded
main push is an alternate way to request the existing composition operation
when an authenticated interactive dispatch surface is unavailable. See the
[manifest procedure](../independent-website-release.md#reviewed-protected-main-composition-manifest).

[PR #1999](https://github.com/ElevenID/marty-ui/pull/1999) initially failed release
contract tests because its manifest step preceded the source guard and its
trigger/input changes were not covered by the existing workflow fixtures.
Its pinned parent also became stale when another PR merged. The repair restores
the source guard as the first post-checkout step, validates the manifest with a
bounded duplicate-rejecting parser, and exercises both manual and manifest
intake credential isolation. Required CI also checks changed manifests against
the actual integration parent before merge, including changes inherited from
earlier entries in a merge-group batch. The normal required checks and merge
queue still apply.

The repaired source at `b2db066e49bc6895be4268c3a39bd984e21d0a17` passed
[full hosted CI](https://github.com/ElevenID/marty-ui/actions/runs/44568782673):
27 successful jobs and one intended skip. The release-contract suite passed
12,370 tests before its separate staging and archive checks. Its first
[queue attempt](https://github.com/ElevenID/marty-ui/actions/runs/44576916109)
then rejected the stale parent at required preflight: the prospective queue
parent was `49bb88b07a26fa454819cf3ae5c6a6d7179d27b2`, while the manifest pinned
`08ee96933373805911de4fd10acb384205c880dd`. Subsequent CI lanes were skipped.
This demonstrates admission before merge; it is not a completed composition.
PR #2000 subsequently merged at `49bb88b07a26fa454819cf3ae5c6a6d7179d27b2`.
The refreshed manifest pins that actual main parent and retains the same two
original invocations. The refreshed source completed required CI and the normal
merge queue. PR #1999 merged as
`6daf2a216fbc6e16472a06977b21f33896f372f5` at 12:06:45 PM America/Denver on
November 19, with the expected first parent
`49bb88b07a26fa454819cf3ae5c6a6d7179d27b2`.

## Completed signed composition

The exact protected-main push
[`44594894023`, attempt 1](https://github.com/ElevenID/marty-ui/actions/runs/44594894023/attempts/1)
completed successfully on that merged source. Its
[compose job](https://github.com/ElevenID/marty-ui/actions/runs/44594894023/job/135810417284)
passed the source and manifest guards, original website intake, application and
backend authentication, composition signing and GitHub provenance, final proof
re-verification and artifact upload. The image-producing release job was
intentionally skipped.

| Evidence | Value |
| --- | --- |
| Artifact | [`web-composition-44594894023-1`, ID `14564688078`](https://github.com/ElevenID/marty-ui/actions/runs/44594894023/artifacts/14564688078) |
| Actions archive size | 10,644,299 bytes |
| Actions archive SHA-256 | `ced2c670ff35e716128911e959a03d80ef72a507d24be357bc544f6f635e1b02` |
| Composition ID | `sha256:476f8b387b42c4904a50a9bfd02173e88cba7e90f74548f50f58d8613a893124` |
| Composition JSON SHA-256 | `5c98c13f825cbe9e4f118354f24ffef98581c725a0101ae3a73634b442baebe5` |
| Payload ZIP SHA-256 | `342434fb1d0991998c3420ed3751acef49ef7be30fb02304c02d2558a3c3713f` |
| Backend source / producer | `ca58b8bec939f5b26bebecd849edf55b5c4af5ae`, original `cd.yml` run `42362661646`, attempt 1 |

The downloaded Actions archive matched its published size and digest and
contained exactly the six outer files in the
[composition guide](../independent-website-release.md#compose-with-an-existing-product).
Independent inspection checked the two outer attestation subjects, source and
workflow/run identity, the complete 22-file payload inventory, the existing
manifest validator and bounded extraction, and retained backend edge capability.
All five original website files and seven original application files matched
the selected producer archives byte for byte. These structural checks supplement
the successful hosted cryptographic verification; they are not a separate local
cryptographic verification claim.

The website image remains
`ghcr.io/elevenid/website@sha256:e02735cddc77f284049f6ddc81a54ecf4de1af9fde17faee19f255ce7a11c8b6`.
The application image remains
`ghcr.io/elevenid/marty-ui-oss/ui-public@sha256:c4f5b38aa21a9ea66fd66543a010fadd5f271f46a542fc8a86946b2e12934ff6`.
The original release selections in the table above are unchanged. Signed
cross-owner composition is complete.

## Continuation gates

[PR #2001](https://github.com/ElevenID/marty-ui/pull/2001) prepares a partial
application source boundary. Its exact candidate `10ce5784eb6a49a925c5c629c56e546beaae1e7a`
passed [required CI](https://github.com/ElevenID/marty-ui/actions/runs/44583667407)
with 27 successful jobs and one intended skip, including an application build
with 37 selected inputs absent. That run tested the pre-composition base;
normal merge-queue validation against the current main remains required.
Composition completion satisfies the PR's sequencing prerequisite. Continue
with the application-specific test profile and expanded source-absence rehearsal,
then audited asset ownership and an independent locked package/container build.

Qualify this composition on the existing isolated deployment using the
actual application and OIDC flow. Exercise active/previous asset retention,
promotion, failed promotion recovery, rollback, reboot recovery and website
availability while product services are stopped. Product and OpenBao pins must
remain unchanged. The full private billing journey remains separately owned.

Composition deliberately records `runtime_tested: false` and
`billing_journey_tested: false`. Packaging does not establish host or journey
success. Production traffic changes, source deletion, slim-application
activation and repository renaming are later gates.
