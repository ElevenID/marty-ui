# Standalone website composition checkpoint

This checkpoint continues the website extraction through the first signed
cross-owner composition. The standalone website publisher is qualified; the
composition and isolated-host gates have distinct evidence and must not be
inferred from publisher success.

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
original invocations. Repeat normal CI and queue admission on the updated head,
and retain its exact source and run evidence in PR #1999.

## Acceptance and continuation

After the manifest change merges, inspect the exact production-web workflow
attempt from that merged source. It must finish successfully and upload one
`web-composition-RUN-ATTEMPT` artifact with the six original outer files listed
in the [composition guide](../independent-website-release.md#compose-with-an-existing-product).
Verify its selected website/application identities, backend source/tag, image
pins, original proof payloads and both outer signatures/attestations. Record the
successful run, attempt, source, artifact ID, size and SHA-256 in the PR's
completion checkpoint. Until that evidence exists, signed cross-owner
composition remains pending.

Then qualify the composition on the existing isolated deployment using the
actual application and OIDC flow. Exercise active/previous asset retention,
promotion, failed promotion recovery, rollback, reboot recovery and website
availability while product services are stopped. Product and OpenBao pins must
remain unchanged. The full private billing journey remains separately owned.

Composition deliberately records `runtime_tested: false` and
`billing_journey_tested: false`. Packaging does not establish host or journey
success. Production traffic changes, source deletion, slim-application
activation and repository renaming are later gates.
