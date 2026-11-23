# Standalone website composition checkpoint

This checkpoint continues the website extraction through the first signed
cross-owner composition. The standalone website publisher is qualified; the
composition and isolated-host gates have distinct evidence and must not be
inferred from publisher success.

## Approved full-release database rollback, November 23

If the full v1.1.292 upgrade must return to v1.1.274, the deployment owner
accepts resetting the selected Windows PostgreSQL cluster to its verified
pre-upgrade recovery point. Later writes can be lost across the application,
Keycloak and Applicant databases. An edge-only backout can keep the accepted
application and database. This decision covers the selected Windows cluster.

A disposable PostgreSQL 15 rehearsal ran the released v1.1.274 migration
owners, captured a verified physical backup and WAL, and ran the v1.1.292
migrations twice. An isolated restore paused at the exact pre-upgrade log
position. A second copy promoted at the same named point, accepted new writes
in all three databases and retained those writes after restarting. All five
available v1.1.274 service schema verifiers passed on the restarted database.
The separate upgraded database still contained its later records. The
Keycloak and Applicant databases used synthetic markers in this rehearsal.
Receipt SHA-256 `de5c749ed7701f9de0b7cef8605b1f2423dd74104f1c5d1030c4a9c385422d77`.

The production owner still needs a consistent recovery point, retained
backup and WAL, a verified restore, and a coordinated writer switch on the
selected host. Reconcile the separate Applicant file, Redis sessions and
provider bindings and verify fresh sign-in before reopening traffic.

## Source-removal compatibility review, November 23

A read-only merge projection of source-removal PR #2017 at
`b85dfac93f061f97000b7b1014ca7ce9ad95e1af` against protected main
`86812db416a64e35bb8c045afc3a02ce379d7ab5` found 12 conflicting files.
They cover CI and affected-component tests, website release evidence and
documentation, and the application package exporter and consumer.

Both revisions' Node package-policy readers ran against the four original
contract files. Both accepted the original npm map (575 inputs, 24 test
files, 296 assertions). Main also accepted the agent-trust npm map (581
inputs, 26 test files, 321 assertions). The parked candidate rejected that
map's digest, `7df5cfa6e3c37f9c1c3c3a8034559608971ad4dca60954013c5487e41b270f41`.
Its two Bun maps have distinct digests and each selects 578 inputs, 25
test files and 308 assertions. This check exercised contract selection.

After production acceptance, the #2017 integration owner must retain the
exact agent-trust npm contract alongside the earlier npm and Bun contracts,
include the six agent-trust files in the refreshed active application
export, and qualify fresh full, reduced and restored packages against the
actual combined test roster. Preserve the upstream signed full-website
evidence handling in the release workflow and verifier as well.
[Source removal #2017](https://github.com/ElevenID/marty-ui/pull/2017) /
[Agent-trust integration #1994](https://github.com/ElevenID/marty-ui/pull/1994) /
[Full website evidence #2024](https://github.com/ElevenID/marty-ui/pull/2024)

## Managed Windows staging and routing, November 23

Website staging merged through the protected queue at
`86812db416a64e35bb8c045afc3a02ce379d7ab5`. Routing PR #2046 now
targets main at `f78dddc86be6c27cda73a480090cec4e589cba8b`. Its
11-file patch against protected main matched the reviewed patch on the
staging branch byte for byte. All 462 applicable Windows tests passed
with two symbolic-link cases skipped, and the organization policy audit
passed. The routing checkout was parked after publication and both refs
were verified. [Hosted routing CI](https://github.com/ElevenID/marty-ui/actions/runs/45108269826)
passed and the protected queue admitted the change. The managed acceptance
PR follows routing. Production still serves the combined release.
[Staging #2045](https://github.com/ElevenID/marty-ui/pull/2045) ?
[Routing #2046](https://github.com/ElevenID/marty-ui/pull/2046) ?
[Acceptance #2047](https://github.com/ElevenID/marty-ui/pull/2047)

The draft acceptance verifier at `329b4011b8993fa0fb5d68f29d10a0a74ab98758`
now checks the OpenID scope, nonce, state and 43-character S256 challenge
that both release versions send on login. It checks field multiplicity
and rejects error or token parameters before recording the handoff.
The exact commit passed 518 Windows tests with two symlink skips and
14 related browser-runner contract tests. Signed-in acceptance on the
selected deployment still requires a healthy gateway. The local test
report SHA-256 is `05890bdb31ca4100ae71d19bbd4a4ce7a977517ebcee4e3c74444ffafa1c70a0`.
[Acceptance qualification #2047](https://github.com/ElevenID/marty-ui/pull/2047)

The queued Resources fix at `5a48f2638f57d76a9b38eff40b445d5c9a6aa9cf`
and the routing and acceptance branches add files to the same selfhost
bundle inventory. A local integration rehearsal found one conflict at
each step, in the frozen CLI output for `bundle-assets selfhost`. Deriving
that case from the combined manifest retained all queued entries in order
and added the edge module, then the verifier (233 and 234 assets).
The catalog-output and bundled-import tests passed on both projected
trees. Codex will apply the resolution to the actual protected base and
run the full Windows suites before each merge. The projections have no
effect on production or either PR branch.
[Resources queue run](https://github.com/ElevenID/marty-ui/actions/runs/45111440032)

## Full website and application qualification, November 23

The full v1.1.292 application built from the verified backend source and
passed local image checks for 414 static files and all 14 image layers.
The installed v1.1.274 combined release remains the rollback selection.
[Application producer #116](https://github.com/ElevenID/marty-subscriptions/pull/116)

Website main commit `98beddf93a1422f2da3ba8c3346e8387e4dfc994` and
standalone producer `92fde38303af240cf336483a4fa144970855fd6b` passed
local full-audience qualification. The private producer passed 74 offline
tests. The production image passed 259 route checks, 57 resource checks,
26 denied or retired route checks and six sandboxed Chromium cases. The
archive scanner checked all 13 layers and 2,988 entries. The final image
contained 454 static files. The three withheld pricing routes returned 404.
Both release-plan consumers accepted the v4 plan. The local qualification
SHA-256 is `cb34e4e7f2b821bf34df7d7d156d031d45bc82334bcb020df27bb831406301fe`.
The draft PR records the plan and original evidence.
[Standalone producer #113](https://github.com/ElevenID/marty-subscriptions/pull/113)

The managed acceptance verifier previously expected a pricing page. The
qualified website returns HTTP 404 on both exact pricing paths and identifies
the selected revision in its response headers. The corrected verifier passed
against two real loopback Nginx listeners serving the verified 453-file full
website build. The disposable edge restored the combined release with its
original v1.1.274 application container still running. The standalone site
also passed after the disposable application was removed. The Windows suite
passed 487 tests and skipped two symbolic-link cases. The local rehearsal
receipt SHA-256 is `9113d3e45bca63ae03e8dbe1fd21e58a6191144bd7bd93bdc20d6c10387de29b`.
[Acceptance correction #2047](https://github.com/ElevenID/marty-ui/pull/2047)

The installed edge template already defines an exact Resources redirect.
The plain website include duplicated that location and Nginx refused to start
in a disposable reproduction. The managed correction passed with a copy of
the installed template and its original rendering script. Two loopback edges
served the standalone build at `/resources`, preserved its query, kept the
slash path on the application and sent a descendant to the Keycloak fixture.
The apex redirect held. Backout restored the combined redirect on the same
application container, and a fresh split edge served Resources even after
the disposable application was removed. All five rendered defaults matched.
The rehearsal receipt SHA-256 is
`a8120de9cf3fce5c88dc4e6d31ece22476a962752abe68e6d1294e838a09c2d0`.
[Retained edge correction #2064](https://github.com/ElevenID/marty-ui/pull/2064)

A live public request to exact `/resources` reached the selected edge and
application as `/index.html`. The release marker and the slash path reached
both containers under their original paths. The retained deployment procedure
identifies the temporary www Resources SPA rule. At the cutover the zone
owner must capture its current configuration, disable the rewrite when the
signed split origin is ready, and restore its prior behavior on combined
backout. The Windows owner and public zone have separate routing controls.

The verifier now checks the Resources canonical path, selected revision and
revisioned script through public and loopback ingress. In a disposable
rehearsal it rejected the stale public rewrite, accepted the correct
Resources page after removing it, and the original public page was restored
on combined backout. The source at
`07fe01edf17449a4464724ce756e4465de2d416e` passed 490 Windows tests with
two symlink cases skipped. Rehearsal receipt SHA-256
`ec40a3ad933d60f3fb02e97e5ea79a1c240659a54a37716b8d3fbfe999c8e639`.
[Public acceptance #2047](https://github.com/ElevenID/marty-ui/pull/2047)

The full application upgrade also changes the Keycloak configuration used
for fresh sign-in. Both installed configurator scripts and all 29 inspected
realm and theme paths matched v1.1.274. The v1.1.292 bundle changes 24 of
those paths. It includes the new account theme and the UI client mapper
that emits the authentication timestamp. The selected realm has one UI
client and lacks that direct mapper. The image-only transition preserves
both mounted scripts and skips the configurator.

A disposable PostgreSQL, Keycloak and OpenBao installation exercised the
three signed v1.1.292 image pins. The original configurator created the
mapper on an existing synthetic UI client, updated it on the second pass
and read back the expected values both times. A fresh authorization-code
login with S256 PKCE returned a remotely signed ID token. Its signature,
issuer, UI audience, nonce and authentication timestamp passed. The
rehearsal receipt SHA-256 is
`aae14cc4bb589919ec3c8c4bcf614d7f2a4279237a8721e7af627073291285a0`.
The production upgrade still needs to select the signed configuration
alongside the images and verify a fresh sign-in on the recovered host.

The selected services mount 37 distinct paths represented in the two
signed prepared bundles. All matched the installed v1.1.274 release by
presence and content. The v1.1.292 bundle changes 28, including the shared
secret-loading script and the PostgreSQL initialization script. Preserve
the established database when selecting the new files. The signed base
Compose model also changes environment bindings and the Redis command.

Docker Compose resolved the signed v1.1.292 environment expressions against
the selected Windows environment file with shell overrides excluded. Across
the 22 installed roles that use the organization name, the one existing
explicit value matched and 21 roles gain that same configured name. The
auth service resolves passkey login to false. The Keycloak configurator
receives an empty management setting and RP ID, preserving the existing
realm passkey policy. The optional kms-initialize role was absent from the
31 installed containers. This read-only comparison covers three settings.
Verify the resulting values again in the fully assembled release before
activation. Receipt SHA-256
`ce64146904b2f3c36667286524ba6db3043c508387ce5c2677b5e09ba4aa66d6`.

Both releases pin the same Redis image. They select different memory
policies, `allkeys-lru` in v1.1.274 and `noeviction` in v1.1.292. A
disposable instance used each original release command with the same
Windows data bind and Unix socket volume through upgrade and backout. The
append-only file retained the synthetic identity value, a replay marker
and its absolute expiry, and a write acknowledged after upgrade. The
rehearsal receipt SHA-256 is
`b893c0ec17717a3820de07996762fa95d9d925fdd3a8a6e0a1e261ccd227da5d`.
The managed full application upgrade still needs to select the signed
command and confirm the data and socket mount identities on the host.

The selected PostgreSQL 15 cluster contains three service databases,
`marty`, `keycloak` and `marty_applicants`. The Applicant service also
writes to a separate host-mounted `applicant_store.json`. Its released
file persistence, store decoder and migration module are byte-identical
in v1.1.274 and v1.1.292. A production recovery boundary must account for
that file independently of the PostgreSQL and Redis recovery points.

A local rehearsal ran the release-pinned Applicant images with an isolated
writable bind and synthetic service identities. The original service
created a profile. The v1.1.292 service updated it and created a second
profile. Returning to the v1.1.274 image on the same bind preserved both
acknowledged writes, as did restoring a copy of the file taken after those
writes. A copy taken before the upgrade restored only the original profile
and its earlier values. Each copy was taken after the fixture service had
stopped. Production sign-in, other Applicant record types and consistency
across the file, PostgreSQL and Redis still require separate verification.
Rehearsal SHA-256 `63a0f4819297a3412a30226ca55db211d1d8e923591286ee4501405705045401`.

A disposable cluster initialized by the original v1.1.274 initializer
accepted authenticated connections to all three databases with both
releases' signed secret loaders. After a verified base backup, separate
writes committed in each database before and after a named recovery
point. Restoring that point retained the three earlier commits and
excluded all three later commits. A second restore retained the later
commits in all three databases. Both restores paused at their expected
WAL positions. The test used synthetic rows and did not apply service
schema migrations. Receipt SHA-256
`4ea381cf730b5329e03ca4fa87a8b0dd4ff15b700f875588667a9162f6feec37`.
The database owner still needs to capture and verify the production recovery point.
[PostgreSQL 15 recovery scope](https://www.postgresql.org/docs/15/continuous-archiving.html)

The original v1.1.274 combined package and application evidence were
retrieved again from their successful producer run. Both archives matched
their published digests. The full package matched the retained authenticated
archive byte for byte, and all 246 files in the accepted local inventory
matched their hashes. The 31 selected Windows container roles matched both
the signed manifest digests and their local immutable image IDs. The
database owner still needs to establish the production writer boundary.

At 00:43 UTC the public and installed loopback endpoints served the combined
release marker. Both readiness and current-account requests returned 502.
The production owner must reconcile the selected workload's credential
through the supported recovery owner and verify live readiness and identity.
The release owner must obtain the original signed full application, website
and composition within the existing private Actions budget. The managed
cutover and source-removal PR remain pending those results.
[Source removal #2017](https://github.com/ElevenID/marty-ui/pull/2017)

### Renewal history and database recovery rehearsal

The installed owner verified the current selection against the activation
published on November 18 at 15:10 UTC. The next two renewals timed out at
19:01 and 23:01 UTC. Both retained attempt directories were empty. The
original selected certificates show all 18 leaves were still within their
validity period at both timeouts. They expired between 23:01:27 and 23:01:29
UTC. The November 17 installed owner checks Docker and storage before it
stages replacement credentials. The retained evidence does not identify
which inspection timed out. At 01:10 UTC on November 23, both public and
installed loopback still served the combined release marker and returned
502 for readiness and account lookup.

A disposable v1.1.274 database was upgraded to v1.1.292. After the original
backup, the rehearsal inserted, updated and deleted organization records and
added a verification receipt specific to the new schema. A physical backup
of the upgraded cluster passed PostgreSQL backup and WAL verification. A
second instance booted from that backup on the isolated rehearsal network.
Its schema dump matched the source after normalization of the paired dump
nonce. Row counts and content digests matched for all 89 application tables.
All five available v1.1.292 service schema verifiers passed against the
restored instance. The private rehearsal receipt SHA-256 is
`2b52d25f1ffb17e1ba7752e8c7478ed05864f37c6077b267300e0fe3691426cf`.

The pre-upgrade archive restored the original v1.1.274 state, including a row
deleted after that backup. The upgraded cluster retained its later writes and
new-schema receipt. The approved full-release reset can rewind these writes.
The physical restore
exercise used a read-only synthetic database during backup. Production
credential recovery, signing and cutover remain pending.

### Installed v1.1.292 migration prerequisites

On November 23 the installed owner observed zero of the ten required migration
records in the selected production database. An independent Docker Desktop
rehearsal confirmed that the image-only preflight refuses the released
v1.1.274 database and accepts both completed v1.1.292 migration passes.
Omitting each of the ten records individually caused the query to refuse.
All 167 Windows product tests passed. PR #2062 merged into protected main
at `b7587d8f05f98e5d5d491505fa085d9c725244ea` on November 23.
The five-file change matched the Windows-qualified patch byte for byte.
The merge-group CI workflow finished with 28 successful jobs and one skip.
[Database preflight #2062](https://github.com/ElevenID/marty-ui/pull/2062) /
[Protected queue run](https://github.com/ElevenID/marty-ui/actions/runs/45107017431)

The product owner still needs a schema-changing upgrade and a verified
production restore point for the approved backout. Production credential recovery precedes the
managed deployment. The rehearsal receipt SHA-256 is
`6a03e1557e22a780e7f14580dba5bf4715ede5e13b97d18d2e12635ef18b3227`.

### Recovery points across the database upgrade

One verified physical v1.1.274 backup and three archived PostgreSQL WAL
segments recovered three named points on a disposable cluster. The first
restore included a v1.1.274 write committed after the backup and before the
schema upgrade. The next two restores included the new verification receipt
and the deletion of an organization. A separate writer held a transaction
open at the second point and committed before the third. Its update became
visible only at the third point. A later write was excluded from all three.
Each restored server paused at the recorded log position and passed all five
schema verifiers from the corresponding release. The rehearsal receipt has
SHA-256 `ab13d7af4b3700b9ed080b2c7dd04eaabf296aad7871d630f5b4e53283a2ad4f`.

Two read-only observations of the selected production PostgreSQL instance
found archive mode off, zero replication slots and zero connected WAL
senders. A production upgrade still needs a retained backup and WAL stream,
and a verified restore before applying the approved full-release rollback. The release owner must
also account for identity, Redis and provider state outside the application
database. The installed readback has SHA-256 `8c98652a766460240efd05b2df1cfebcc328b2c409a61fbd32059ae8574e8563`.

## Managed full-audience cutover, November 22

The release owner selected v1.1.292 for both the backend and the full
application. All five backend release subjects passed provenance verification
at source `ab8c96626100418f8a88a883380e807a575fbe16`. The producer candidate
accepted the matching full application plan and passed 44 Linux producer tests.
The application image, standalone full-audience website and signed composition
still need their original producers. Retain the installed v1.1.274 combined
package for rollback. [Stable backend release](https://github.com/ElevenID/marty-ui/releases/tag/v1.1.292)

An isolated database rehearsal used the released v1.1.274 migration and service
images to establish the baseline and create a synthetic organization. The
v1.1.292 images upgraded that same database twice. Both passes verified all
ten new migration records across Credential Template, Device Registration,
Flow, Issuance and Trust Profile. The organization survived. The release
owner still needs to qualify production data recovery and the application
journeys on the signed full composition.

In the database rollback rehearsal, the v1.1.274 Issuance schema verifier
refused the migrated database. The other four available v1.1.274 read-only
schema verifiers passed. All five passed on a separate restore of the
pre-upgrade PostgreSQL archive, which contained the synthetic organization.
The full-release rollback plan must account for writes made after the backup.
An edge-only website rollback can retain the accepted application and database
generation.

At 22:34 UTC, the original installed recovery caller still selected generation
33, local sequence 9. A read-only check found the same 31 container IDs in two
snapshots. Seven services changed runtime state. The installed expired-origin
predicate rejected the change before any credential operation was attempted.
Both public and loopback ingress served the signed application marker and
returned HTTP 502 on `/ready` and `/v1/auth/me`. The next production step
requires a stable runtime under the existing recovery owner.

The first-cutover planner landed through [#2042](https://github.com/ElevenID/marty-ui/pull/2042).
The durable journal merged through
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
The renewed rollback path publishes the combined model with the current
credentials and archives its guard after authenticated readback. The installed
Windows caller and host rehearsal still need to exercise this path.
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
