# Website switchover and first source removal

This change makes `ElevenID/website` the current marketing build owner and
removes the reviewed first batch from `marty-ui`. It preserves the accepted
historical composition, release grammar and customer deployment identities.
The application remains in `marty-ui` until its independent ownership gates pass.

## Current build and release ownership

| Consumer | Current behavior |
| --- | --- |
| Ordinary UI development/build | Application entry, output `ui/dist` |
| Explicit application build | Application entry, output `ui/dist-application` |
| Customer/selfhost build | Retained customer profiles, output `ui/dist-selfhost` |
| `docker/ui.Dockerfile` | Default `application`; explicit `selfhost` and `console` retained; legacy `public` and `website` targets absent |
| Standalone marketing | `ElevenID/website`, Bun 1.4.4, its own Docker recipe and protected-main publisher |
| Current public web workflow | Independent `application` producer and original-evidence `compose`; retired modes fail admission |
| Stack release coordinator | Qualify, nightly, stable and stable publication; no automatic legacy web continuation |
| Private legacy producers | Reviewed immutable source/tag allowlist adopted through [subscriptions PR #112](https://github.com/ElevenID/marty-subscriptions/pull/112) |

Current `ui_release.py` and `website_release.py` CLI `plan`/`record` calls refuse
to manufacture a legacy release from a checkout without its original Docker
target. Internal validators retain the original combined/website schemas and
can verify their exact historical source. A new application image is never
relabeled as the old combined image.

The required CI identities remain unchanged. `Website Surface` now qualifies
the application and customer boundary. Two retired crawler jobs are removed
from both the workflow and the closed aggregate roster, leaving 18 jobs. The
historical `website_only` plan field is false-only, and merge groups require
full qualification. The customer HTTP suite is now
`ui/scripts/test_nginx_application_routes.py`.

## Reviewed removal boundary

The 72 original paths are the union of the historical website module ownership
roster and the application closure/asset omission groups. All are absent in the
new source. Nine obsolete marketing test files are also retired; the surviving
customer HTTP suite is renamed and retains its behavioral checks.

| Original ownership group | Paths |
| --- | ---: |
| Website modules | 34 |
| Raw public demo manifests/index | 3 |
| Combined entry adapters | 2 |
| Generated demo projections and services | 4 |
| Combined test setup and English marketing locale | 2 |
| Website build helper | 1 |
| Audited public website assets and other marketing locales | 26 |
| **Audited original paths removed** | **72** |

The 54 application public resources remain: 42 locale resources and 12 shared
assets. Current build guards reject reintroduced marketing source, including
symbolic links, and still check emitted modules. The entire portable-package
omission inventory is not a deletion authorization.

## Historical packages and operator compatibility

The original npm v1 source contract and the exact pre-removal Bun v2 contract
are frozen separately. Approved contract digests select the original path map;
unknown digests and schema/digest substitutions are rejected. The retained npm
package restores its 575 files and original 296-test policy; the retained Bun
package restores its 578 files and original 308-test policy. Current packages
use the new map without pretending removed paths still exist.

Backend operators still need a deployment demo template and a draft-poster
hash. Their smallest retained input set is now explicit under
`deploy-config/catalog/operator-demos`: the original `2026.08.0` JSON, the
original `2026.08.1` SVG, and a code-hash-bound catalog of their provenance and
digests. The old `2026.07.0` JSON is a digest-checked test fixture. No public
index or historical poster tree is retained in the application.

The operator catalog does not assert website image availability or recorded
demo success. Explicit website catalog validation still checks real poster
files. Draft generation writes to `build/demo-manifests/` and retains the exact
original draft bytes. Startup completion validates the operator-owned template
after the full local snapshot verification and before startup/Docker work.
All deployment metadata consumers select the template from the exact product
Git commit. New sources use the retained operator catalog; an older source
uses its original `ui/public/demos/manifests/2026.08.0.json` only when that Git
commit has no current catalog path. Git failures and changed current files
cannot trigger fallback. The real v1.1.273/v1.1.274 template retains its
87,282 bytes and SHA-256 `3e643f3b471daac620c670aa506c654fb7894b940744c83169775fb643a655f1`;
the retained newer template has 87,363 bytes and SHA-256
`3859324f5f2fb13dae158b8ff95c1e2261ae69c5ce2ce8806a2e4048e16ca494`.
An older frozen product checkout is not modified to insert new catalog files.

PowerShell uses an official source's `revision` or a local source's `head_sha`,
and verifies the selected path, digest and revision again before binding.
The local snapshot's worktree-derived `marty_ui_sha` marker is not its Git HEAD.

The legacy beta demo publisher requires its original combined image, page
adapters and complete public catalog. Its existing signed-source admission now
precedes an immutable-source layout check, which runs before browser, OAuth,
recorder or deployment work. Historical ca58/3ff/b109 layouts remain admitted;
post-removal sources fail with website-owned-publication guidance. A reviewed
website-owned demo publication flow is required before publishing new split
releases through that procedure. The application does not regain demo assets.

## Qualification and rollout record

The repaired source baseline is Marty `b1095e8c86389929cf1a93c4ed04d9eb784f3a6d`
and website `14ec367ea74048f40a709d7c2b4415181dc454e5`. Free public CI uses identical
trees at Marty `3af9c44f47084df567cd8579ac5fb8801a0dddf5` and website
`6ddb8de7c750fa1aff8d1cfb56253790f3724cd8`. The website's contracts, migration
provenance and standalone production qualification all passed, including
[run 44873115996](https://github.com/ElevenID/website/actions/runs/44873115996).
The downloaded original CI artifact was checked against GitHub's archive
digest and its internal source/tree/output bindings: 259 rendered routes,
251 canonical/sitemap routes, 57 resource checks and 23 denied-route checks.
The private producer guard merged normally in PR #112 at
`1d1d27803fc394dfaaf65a4856804f56893cfafe`; its reviewed tree is
`fdd1089b7ead3eefcd036e36207d60746c0168d2`. No private Actions were run.

The existing Ohio AWS Free plan host runs the additional diagnostic suite with
Node 24.22.1, Bun 1.4.4, ordinary Chrome and rootless Docker. It retains the
existing six-hour automatic stop and all pre-existing containers. Its first
run passed full/profile application installation and nginx, then correctly
rejected a checkout created with mode 0664 instead of Git's 0644. A subsequent
attempt exposed Chrome's Unix-socket path limit. The runner now checks exact
source modes and bounds the UTF-8 temporary path before execution. The third
attempt passed all three fresh application dependency/install paths, nginx,
export/restore, release planning and all three sandbox-required Chrome gates,
including the production image recipe. Its website tests exposed a runner
environment error: a production revision was being supplied to a development
server test. Production identity is now confined to the appropriate stages.
The same inherited variable occurs in the standalone production publisher;
the companion website change makes development tests own and restore their
environment and cover both the default and exact-source resource namespaces.
Each failed attempt and its logs remain intact; a new clean attempt runs the
corrected complete qualification. Existing container IDs were verified after
the failed attempts.

Local removal validation includes 308 selected application assertions, 38
supplemental customer/console assertions, 25 build/configuration checks, 83
operator/manifest tests (one existing Windows-only skip), 41 compatibility
tests with 54 subtests, and 516 CI/release tests with 123 subtests. Actual
default, explicit application and customer Vite builds passed.

Integrated commit `47c5c7c0248de460a80259af8927c7c5deff6901`, tree
`6537f446e613d2c361803824bc903c53a29eb137`, passed 106 closure/export/consumer
protocol tests and three separate fresh frozen Bun rehearsals. Each rehearsal
passed 308 tests. Full, reduced and restored builds matched all 88 output files
and 54 public resources. The actual source export contains 578 packaged files
and 332 present omission records; the Node bridge, Python release plan and
ordinary `bun run build` lifecycle passed. Its checkpoint SHA-256 is
`b02c07865bf67e47b20c5c050a47c24bde599ce1633802c2a783eb63088c2f24`.
Later operator/runner/CA-certificate fixes leave all 578 packaged inputs
unchanged, but new builds must record their actual producing source commit.
The updated customer nginx suite, actual source Docker builds and final AWS
result remain separate execution gates and are not claimed by this checkpoint.

## Development priority

1. Complete the corrected AWS qualification and exercise the actual retained
   application/selfhost Docker producers and customer HTTP boundary.
2. Merge the independently qualified standalone website and this first removal
   through normal required CI; retain the frozen private and beta consumers.
3. Identify the public deployment owner and apply the accepted signed
   composition through its existing staged promotion and rollback procedure.
4. Move new demo publication to the website owner, then continue independent
   application release ownership and further audited removal only after the
   relevant consumers have moved. Preserve original
   signed releases, package contracts and customer-stack identities throughout.

The AWS machine currently hosts an existing customer installer stack. It is
not the accepted public marketing deployment target. Neither a source merge
nor a diagnostic build changes public routes, proves OIDC, or replaces the
accepted composition's original application/backend pins. The next live
activation must identify and verify the actual public deployment, then exercise
the existing retained-slot promotion, rollback and recovery contract.
