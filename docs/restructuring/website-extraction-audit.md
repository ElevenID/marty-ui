# Website extraction audit

Source inspected: `ElevenID/marty-ui`, default branch `main`, tree SHA `9e098423b5d98bc1bb50147f6cf1412973256144` (inspection snapshot).

## Existing separation already present

The website is already a separately selectable production surface. The repository contains:

- `contracts/website-source-ownership.json` — canonical list of 34 website-owned source modules.
- `contracts/web-surface-routes.json` — route ownership contract, with application fallback.
- `docs/independent-website-release.md` — existing independent producer/composition/retained-slot deployment design.
- `scripts/website_release.py` — source-bound website build plan and release record.
- `scripts/website_provenance.py` — original producer and image evidence verification.
- `scripts/deploy_website.py` — retained-slot deployment, promotion, rollback and product-adoption logic.
- `ui/scripts/build-web-surface.mjs`, `ui/scripts/website-assets.mjs`, `ui/scripts/render-website-nginx.mjs`, `ui/scripts/smoke-website.mjs` and associated tests.
- `ui/nginx.website.conf` and `ui/nginx.website.headers.conf`.
- `.github/workflows/production-web-release.yml`.

The current workflow supports `website`, `combined` and `compose` modes. Preserve the behavior and trust guarantees; split workflow ownership rather than rewriting the release model.

## Website-owned source manifest

The existing `contracts/website-source-ownership.json` lists the 34 initial website modules. Use it as the starting set, not as a complete extraction closure. Every import, asset, test and build input must be classified before moving.

Other known website-related paths include:

- `ui/src/website.jsx`
- `ui/src/apps/website/`
- `ui/src/variants/marketingRoutes.jsx`
- `ui/src/variants/publicConfig.website.js`
- `ui/src/data/marketingContent.js`
- `ui/public/locales/*/marketing.json`
- `ui/scripts/*website*`, `ui/scripts/*web-surface*` and crawler/SEO/prerender scripts
- `ui/nginx.website*.conf`
- `scripts/website_release.py`, `scripts/website_provenance.py`, `scripts/deploy_website.py`
- `tests/test_website_*.py`, `tests/test_deploy_website.py`, `tests/test_web_release_intake.py`, `tests/test_web_producer_evidence.py`, and corresponding UI website tests
- `contracts/website-source-ownership.json`, `contracts/web-surface-routes.json`, and relevant website release schemas/contracts.

Do not move application-only routes/components merely because they share `ui/src/components/pages`.

## Dependency closure and blockers

### Shared React application code

`WebsiteApp.jsx` currently imports shared application modules including BrandingContext, public-entry routing, runtime configuration, analytics, shared navigation/footer, prerender signaling and WebSurfaceBoundary. Classify each dependency:

- Website-only implementation: move into `website`.
- Small stable shared contract: duplicate only if truly trivial, otherwise publish a small shared package or define a versioned contract.
- Application-owned runtime behavior: replace with a website-specific implementation/configuration; do not make `website` depend on the `application` source checkout.

The website must not import private application modules through relative paths after extraction.

### Build context is coupled to marty-ui

The current `docker/ui.Dockerfile` builds with repository-root context and copies both `ui/` and root `contracts/`. `scripts/website_release.py` derives its root from the current monorepo and imports `ui_release.py` and `product_package_plan.py`. The website build plan also hashes the current shared Dockerfile and dependency lock.

This is a hard extraction task: create a website-owned Dockerfile/build context and self-contained release planner/verifier. Do not retain hidden dependency on a checkout of `marty-ui`.

### Dependencies

- `@elevenid/marty-blog` is a versioned published dependency; continue consuming immutable releases.
- `@elevenid/marty-api-core` is currently part of the frontend dependency set. Determine which website routes actually need it; remove it from website if unnecessary.
- Public/private commerce split currently uses `ElevenID/marty-ui` and private `ElevenID/marty-subscriptions` producers. Preserve private source isolation and explicitly rebind private producer identity to the new public website workflow only after private workflow changes are reviewed.
- Preserve lockfile integrity and pinned package digests.

### Release identity and provenance

Current website release code binds repository identity, workflow identity, source SHA, run ID/attempt and image URI. The verifier currently recognizes `ElevenID/marty-ui` and `ElevenID/marty-subscriptions`. Moving the public producer to `ElevenID/website` requires coordinated changes to:

- Allowed producer repository IDs and workflow identities.
- Sigstore certificate identity and SLSA source repository identity.
- Image source labels and OCI image coordinates.
- Artifact intake allowlists and repository/run/attempt checks.
- Private commerce producer's accepted public source SHA/lineage.
- Release manifests, retention records and deployment verifier policy.

Do not simply change the image name or accept both identities indefinitely without a bounded migration policy.

## Workflow ownership proposal

| Concern | Future owner |
| --- | --- |
| Website source build, SEO/prerender, website tests | `website` |
| Website image publication and website producer attestation | `website` |
| Application combined/compatibility image production during transition | `application` |
| Website + application + backend composition and deployment intake | `platform` |
| Host promotion, retained-slot rollback and product adoption | `platform` |
| Private pricing/commerce producer | `subscriptions`, with explicit cross-repository contract |

Keep the existing combined release path until the replacement application release path is independently qualified.

## Acceptance gates

1. Clean checkout of `website` alone installs dependencies and builds the static website.
2. No import, build step, Docker COPY or workflow checkout requires `marty-ui`.
3. Route contract and fallback behavior are tested against the application.
4. All public pages, language resources, images, fonts, favicon, manifest, robots, sitemap, RSS and llms assets are present.
5. Blog pages and demo catalog prerender correctly.
6. Public/private commerce boundaries are enforced.
7. Website producer provenance verifies the new repository/workflow identity.
8. Website image is digest-pinned and composition preserves original producer evidence.
9. Existing deployment promotion, rollback and product-adoption tests pass.
10. Actual host qualification occurs before production routing changes.

No website source has been moved in this audit PR.
