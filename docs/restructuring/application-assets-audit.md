# Application public asset audit

This audit identifies the next bounded source-absence batch after the
[45-input application build and test rehearsal](application-build-boundary.md).
It does not establish that the additional assets can already be absent before
the build, and it is not a source deletion manifest.

## Observed boundary

The clean rehearsal for `10ce5784eb6a49a925c5c629c56e546beaae1e7a`, recorded in
[PR #2001](https://github.com/ElevenID/marty-ui/pull/2001), inventories 84 public
source files. All 84 files were compared by size and SHA-256 with the source
used for this audit. They are unchanged. The application output retains 54 of
those files byte for byte: 42 translation files and 12 other resources. It
excludes exactly 30 public inputs.

The original 37-input rehearsal already omits three raw demo manifests before
building. The next 45-input rehearsal also omits English `marketing.json`.
The remaining 26 public files below are candidates for absence before the build.
They total 17,105,464 bytes and would expand the bounded omission set to 71.
For comparison, the delta from the initial 37-input rehearsal is 27 files,
including English marketing translations, for 17,116,003 bytes.

`ui/scripts/prune-selfhost-dist.mjs` and the exact exclusions in
`ui/scripts/selfhost-build-contract.mjs` explain their absence from the current
application output. Vite currently copies the public directory before this
pruning. Absence from final output alone does not establish independence from
these files during configuration, compilation or tests.

## Exact additional application omissions

Keep a closed path roster rather than omitting whole image or locale trees.
Future application assets must not silently inherit website ownership.

```text
ui/public/blog/rss.xml
ui/public/images/authors/aiko-tanaka.png
ui/public/images/authors/daniel-ortega.png
ui/public/images/authors/elena-kovacs.png
ui/public/images/authors/marcus-vale.png
ui/public/images/authors/nora-patel.png
ui/public/images/authors/sofia-rahman.png
ui/public/images/authors/victor-leclerc.png
ui/public/images/demos/2026.07.0/canvas-learning-achievement.png
ui/public/images/demos/2026.07.0/credential-lifecycle.png
ui/public/images/demos/2026.07.0/first-party-browser-wallet.png
ui/public/images/demos/2026.07.0/independent-wallet-interoperability.png
ui/public/images/demos/2026.07.0/membership-badge-login.png
ui/public/images/demos/2026.07.0/organization-primitives.png
ui/public/images/demos/2026.08.0/portfolio-draft.svg
ui/public/images/demos/2026.08.1/portfolio-draft.svg
ui/public/images/social/elevenid-blog-default.png
ui/public/images/social/trust-profiles-explained.png
ui/public/images/social/understanding-csca-certificates-v2.png
ui/public/images/social/why-identity-needs-a-protocol.png
ui/public/llms.txt
ui/public/locales/de/marketing.json
ui/public/locales/es/marketing.json
ui/public/locales/fr/marketing.json
ui/public/locales/ja/marketing.json
ui/public/locales/nl/marketing.json
```

The three raw demo inputs and English marketing locale remain in the existing
omission set. This list is additional to that set, not a replacement.

## Resources that must remain

| Retained resources | Reason and required check |
| --- | --- |
| Seven namespaces in all six languages: `common`, `console`, `onboarding`, `forms`, `errors`, `applicant`, `vendor`; `en`, `de`, `es`, `fr`, `ja`, `nl` | `ui/src/i18n/index.js` uses an HTTP backend, language detection and English fallback. Preserve all 42 JSON files and their exact source bytes; exercise a non-English request and a missing-key English fallback. |
| `runtime-config.js`, `startup.js` | Both HTML entrypoints load them before the application module. The production startup script rewrites runtime configuration; the startup helper detects and handles failed module/WASM loading. |
| `config.json`, `apple-touch-icon.png` | `BrandingContext.jsx` fetches configuration dynamically. The mobile console header uses the default icon when no deployment-defined logo is configured. |
| `manifest.json`, `favicon.ico`, `logo192.png`, `logo512.png` | Resolve the manifest's relative icon URLs against the actual output and verify the referenced bytes. |
| `favicon.svg`, `favicon-96x96.png` | Existing crawler/startup checks recognize these shared assets; this audit does not establish exclusive website ownership. |
| `.well-known/ai-plugin.json`, `test-harness.html` | The former has explicit edge/console routing; the latter supports application and wallet QA. Both remain in the current application output. |

These 54 public resources total 3,453,664 bytes in the observed output.
Partial non-English dictionaries make preservation of English fallback
resources necessary. A null default branding logo does not qualify arbitrary
deployment-defined logo URLs. All observations concern the selected public
application profile; they do not qualify private commerce assets.

## Next acceptance gate

1. Omit the exact 26 additional paths in a disposable export, then run the
   unchanged application build and selected application tests. Require every
   omission to remain absent after both children and preserve the original
   source inventory, byte hashes, file modes and Git status.
2. Verify all 42 locale files and 12 other retained public resources, including
   exact source-byte preservation. Parse both built HTML entrypoints and the
   manifest so every local referenced resource resolves to an actual output
   file. A successful SPA fallback is not a valid asset response.
3. Serve the same exported output for a bounded resource smoke check. Check
   bytes and content types for configuration, startup scripts, locale JSON,
   manifest/icons and emitted JavaScript/WASM; fail on HTML masquerading as
   another resource. Observe real locale requests, English fallback, default
   branding/mobile logo loading and application startup. Include a missing
   required locale, icon or script to show that the probe detects breakage.
4. Keep this evidence separate from independent dependencies, signed
   application publication and actual host/OIDC qualification. Preserve the
   existing combined and website defaults. Puppeteer remains used by
   `ui/scripts/public-verification-browser.mjs` for application QA and cannot
   be classified as website-only solely from this audit.

The source and output comparison is complete. The additional prebuild absence
and served-resource/browser gates remain unexecuted at this audit checkpoint.
