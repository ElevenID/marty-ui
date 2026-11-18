# Beta demo CSP follow-up

## Observed failure

The v1.1.216 beta public-demo gate passed exact release/source binding but failed
six browser checks. Five responsive/catalog/scenario checks observed a blocked
Cloudflare Web Analytics script injected by the existing edge configuration.
The consented video check created the correct privacy-enhanced iframe, but
`frame-src 'self'` prevented its request. This is a delivery/configuration gap,
not evidence that Rust credential issuance lost functionality.

## Feature-preserving repair

Retain the enforcing CSP, same-origin defaults, WebAssembly compilation, existing
documentation CDNs, and all existing style/font/image restrictions. Add only:

- `script-src https://static.cloudflareinsights.com` for the configured beacon.
- `connect-src https://cloudflareinsights.com` for its telemetry endpoint.
- `frame-src https://www.youtube-nocookie.com` for the consent-gated video player.

These follow [Cloudflare's documented CSP requirements](https://developers.cloudflare.com/fundamentals/reference/policies-compliances/content-security-policies/)
and [YouTube's privacy-enhanced embedding guidance](https://support.google.com/youtube/answer/171780).
No wildcard, JavaScript eval, inline-script permission, ordinary YouTube iframe,
new analytics feature, or automatic video loading is introduced.

## Verification and acceptance boundary

The real Chromium regression reads the actual nginx policy. It requires zero
third-party requests before the fixture's explicit player consent, then renders
the privacy-enhanced frame and allows the configured beacon and telemetry.
Third-party responses are local test fixtures; the browser still enforces CSP.
Ordinary YouTube and lookalike origins remain blocked. Existing tests prove
same-origin WASM works while eval, Function and inline scripts remain blocked;
removing the WASM permission remains a negative control.

The unmodified policy failed the new allowlist and actual iframe-rendering tests.
The corrected policy passes. These tests do not prove deployed beta is repaired:
the immutable v1.1.216 image remains unchanged. A future protected aggregate
release/deployment must rerun the unchanged public-demo and full lifecycle gates.
No production deployment or edge configuration change is part of this patch.
