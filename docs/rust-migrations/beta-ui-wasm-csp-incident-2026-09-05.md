# Beta UI WebAssembly CSP regression — 2026-09-05

## Evidence

The exact-source `v1.1.214` KMS-switching recording failed during organization
selection. The first recorder wrapper only reported its child exit code; the
preserved direct audit diagnostic located the timeout in `selectOrganization`.
A follow-up browser inspection passed the ElevenID Keycloak theme checks
(`login/11id/css/marty.css`, branded shell), authenticated successfully and found
the pilot membership eligible. The UI did not restore its organization state.

The browser reported WebAssembly initialization blocked by the published UI's
production CSP. The policy allowed same-origin scripts but omitted the explicit
WebAssembly compilation permission required by the Rust-backed UI modules.
Startup/HTTP health and release-marker probes did not exercise this behavior;
they must not be represented as full browser acceptance.

## Correction and scope

Add only `'wasm-unsafe-eval'` to the existing production `script-src` directive.
JavaScript `'unsafe-eval'` and script `'unsafe-inline'` remain absent; script
origins, connection limits and frame limits remain unchanged. This preserves
Rust ownership and does not replace the failing WASM modules with JavaScript.
See the [browser policy documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src).

An executable Chromium contract serves the actual configured CSP from a
loopback HTTP fixture. Same-origin streaming WASM compilation must succeed,
while JavaScript eval, Function construction and inline script execution remain
blocked. A negative control removes only the WASM permission and must reproduce
the blocked compilation. The existing browser CI lane executes this contract.

The separate preference-mode hypothesis was not used to change behavior: raw
backend mode `org_admin` was accepted while direct `org` returned HTTP400.
UI/API normalization must be respected; forcing localStorage or changing demo
expectations is not a fix for failed application startup.

No live container, production configuration or immutable `v1.1.214` source was
patched. The reviewed correction requires the normal release gates and a
beta-only follow-up rollout before release-bound recording can pass. Preserve
both failed recording attempts and rerun the complete scenario after deployment.
Custom-theme success alone does not prove the KMS-switching feature passed.
