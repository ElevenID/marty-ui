# Supabase authorization UI

Static, framework-free email/password sign-in, enrolled TOTP verification and
OAuth consent for explicitly registered ElevenID and Rifare clients. The opt-in
v3 configuration also supplies signup, email confirmation, initial authenticator
enrollment and password recovery pages; live delivery and
provider settings require separate qualification.
The v4 configuration additionally pins final redirect origins when an API
callback sends the browser to a separately hosted console.

```sh
bun install --frozen-lockfile --ignore-scripts
bun test
bun build.mjs --config public/config.example.json
```

Use `public/config.split-origin.example.json` as the synthetic v4 example.
`postRedirectOrigins` contains exact HTTPS origins needed after the native
callback POST; it does not register another destination for the MFA proof.

Build from a repository checkout. The application, standalone website, Keycloak
and Pages use the general header factory and styles in `ui/src/shared/web-layout`.
Thin React and HTML adapters retain each consumer's actions. Keycloak's existing
FreeMarker layout and stylesheet are generated from that source and packaged
identically in Helm. The static builder checks those generated files and fills
the content slot with the loading screen. Its HTML and runtime configuration
both use `config.brand`; the public examples use **ElevenID LLC**. Read the
[shared-layout guide](../../docs/shared-web-layout.md) before changing the source.

The existing Fast Feedback CI lane installs the locked companion dependencies
with hooks disabled, runs its full test suite and builds default and v3 examples.
This is source verification; it does not configure or contact a live provider.

The example is deliberately synthetic and uses reserved `.invalid` domains.
The build makes no provider requests. `dist/` contains static assets, public
configuration, Cloudflare `_headers` and exact consent-path rewrites. It has no
Functions or backend. Bun 1.4.4 and `@supabase/supabase-js` 2.119.2 were used for
the local build and tests.

Read the [operator guide](../../docs/supabase-auth-ui.md) for public configuration,
provider/client registration, session behavior and the remaining hosted
qualification gates. These account pages have synthetic browser coverage;
live email delivery, provider mutations and the installed application journey
must still qualify before production use. Lost-authenticator recovery and
replacement of existing verified factors are outside these setup pages.
