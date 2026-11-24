# Supabase authorization UI

Static, framework-free email/password sign-in, enrolled TOTP verification and
OAuth consent for explicitly registered ElevenID and Rifare clients. The opt-in
v3 configuration also supplies password recovery pages; live delivery and
provider settings require separate qualification.

```sh
bun install --frozen-lockfile --ignore-scripts
bun test
bun build.mjs --config public/config.example.json
```

Build from a repository checkout. Keycloak and Pages use the same header, main
landmark, responsive layout and brand colors from `config/keycloak/themes/11id/login/auth-layout.ftl`
and `resources/css/auth-layout.css` under that directory. Keycloak supplies its
language selector and provider forms through FreeMarker slots. The static build
fills the content slot with the loading screen, then the browser renders the
sign-in, TOTP and consent forms. The Helm chart packages the same theme files.

The example is deliberately synthetic and uses reserved `.invalid` domains.
The build makes no provider requests. `dist/` contains static assets, public
configuration, Cloudflare `_headers` and exact consent-path rewrites. It has no
Functions or backend. Bun 1.4.4 and `@supabase/supabase-js` 2.119.2 were used for
the local build and tests.

Read the [operator guide](../../docs/supabase-auth-ui.md) for public configuration,
provider/client registration, session behavior and the remaining hosted
qualification gates. Signup, email confirmation and MFA enrollment remain
additional product work; the recovery implementation does not complete those
account-lifecycle requirements.
