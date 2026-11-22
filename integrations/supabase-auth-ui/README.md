# Supabase authorization UI

Static, framework-free email/password sign-in, enrolled TOTP verification and
OAuth consent for explicitly registered ElevenID and Rifare clients.

```sh
bun install --frozen-lockfile --ignore-scripts
bun test
bun build.mjs --config public/config.example.json
```

The example is deliberately synthetic and uses reserved `.invalid` domains.
The build makes no provider requests. `dist/` contains static assets, public
configuration, Cloudflare `_headers` and exact consent-path rewrites. It has no
Functions or backend. Bun 1.4.4 and `@supabase/supabase-js` 2.119.2 were used for
the local build and tests.

Read the [operator guide](../../docs/supabase-auth-ui.md) for public configuration,
provider/client registration, session behavior and the remaining hosted
qualification gates. Registration, recovery and MFA enrollment are outside this
companion's scope.
