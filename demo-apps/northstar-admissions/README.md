# Northstar Admissions

Northstar is the synthetic external application for D-11. It is deliberately
separate from the Marty UI and sends every Marty-bound request through the
configured public gateway origin. Its client rejects other origins and all
non-`/v1/` paths.

`scripts/prepare.mjs` creates the webhook, subscription, submitted application,
and scoped API keys through the same public routes used by the UI. It requires
public OIDC session cookies and writes secrets only to a new mode-0600 output
file. Start the receiver with `NORTHSTAR_RUN_SECRET_FILE` pointing to that file.
Keep the output outside the repository, or use an ignored
`.northstar-run*.json` filename in this directory.
The bootstrap key is revoked in a `finally` block; the protected file contains
separate runtime, read-only negative-test, and `webhooks:read` evidence keys.

The callback verifies Marty's canonical HMAC-SHA256 signature, binds event
headers to the signed body, checks organization and application scope, and
processes a valid event only once.
After the callback returns, the server uses the evidence key to retrieve and
bind the persisted delivery record through `/v1/webhooks/{id}/deliveries`.

Run unit tests with `npm test`. The public deployment is expected at
`https://admissions-test.elevenidllc.com`, with `/webhooks/marty` routed to this
service through the existing beta tunnel.
