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
It also retains a privacy-safe inventory of preparation requests (origin,
method, public path, authentication class, and idempotency identifier). The
server validates that inventory against the exact configured gateway before it
starts and exposes only that safe inventory to the recorder.

The callback verifies Marty's canonical HMAC-SHA256 signature, binds event
headers to the signed body, checks organization and application scope, requires
the signed event correlation ID to equal the successful gateway approval
request ID, and processes a valid event only once.
After the callback returns, the server uses the evidence key to retrieve and
bind the persisted delivery record through `/v1/webhooks/{id}/deliveries`. The
delivery record must preserve that same correlation ID or the run fails closed.

Run unit tests with `npm test`. The public deployment is expected at
`https://admissions-test.elevenidllc.com`, with `/webhooks/marty` routed to this
service through the existing beta tunnel.

Deploy it only after preparation creates the run-scoped secret file. The
dedicated `docker-compose.profile.northstar-admissions.yml` overlay mounts that
file as a read-only Compose secret, binds the app to the beta network, and makes
the tunnel proxy wait for `/health`. Set `NORTHSTAR_RUN_SECRET_FILE` to the
protected host path and combine the overlay with the normal beta/tunnel compose
files. Use the `tunnel-beta-d11` stack descriptor for the governed topology.

The Cloudflare tunnel must have a public-hostname entry for
`admissions-test.elevenidllc.com` pointing at
`http://tunnel-nginx-proxy:80`. DNS/tunnel provisioning remains an operator
step; the repository nginx route fails closed if the Northstar container is not
healthy.

The D-11 overlay enables two Northstar-only receiver test controls for the
separate uncut resilience runs. They never call Marty: one submits a tampered
signature to the receiver and one replays the last valid signed envelope. The
duplicate run must follow the positive run without restarting Northstar so the
in-memory, already-processed event remains available. Browser responses contain
only the receiver status, event identifier, and whether admissions state stayed
unchanged; signatures and the signing secret remain server-side.
