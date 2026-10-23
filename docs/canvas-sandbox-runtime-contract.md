# Canvas sandbox runtime contract

Frozen from the Python sandbox at `be17936d3` before the Rust port. The
language-neutral, normalized route observations are in
`contracts/canvas-sandbox-runtime-v1.json`; the Rust route test executes that
corpus. This is a beta test platform, with process-local mirror records and a
fresh Ed25519 key on start.

| Route | Observable behavior |
| --- | --- |
| `GET /health` | `200`, plain text `ok` |
| `GET /` | Service metadata, issuer, current `kid`, route inventory, connector hints |
| `GET /.well-known/openid-configuration` | LTI OIDC discovery; issuer/authorization/token/JWKS/registration URLs derived from sandbox host, scheme, and port; EdDSA, `id_token`, public subject, openid scope, LTI claims |
| `GET /api/lti/security/jwks` | One OKP Ed25519 public JWK, `use=sig`, `alg=EdDSA`, with the current signing `kid` |
| `GET /login/oauth2/auth` | Requires standard OIDC query fields; HTML auto-posts `id_token` and state to supplied redirect URI. JWT has EdDSA signature, one-hour expiry, nonce, client audience, sandbox deployment/context/roles/LTI claims and optional message hint. `scope`, `response_type`, `login_hint`, `prompt`, and `response_mode` are accepted but not policy checked. |
| `POST /api/lti/credentials/webhook` | Event defaults, current UTC `completion_at` when omitted; `409` without shared secret. Signs timestamp dot compact JSON body with HMAC-SHA256 and POSTs it to issuance `/v1/integrations/canvas/evidence-events` without following redirects. Relays upstream status plus parsed JSON below 500; malformed upstream JSON below 500 fails with `500`, and a transport error is `502`. |
| `POST /api/credentials/mirror/publish` | Optional exact Bearer token; object payload and `credential.id` validation; in-memory record keyed as `canvas-sandbox-<credential id>`; public credential and console provenance URLs; active response and 12-byte random request ID header. |
| `POST /api/credentials/mirror/status` | Same optional Bearer token; in-memory status event with 8-byte random suffix; updates known mirror record to lowercase status or `updated`; returns synced event ID and external ID. |
| `GET /api/credentials/mirror/{id}` | Same optional Bearer token; full mirror record or `404 credential_not_found`. |
| `GET /credentials/{id}` | Public HTML badge display or public 404 display; escapes untrusted values in HTML attributes and text. |

Mirrors and status events are intentionally ephemeral, as in the live runtime.
The `CANVAS_CREDENTIALS_PUBLIC_BASE_URL`, public host, and sandbox host
fallback rules determine display URLs. The issuer base URL determines console
provenance links. The public proxy and beta deployment checks expect the
service name `canvas-sandbox`, port 8017, and HTTP health check.
