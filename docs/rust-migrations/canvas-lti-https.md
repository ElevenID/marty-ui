# Actual AGS/NRPS HTTPS provider gate

Status: implemented, compiled and linted locally; actual Linux execution is
pending hosted CI. Windows's unconfigured child-test return is not HTTPS proof.
No runtime or production TLS policy changes are included.

The existing OAuth test executable includes a Linux parent test that runs
`scripts/test_canvas_lti_https.py`. The script owns an ephemeral loopback HTTPS
server and a temporary, short-lived synthetic certificate/key. It first runs a
child with ordinary system roots and requires rejection without an HTTP request.
It then runs a separate child with that certificate in `SSL_CERT_FILE`; only
the child process receives this trust setting. No machine trust store is altered.
The script stops its server, waits for its thread and removes temporary inputs.
Bounded subprocess deadlines kill and wait for a failed child before cleanup.

The actual `HttpCanvasAuthoritativeProvider` performs token, AGS and NRPS HTTPS
requests under the real self-managed-origin trust profile and exact origin
allowlists. `allow_http_localhost` and broad private-network permission stay off.
An injected synthetic signer records claims; this does not qualify cryptographic
LTI signing, which remains a separate responsibility. OAuth fixtures are reused.

The server and Rust child jointly verify:

- exact client-credentials form, assertion type, client ID, and AGS/NRPS scopes;
- signing claims' issuer, subject, audience, five-minute lifetime and unique IDs;
- result/membership Accept headers, bearer tokens and learner subject query;
- full learner AGS assertion/payload/timestamp projection with name omitted;
- empty AGS results as negative evidence and429 Retry-After37 preservation;
- missing verified NRPS binding metadata prevents token/provider requests;
- two-page NRPS discovery retains the active opaque subject only, with no
  numeric identity, name/email or preloaded issuance evidence.

Successful script completion also requires exact counts: four token requests,
three AGS reads and two NRPS pages. A missing/filtered child test cannot silently
pass. The mandatory CI step separately selects one compiled OAuth executable,
verifies the Linux parent test is registered, and runs it explicitly with logs.

This is a real synthetic-provider HTTPS gate, not a complete published-Python/
native transport differential or all-provider error matrix. The existing frozen
roster and review corpora are unchanged. Broader HTTP parity, concurrency/audit
rollback, manual review endpoints, readiness, every deployment consumer and beta
acceptance still precede Python deletion. The worker remains unrouted.
