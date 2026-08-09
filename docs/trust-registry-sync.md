# Trust registry synchronization

Marty consumes external registries through the versioned
`MARTY_TRUST_REGISTRY_SYNC_V1` adapter contract. A public caller selects only
the adapter URL and refresh interval in a Trust Profile. It cannot select a
network route, TLS policy, credential, key, or provider.

Registry destinations use HTTPS on port 443, disable redirects and proxy
environment variables, pin the validated DNS result for the request, retain
the original host for TLS SNI and HTTP authority, require a JSON response, and
enforce page, payload, entry, sequence, and certificate bounds. Failed refreshes
do not partially change effective trust. Unsynchronized, stale, corrupt, or
expired imported material fails closed.

By default, every resolved address must be globally routable. Operators that
run a registry on an internal network may configure an exact, comma-separated
DNS hostname allowlist with `TRUST_REGISTRY_PRIVATE_HOST_ALLOWLIST`. IP
addresses, wildcards, loopback, link-local, multicast, unspecified, and
reserved destinations remain prohibited. This is process configuration and is
never accepted from a public API request.

An internal registry using a private certificate authority can add that CA to
normal Web PKI validation with `TRUST_REGISTRY_TLS_CA_FILE`. Certificate and
hostname verification remain mandatory. The default production Compose files
set neither option; the isolated conformance overlay uses both for its
project-scoped disposable adapter.
