# Controlled DID resolution

Verification services resolve organization-owned `did:web` documents through
the configured internal resolver first. Parsing, document validation, egress
policy, retrieval limits, and provenance are owned by `marty-didcomm` and
called through the required `_marty_rs` binding. The Python module is only an
async DTO/configuration adapter and requires the `did_resolution` capability in
native readiness diagnostics.

## Environment addresses

Keep service routing separate from the externally advertised identity and API
origin. Docker Compose service names such as `gateway` and `organization` are
appropriate for communication between containers on their shared network. A
browser or external wallet needs an address reachable from its own network.

| Environment | Internal service routing | Advertised HTTPS origin |
| --- | --- | --- |
| Local development and isolated tests | Docker service names | A test hostname with the test client's DNS and CA configured |
| Production-like beta | Docker service names | `https://beta.elevenidllc.com` |
| Production | Docker service names | `https://elevenidllc.com` |

For beta, set `PUBLIC_DOMAIN=beta.elevenidllc.com` and
`PUBLIC_API_URL=https://beta.elevenidllc.com`; for production use
`PUBLIC_DOMAIN=elevenidllc.com` and `PUBLIC_API_URL=https://elevenidllc.com`.
The environment's deployment configuration owns these settings. The console
must use the API's canonical publication URL rather than deriving it from the
browser origin or an internal Docker URL. Existing DID identifiers retain
their original authority: changing an environment setting does not migrate an
issued credential's issuer DID or establish trust in another environment.

Local registry resolution and locally trusted HTTPS tests do not prove public
network retrieval. The public fallback policy below deliberately rejects
private Docker addresses and non-default HTTPS ports. Keep that policy intact;
use the organization registry for local identities and a reachable public
HTTPS publication endpoint for external resolution. Public readiness requires
an actual successful retrieval with the expected DID document, not just DNS
records or a provisioned key. An authentication challenge, access-denied
response or unavailable route is a publication failure for that resolver.

Public network fallback is disabled by default and must be enabled by
deployment configuration, never by a credential or API request.

```env
DID_RESOLUTION_BASE_URL=http://gateway:8000
DID_PUBLIC_FALLBACK_ENABLED=false
DID_WEB_ALLOWED_HOSTS=issuer.example.com,partner.example.org
```

When public fallback is enabled, every hostname must be listed exactly in
`DID_WEB_ALLOWED_HOSTS`. IP literals, non-default HTTPS ports, private DNS
answers, redirects, unsafe encoded paths, oversized or deeply nested documents,
unexpected media types, mismatched DID/controller values, duplicate method ids,
and invalid verification relationships fail closed. The resolver pins the
validated public address for the request and returns retrieval time, source, and
a canonical content digest as provenance.

Deployment egress policy should still deny private, link-local, metadata, and
service-network destinations. Native validation is defense in depth, not a
replacement for a firewall or controlled outbound proxy. If the native backend
or capability is unavailable, resolution fails closed with
`NativeBackendUnavailable`; there is no Python resolver fallback.
