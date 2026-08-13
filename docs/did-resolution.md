# Controlled DID resolution

Verification services resolve organization-owned `did:web` documents through
the configured internal resolver first. Parsing, document validation, egress
policy, retrieval limits, and provenance are owned by `marty-didcomm` and
called through the required `_marty_rs` binding. The Python module is only an
async DTO/configuration adapter and requires the `did_resolution` capability in
native readiness diagnostics.

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
