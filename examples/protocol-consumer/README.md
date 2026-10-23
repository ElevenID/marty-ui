# Public DID-first API examples

Run these examples against your authorized Marty deployment using Python 3.11 or later. They use public organization, template, DID and presentation-policy identifiers. The template selects compliance and lifecycle configuration; Marty resolves signing custody internally. Use an active template, an active compatible issuer DID, and a verification policy that trusts the issuer.

Fetch the gateway's canonical API document:

```powershell
python examples/protocol-consumer/client.py --base-url https://your-api.example schema
```

Set `MARTY_API_KEY` or `MARTY_BEARER_TOKEN` in your shell using your deployment's authorized credential. Configure one authentication method at a time. API keys need the corresponding issuance or verification permissions in the chosen organization.

Discover issuer creation options using an API key with `keys:read` (or `keys:write`):

```powershell
$apiBase = 'https://your-api.example'
$organizationId = [uri]::EscapeDataString('ORG_ID')
$headers = @{ 'X-API-Key' = $env:MARTY_API_KEY }
$capabilities = Invoke-RestMethod "$apiBase/v1/signing-keys/issuer-identities/capabilities?organization_id=$organizationId" -Headers $headers -MaximumRedirection 0
$capabilities.creation_options
```

Choose a complete `key_purpose` / `credential_format` / `algorithm` tuple from this response and use its `managed_issuer_did_prefix` when creating a managed issuer identity. Refresh discovery after organization or configuration changes. These are configuration-derived creation options; issuance compatibility, provider health and public DID resolution are checked in their respective workflows. Empty options or an unavailable response block creation. The console rechecks the selected tuple before provisioning.

Before creating a credential template, call `POST /v1/credential-templates/issuer-options` with your `organization_id`, active `compliance_profile_id`, and optional `credential_payload_format` and `supported_formats`. This operation requires the same organization permission as template creation. It returns the derived format, issuance protocol, required VCT/doctype/lifecycle fields and compatible public issuer DIDs. Every declared format must resolve unambiguously to its intended signing purpose. Ambiguous DIDs appear only in `rejected_issuers`; no algorithm or private key/profile selector can resolve that ambiguity through this API. Unavailable discovery blocks selection. Template creation repeats these checks, so refresh options if the registry or compliance profile changes. Compatibility discovery does not establish provider health or DID publication.

Inspect an exact public tuple returned by `GET /v1/signing-keys/issuer-identities?organization_id=ORG_ID` using `keys:read` (or `keys:write`):

```powershell
python examples/protocol-consumer/client.py --base-url https://your-api.example --organization-id ORG_ID inspect --issuer-did did:web:your-issuer.example:orgs:your-org --purpose vc_jwt_issuer --format SD_JWT_VC --algorithm ES256
```

The response separates organization registry material, current managed-signer matching and fresh public HTTPS resolution. Use its `canonical_document_url` to view publication. Stored documents may be a labeled legacy projection; their presence does not prove public reachability. `assertion_ready` requires matching stored/public keys and assertion authorization; it does not qualify credential issuance, certificate trust or interoperability. Failed public resolution preserves the stored document for inspection. Refresh after publication or key rotation. Certificate state describes expiry and public-key matching, without establishing chain trust. Only the configured publication authority is probed, with bounded timeouts and no internal resolution fallback or private selectors.

The console keeps these public identity operations under **Deploy > Issuer Identity**. Connector endpoints, provider credentials, key references and rotation are in **Operator > Key Management**. Operator metadata requires `signing-key:view`; registering or changing services requires `signing-key:create` in the console. Existing API-key `keys:read` / `keys:write` rules are unchanged. Legacy console URLs redirect through the same permission guards.

Browser integrations use `issuerIdentitiesApi` for DID discovery, inspection, certificate/CSR operations and retirement. `signingKeysApi` owns operator configuration and retains compatibility exports for older integrations. Public requests use the organization and DID tuple; they do not select a signing-service ID or provider key reference. Trusting external issuers does not require local KMS setup. The dashboard's active-DID setup state does not establish live signer health or public publication.

Save a VCDM v2 credential object matching your template's claims to `credential.json`, then issue it:

```powershell
python examples/protocol-consumer/client.py --base-url https://your-api.example --organization-id ORG_ID --output issued-response.json issue --template-id TEMPLATE_ID --issuer-did did:web:your-issuer.example --credential credential.json
```

Verify the returned credential using a presentation policy. The example extracts `verifiableCredential` from the issuance response automatically:

```powershell
python examples/protocol-consumer/client.py --base-url https://your-api.example --organization-id ORG_ID verify --policy-id POLICY_ID --credential issued-response.json
```

For deployments exposing `/api/v1/...`, use `https://your-host.example/api` as the base URL for issue/verify or discovery. Fetch the public schema from the origin using the first command. HTTP redirects fail instead of forwarding credentials. A policy or signature rejection returns HTTP 422, which this CLI reports as an error. The canonical OpenAPI documents verification rejection and other error envelopes. These direct credential operations do not initiate wallet/QR journeys; those use the deployment's flow API.

The automated example tests exercise the real CLI over local HTTP fixtures. They validate request construction and credential handling; they do not establish live interoperability or KMS custody qualification.
