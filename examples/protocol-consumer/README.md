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
