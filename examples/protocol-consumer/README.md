# Public DID-first API examples

Run these examples against your authorized Marty deployment using Python 3.11 or later. They use public organization, template, DID and presentation-policy identifiers. The template selects compliance and lifecycle configuration; Marty resolves signing custody internally. Use an active template, an active compatible issuer DID, and a verification policy that trusts the issuer.

Fetch the gateway's canonical API document:

```powershell
python examples/protocol-consumer/client.py --base-url https://your-api.example schema
```

Set `MARTY_API_KEY` or `MARTY_BEARER_TOKEN` in your shell using your deployment's authorized credential. Configure one authentication method at a time. API keys need the corresponding issuance or verification permissions in the chosen organization.

Save a VCDM v2 credential object matching your template's claims to `credential.json`, then issue it:

```powershell
python examples/protocol-consumer/client.py --base-url https://your-api.example --organization-id ORG_ID --output issued-response.json issue --template-id TEMPLATE_ID --issuer-did did:web:your-issuer.example --credential credential.json
```

Verify the returned credential using a presentation policy. The example extracts `verifiableCredential` from the issuance response automatically:

```powershell
python examples/protocol-consumer/client.py --base-url https://your-api.example --organization-id ORG_ID verify --policy-id POLICY_ID --credential issued-response.json
```

For deployments exposing `/api/v1/...`, use `https://your-host.example/api` as the base URL for issue/verify. Fetch the public schema from the origin using the first command. HTTP redirects fail instead of forwarding credentials. A failed verification is a verification result: inspect its result fields even when the HTTP request succeeds. These direct credential operations do not initiate wallet/QR journeys; those use the deployment's flow API.

The automated example tests exercise the real CLI over local HTTP fixtures. They validate request construction and credential handling; they do not establish live interoperability or KMS custody qualification.
