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

Validate the complete read-only composition before issuing or verifying:

```powershell
python examples/protocol-consumer/client.py --base-url https://your-api.example --organization-id ORG_ID composition --trust-profile-id TRUST_PROFILE_ID --template-id TEMPLATE_ID --policy-id POLICY_ID --deployment-profile-id DEPLOYMENT_PROFILE_ID --issuance-flow-id ISSUANCE_FLOW_ID --verification-flow-id VERIFICATION_FLOW_ID
```

This command first reads the public `/v1/protocol-support` catalog without credentials. It then loads the selected trust profile, credential template, presentation policy, deployment profile, issuance flow and verification flow; follows the template's compliance and optional revocation profile references; rejects any resource outside the chosen organization; and checks every cross-resource link. A system compliance profile is accepted only when the response explicitly marks it as a system profile with no organization owner. Finally, it requires the gateway-composed organization runtime status to report both `can_issue` and `can_verify`. The output contains public IDs, lifecycle states and runtime readiness only. It never accepts or returns a provider, signing-service ID, KMS key reference or private key. A successful composition check establishes reference consistency and gateway readiness at that moment; issuance and policy-bound cryptographic verification below remain separate operations.

For API-key composition checks, grant `trust:read` (trust, presentation policy and revocation profile), `templates:read`, `compliance:read`, `deployment:read`, `flows:read`, and `users:read` (organization runtime status) in the selected organization. Corresponding writer scopes can also authorize reads. Revocation-profile discovery does not grant credential-revocation authority. Bearer sessions need the corresponding organization read permissions.

`flows:read` authorizes Flow Definition metadata used by composition. Native Flow Instance reads, results, artifacts and controls require `flows:execute` or `flows:write`; artifacts can include wallet invitations. A metadata-only composition key therefore cannot inspect or change runtime executions.

The console exposes confirmed step-outcome recording with `flow-instance:advance` and execution cancellation with `flow-instance:cancel`. It re-reads the selected organization's current execution before posting the native outcome and requires refresh after an error or changed step. An operator-recorded step result is separate from credential verification. Wallet acceptance notifications do not automatically advance the flow. Cancelling an execution leaves credential offers and issued credentials under their separate native lifecycles.

The `issue` command uses the VC-API Data Integrity adapter. Select an active `JSON_LD` (VCDM v2 Data Integrity) template and compatible public issuer DID. Save an unsigned VCDM v2 credential object matching that template's claims to `credential.json`, then issue it:

```powershell
python examples/protocol-consumer/client.py --base-url https://your-api.example --organization-id ORG_ID --output issued-response.json issue --template-id TEMPLATE_ID --issuer-did did:web:your-issuer.example --credential credential.json
```

SD-JWT, JWT VC and mdoc templates use the native issuance workflow: initiate `POST /v1/issuance` with the organization, credential template, public issuer DID and format-appropriate claims; redeem the resulting credential offer through the advertised OID4VCI token, nonce and credential endpoints using the wallet's holder proof. Sending a complete `credential_document` through the VC-API adapter for these formats is rejected. Capability discovery describes supported signing tuples; it does not make every format compatible with this Data Integrity command.

Verify the returned credential using a presentation policy. The example extracts `verifiableCredential` from the issuance response automatically:

```powershell
python examples/protocol-consumer/client.py --base-url https://your-api.example --organization-id ORG_ID verify --policy-id POLICY_ID --credential issued-response.json
```

For deployments exposing `/api/v1/...`, use `https://your-host.example/api` as the base URL for issue/verify or discovery. Fetch the public schema from the origin using the first command. HTTP redirects fail instead of forwarding credentials. A policy or signature rejection returns HTTP 422, which this CLI reports as an error. The canonical OpenAPI documents verification rejection and other error envelopes. These direct credential operations do not initiate wallet/QR journeys; those use the deployment's flow API.

The automated example tests exercise the real CLI over local HTTP fixtures. They validate request construction and credential handling; they do not establish live interoperability or KMS custody qualification.


The console exposes the native compliance lifecycle at **Govern > Compliance Profiles**: inspect an immutable system preset, copy its public requirements into an organization-owned draft, edit only changed metadata, activate it, then select it when creating a credential template. Suspension and deletion use the owner's separate permissions. The public list is paginated. Template issuer options remain the compatibility check for the chosen compliance profile and every declared format; activation alone does not prove signer health, public DID publication or interoperability.

Equivalent API operations are `GET /v1/compliance-profiles?organization_id=ORG_ID&limit=50&offset=0`, authenticated/scoped `GET /v1/compliance-profiles/system/discoverable`, `POST /v1/compliance-profiles`, `GET`/`PATCH`/`DELETE /v1/compliance-profiles/PROFILE_ID`, and `POST .../activate` or `POST .../suspend`. The catalog requires the gateway's existing `compliance-profile:view` grant. Lifecycle operations require their corresponding `activate` or `suspend` grant; API keys use `compliance:write` for mutations and `compliance:read` or `compliance:write` for reads.

Canonical OpenAPI uses service-owned `runtime__compliance_profile_*` schemas and marks this resource's protocol coverage `partial`. The native metadata projection implements format, protocol, artifact/trust requirements, public API surface and lifecycle, rather than the protocol entity's full feature vocabulary. Seven internal privacy-policy sections are accepted by the native request contract but intentionally absent from public responses. A public metadata editor must preserve them by omitting unchanged fields; it cannot infer them from an output model. New organization profiles use service privacy defaults. In sparse PATCH, omission/null preserves stored fields, while explicit false, empty strings, arrays and objects are changes subject to validation. System presets remain immutable. The old client-only `validateIssuerArtifacts` operation is explicitly unsupported; there is no corresponding compliance API route.


### Authorization Policy Sets

At **Govern > Policy Sets**, select a provider template, inspect or edit its
Cedar statements, validate them, and create an organization-owned draft. The
template catalog contains global presets; the resulting Policy Set has an
explicit organization owner. Draft metadata editing sends only changed name
or description fields; clearing the description sends `null` and preserves
Cedar statements, type and schema settings. The console limits this editor to
drafts; the native PATCH API's broader update semantics remain unchanged.

The public gateway accepts `GET /v1/policy-sets`, `GET .../templates`,
`GET .../POLICY_SET_ID`, `POST /v1/policy-sets`, `POST .../validate`,
`PATCH .../POLICY_SET_ID`, and `POST .../POLICY_SET_ID/activate` or
`POST .../POLICY_SET_ID/archive`, each with `organization_id=ORG_ID`.
Reads require `policy-set:view`, metadata PATCH requires `policy-set:edit`,
and draft creation requires `policy-set:create`. The existing gateway uses
separate `policy-set:validate`, `policy-set:activate` and `policy-set:archive`
grants for those operations. The wizard validates before creating and therefore
requires both create and validate permission.
Activation archives the previously active Policy Set of the same type in that
organization. A workflow must consume the selected Policy Set to evaluate its
Cedar statements; activation alone does not demonstrate a runtime decision or
replace the gateway's membership grants.
Activation and archive require explicit confirmation in the console. Their
fresh scoped read prevents acting on an already changed snapshot; it is not
an atomic version precondition. The server remains the authorization and
mutation authority. Policy Sets are Cedar authorization configuration, not
presentation policies or cryptographic verification receipts.

See [environment addresses and DID resolution](../../docs/did-resolution.md)
for the distinction between Docker service routing, beta/public origins and
actual publication readiness.

### Derived wallet requirements

Open a credential template and choose **Wallet profile** to read `GET /v1/credential-templates/TEMPLATE_ID/wallet-compatibility`. The native service authorizes the template's owning organization and derives the primary credential format, issuance protocol and compliance key, then applies organization registry overrides. The view shows the derivation tuple, configured applications, specifications, platforms, applied override IDs, merge metadata and template wallet configuration. Other declared formats need separate qualification. Physical documents have no wallet profile.

The standard-library example can read this same public projection without an issuance request or credential file:

```sh
python examples/protocol-consumer/client.py --base-url https://api.example --organization-id ORG_ID wallet-profile --template-id TEMPLATE_ID
```

Use the existing environment authentication described above. This command requires `credential-template:view` (API key `templates:read` or `templates:write`). `GET /v1/wallet-registry/resolve/profile?organization_id=ORG_ID&credential_format=FORMAT&issuance_protocol=PROTOCOL&compliance_profile_code=CODE` resolves a supplied tuple under `wallet:view`; it does not load or validate a template, and unknown tuples can return generic requirements. A generic fallback retains its original compliance key for scoped override matching. OpenAPI describes both operations with the actual `runtime__wallet_compatibility` projection, marks support `derived`, and references the pinned WalletProfile vocabulary separately. The native result includes derivation and applied-override fields beyond that pinned schema, so clients must not treat it as an exact pinned WalletProfile entity.

Registry entries and derived application/platform names are configuration, not independently verified wallet interoperability or delivery evidence. Deep-link patterns are displayed as text rather than executed as test links. Dependency failures remain visible and retryable; the console does not replace them with guessed wallet support.

Delivery destinations are a separate abstraction. Reads require the existing `wallet:view` grant (API key `wallet:read` or `wallet:write`), preserving applicant claim-dialog reads. Creates, sparse updates and deletes require `integration-connector:create`, `integration-connector:edit` and `integration-connector:delete` respectively (API key `integrations:write`). The gateway checks the selected organization and resolves stored destination ownership before forwarding. The console uses these same catalog grants instead of an unseeded delivery-destination permission. A configured/enabled destination does not establish approval, successful delivery or wallet compatibility. Template detail and destination loaders discard results after organization changes; Canvas observations require their separate integration read grant.


### Notifications and embedded targets

The console notification inbox reads the selected organization and authenticated recipient through the native array API. It displays the service-owned read state and message body, acknowledges notifications, confirms deletion and pages recorded delivery attempts. A returned notification is not proof of delivery; inspect each attempt's success/error/retry metadata. The bell and dropdown use the same scoped selectors and discard late responses after an organization or principal change. Notification links in the dropdown are limited to safe console paths.

Native operations are `GET /v1/notifications?organization_id=ORG_ID&recipient_id=USER_ID&unread_only=false&limit=25&offset=0`, `GET .../unread/count`, `POST .../read-all`, `GET`/`DELETE .../NOTIFICATION_ID`, `PATCH`/`DELETE .../NOTIFICATION_ID/read` (acknowledge/unread), `GET .../NOTIFICATION_ID/delivery-results` and `GET .../templates`. Every operation in that list requires the organization query selector. List/template/delivery-result reads accept `limit` and `offset` and return arrays with no total count. Count/read-all use the trusted authenticated user if their optional recipient selector is absent. List reads require an explicit recipient selector for a personal inbox. They require `notification:view`; API keys can use the existing `notifications:read` or `notifications:send` compatibility scopes.

`POST /v1/notifications/send` requires `notification:send` (API key `notifications:send`) and accepts the organization in its JSON body. The existing `NotificationTarget` is embedded inside this request, with organization/user selectors and device, email, webhook and channel fields; it is not an independently stored profile with CRUD routes. An explicit target organization must match the request organization. Existing channel/destination, TTL and protected-payload validation still applies. Unknown root and target members are now rejected instead of silently ignored. The public send/read projection adds the stored organization, read state, severity, status and optional link so consumers can interpret the native result. Transport availability and recorded attempts remain separate from request acceptance. This example suite does not send real notifications to people.

The browser client exposes scoped inbox/get/count/read/delete, send and delivery-result functions. It preserves native responses rather than fabricating `message`, `read` or count envelopes. The canonical contract now lists native notification operations instead of a permissive management catch-all, embeds pinned notification vocabulary, and uses separate `runtime__notification_*` HTTP schemas with explicit `partial` support. Native inputs accept defaults/aliases and a richer response than the pinned entities; these schemas are not interchangeable.

Alert rules and notification preference read/update operations have no native owner implementation. Their compatibility client exports return local `UNSUPPORTED_OPERATION`/501 before a request. The console API-support tab and existing `/settings/notifications` URL state this explicitly and offer no nonfunctional editor or save confirmation. Event subscriptions and configured webhook delivery remain separate existing APIs; they are not an invented alert-rule engine.
