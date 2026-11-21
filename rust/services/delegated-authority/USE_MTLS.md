# Certificate-authenticated internal delegated use

`DelegationUseHttpAuthenticator::mutual_tls` selects a concrete transport identity
boundary for the existing internal command router and the new protected Flow
ingress. `BoundDelegatedUseMtlsServer` supplies its mandatory mutual-TLS listener.
The explicit default-off [`marty-delegated-use` host](../delegated-use/README.md)
now selects these components. No public Gateway route or capability selects
them automatically.

## Identity and current access

The listener verifies the client certificate chain against an explicitly supplied
CA set. Only the authenticated **leaf** certificate is inspected for the workload
identity. It must have exactly one URI SAN in the selected canonical
`spiffe://trust-domain/path` form and must be a non-CA certificate. Intermediate
or root SANs cannot identify a workload.

Deployment construction supplies `DelegatedUseWorkloadBindings`. Each entry pins
the exact URI SAN and `sha256:<lowercase-hex>` digest of the complete leaf
certificate to one full `MACHINE_IDENTITY` principal. Duplicate URI or certificate
pins are rejected. Reissuing a certificate under the same URI does not silently
replace the pin. A changed pin is a separate deployment configuration change.

The typed actor and tenant are derived from this mapping and the configured
tenant. HTTP actor assertions, service tokens, cookies, user credentials and
forwarded certificate/workload identity headers cannot supply or override the
mutual-TLS identity. The private peer extension is constructed only by the
successful TLS acceptor. Mounting the router on an ordinary HTTP listener cannot
manufacture that extension.

Each request receives a fresh authentication observation bounded to 30 seconds
and to the original leaf certificate expiry. Certificate validity is checked
again for each request on a reused connection; clock regression behind the TLS
authentication instant is rejected. Authentication must still be current after
the HTTP body read and throughout the downstream operation's original bounds.
TLS session resumption and TLS 1.3 tickets are disabled for this listener.

`workload_identity_ref()` exposes certificate-authentication provenance on the
opaque HTTP context. It is separate from human approval session provenance and
from the registered machine-key proof required by finalization. Possessing a
transport certificate does not provide a verified OID4VP presentation or grant
Rifare business authority.

The current
[`OrganizationDelegationUseCommandAuthorizer`](../organization/MACHINE_USE_ACCESS.md)
independently reads the actual active tenant, full machine, immutable deployment
assignment and explicit use-access rights. It controls START_USE, FINALIZE_USE,
original-result recovery, request retrieval and proof submission separately.
Current access revocation therefore applies to an otherwise valid TLS client.
Finalization additionally performs the existing current grant/consent, machine
proof, constraint and delegated-use policy evaluations.

## Explicit assembly

1. Build the restricted Organization access source with its configured tenant and
   deployment, and construct the concrete command/ingress authorizer.
2. Build the certificate-to-machine mapping and the mutual-TLS authenticator.
3. Supply the same selected authenticator to `DelegationUseHttpState` and
   `FlowDelegatedUseHttpState`. Assemble only their internal routers.
4. Call `BoundDelegatedUseMtlsServer::bind` with the listener address, existing
   `RemoteTlsIdentityFiles`, explicit client CA DER certificates and router.
5. Serve with the existing shutdown watch. The server binds only after the
   remote identity and mandatory client-certificate verifier are ready.

The production constructor uses the existing MMF keyless TLS identity backed by
the selected remote signer. It accepts no local private-key file and supplies no
plaintext fallback. Test fixtures create ephemeral certificates in memory to
exercise real TLS handshakes; they do not qualify production custody.

`DelegationUseHttpAuthenticator::trusted_forwarder` preserves the earlier
explicit service-hop mode. It authenticates a separately trusted forwarder that
supplies actor metadata and original observation bounds. That mode is a distinct
selection and does not acquire the certificate guarantees described here.

## Validation and remaining deployment work

Focused tests exercise actual successful mutual TLS, absent/untrusted client
certificates, unknown URI, stale certificate pin, ambiguous or absent leaf URI,
CA-SAN substitution, foreign tenant and HTTP metadata injection. An actual TLS
request whose body finishes after its certificate expiry never reaches the
application. Bounded mapping and original-deadline tests cover the remaining
pure configuration/time cases.

This is a selected X.509 transport and exact URI mapping, not an implementation
of SPIRE enrollment, SVID distribution, trust-domain federation or automatic
certificate rotation. Production CA issuance/revocation and pin replacement
remain operator-owned qualification. No online CRL/OCSP fetch is introduced.
The serving executable is implemented. Production database-role deployment,
public wallet transport and deployed receipt-signer qualification remain
explicit milestones.

See [internal use commands](USE_HTTP.md),
[protected Flow ingress](../flow/DELEGATED_USE_INGRESS.md), and
[the runtime candidate](../../../docs/delegated-use-runtime-candidate.md).
