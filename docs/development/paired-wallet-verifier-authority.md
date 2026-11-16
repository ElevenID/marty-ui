# Paired wallet verifier authority

The native Trust Profile owner now recognizes the explicit `PRESENTATION_VERIFIER` purpose and `REGISTERED_VERIFIER` source. This purpose is separate from credential-issuer and machine-identity authority. Profile writes still use the existing tenant authorization and validation path; creating a profile keeps it draft. Registered sources default to disabled through the HTTP API. This source change does not provision or activate a production profile.

The `registered_verifier` object contains one pre-registered client ID, request-signing key ID, public ES256 JWK, up to eight exact HTTPS response URIs, and whole-second UTC key-validity boundaries. The closed schema rejects private key material, arbitrary key-resolution URLs, alternate algorithms, duplicate clients and mixed source purposes. No certificate, DID, issuer-key, registry or machine-identity setting implicitly supplies verifier authority. The synthetic public source in the native test fixtures is not a runtime configuration.

The initial contract requires a custom profile permitting ES256, a minimum EC size no greater than256, and JWT whenever assertion formats are restricted. The native request validator permits at most30seconds of future issuance skew and a900second request lifetime; a profile requiring less than30seconds of skew is unsupported until the validator can enforce that setting. These relevant controls are enforced on writes and projection and bound into the revision. Unknown validation-rule extensions, custom verification/revocation policy references and framework compliance constraints are refused. Raw registered JWKs have no certificate chain, so X.509 chain-depth/self-signed/key-usage extensions, CRL and OCSP controls do not supply their authority. Explicit request-signing purpose constrains key use; any JWK use/key_ops metadata must also permit verification. Credential freshness controls remain part of credential authority, not a source of verifier trust. Revocation here means disabling/suspending the governed source/profile or expiration; snapshot freshness allows no offline grace.

`GET /internal/v1/trust-profiles/{profile_id}/wallet-verifier-authority?organization_id=...&client_id=...` requires configured workload authentication. The owner loads one coherent profile and checks the exact tenant, active/compliant state, explicit purpose, enabled source, algorithm and registration validity. Its response is bounded to64KiB and marked `no-store`. It does not resolve issuer relationships or accept a request-provided JWK or URL.

The versioned snapshot binds organization/profile, one registration, a profile-scoped authority ID and a canonical owner-state revision. `observed_at` and `expires_at` bound snapshot freshness to at most60seconds. Registration validity bounds the key separately; consumers must not replace the key expiry with the shorter snapshot deadline. Acquire fresh authority again at preparation and require the approved original signed request and its authority binding to remain unchanged.

The regular profile API exposes the validated public registration, its stable source ID and enabled state for review and round-trip editing. Unsupported legacy source controls remain rejected; this adds no private-custody readback.

This owner component is a prerequisite for Authenticator #57 and Core #439. The paired-device binding described below is a separate additive component; mobile/native consent/preparation integration remains incomplete. Core #439's initial profile also refuses the existing managed DID/VCT request profile; those semantics require their own owner implementation and qualification. The canonical credential-authority producer currently treats nonempty trust sources as unsupported, so do not assume that adding this source to an issuer profile qualifies that separate path. Preserve distinct authority decisions instead of weakening its controls.

Current local tests use native library/application/HTTP adapters with in-memory persistence and mocked control-plane permissions. They are not installed-wallet, managed-runtime, public-network or official-suite acceptance.

## Paired-device binding

The authorized browser may supply a distinct `verifier_trust_profile_id` when issuing a pairing ticket. The service requires current organization membership and user view permission on an active, compliant verifier profile through the workload-authenticated owner admission endpoint. Membership is checked again after owner reads. The profile reference is retained in both the single-use Redis ticket and the durable PostgreSQL confirmation. Before allocating a device, credential or remote key, redemption requires the Redis scope to match that durable browser record, including user, tenant, both profile references and exact ticket times. Redemption repeats this binding check when recording the result.

Migration `20261116_0002` adds a nullable verifier-profile reference without backfilling an authority grant. Existing pairings therefore retain their issuer profile and have no verifier authority. The migration source is not permission to migrate an existing installation during development qualification.

Device Registration enables the projection client only when an operator configures `WALLET_VERIFIER_TRUST_OWNER_URL`, a fixed HTTPS origin with no path, query or credentials. Optional `WALLET_VERIFIER_TRUST_OWNER_CA` names a public PEM certificate bundle; malformed or empty bundles fail startup. The existing workload token is required. Certificate validation remains enabled; redirects and proxy environment inheritance are disabled. No origin is selected from a mobile request or request object. Absence of this new configuration leaves verifier projection unavailable while preserving existing issuer-only pairing.

`GET /v1/devices/wallet-verifier-authority?client_id=...` requires Gateway workload authentication and a confirmed active device bearer. The mobile caller supplies only the registered client ID; unknown query fields are refused. User, organization and verifier profile come from the current durable pairing. The service checks membership before and after the owner read, sends only the server-derived user identity to the owner for current view authorization, then rereads bearer/pairing state before returning a `no-store` snapshot. The client enforces a 64KiB bound, recursively rejects duplicate JSON members, and checks exact scope, freshness, public ES256 material, purpose, recipients and key validity. It provides no issuer-key or caller-key fallback.

Wallet setup now offers an explicit optional verifier-profile selection, separate from its issuer profile. Only active profiles with the presentation-verifier purpose appear in that selection; it never selects a verifier automatically. Profile and organization changes invalidate displayed pairing data, pending ticket results and pending pairing-status results. Server admission remains authoritative. Older wallets are not qualified merely because a browser can issue the new scoped ticket.

The native Redis qualification now exercises explicit verifier-scope serialization, single-use redemption under a race and issuer-only omission. A separate PostgreSQL test requires a nonce-marked empty fixture, builds the preceding schema, checks additive/idempotent migration and legacy preservation, then rejects substituted scope and cancellation before key allocation. These run only against freshly created disposable fixtures; they establish no rootless or existing-installation acceptance.

`scripts/qualify_wallet_verifier_pairing.py --postgres-test-binary /absolute/path/to/verifier_pairing_postgres-... --redis-test-binary /absolute/path/to/pairing_ticket_redis-...` requires exact native test discovery before allocating either backend. It uses the repository's pinned owned-fixture helpers and removes only its exact labelled container IDs. The contracts CI lane invokes this driver and the TLS driver using the recorded workspace compiler artifacts; ordinary test collection alone is not counted as qualification.

`scripts/qualify_wallet_verifier_transport.py --test-binary /absolute/path/to/verifier_trust_tls-...` runs the explicitly ignored native transport test against a temporary loopback TLS fixture. It generates a disposable CA and server certificate, checks actual certificate/hostname validation and user/service/tenant binding, and exercises redirect, oversized, duplicate-member, stale, private-key and wrong-scope responses. It also verifies that an unusable proxy environment does not redirect owner traffic. The driver checks its negative response vectors and propagates handler failures instead of treating fixture failures as successful rejection. All fixture responses are synthetic; this is actual TLS transport evidence, not deployed Trust Profile governance, KMS, installed-wallet or official-suite execution. The server and private temporary TLS material are removed on completion.

Complete managed DID/VCT request semantics, mobile/native consent/preparation wiring and installed-wallet acceptance remain required before claiming the paired feature complete.

## Managed Flow producer component

The next component prepares an exact owner-produced DID request for a trusted
Flow instance. It retains one original signed JWS, with a scope digest covering
the stored tenant, instance, nonce, frozen policy/query and producer settings.
Revalidation uses the current signing identity, its canonical DID client/key IDs,
the actual JWS signature, exact destination/state/query, closed signed fields,
canonical metadata and bounded times. A900-second request lifetime does not
shorten the underlying Flow instance. Unsupported query constraints fail closed.
The ordinary request builder retains its existing behavior; this component has
a separate paired SD-JWT metadata profile matching accepted Core authentication.

`POST /internal/v1/wallet-verifier-requests/{instance_id}` requires a configured
workload authenticator and exactly one valid service-token header. It derives
the tenant from the stored instance, ignoring caller tenant headers. Both new
and cached owner responses use the existing status/time compare-and-swap after
asynchronous signing-identity resolution. A competing cancellation or snapshot
change prevents exposure. The projection is checked for freshness after the CAS
and returned with no-store headers.

Once this canonical cache exists, public request GET revalidates and returns its
exact persisted JWS. POST, DC API, Lissi and wallet-nonce retrieval changes fail
closed. Uncached ordinary request retrieval retains its existing behavior. No
production configuration or profile is activated by this component.

The guarded qualification driver explicitly executes three native cases against
fresh owned PostgreSQL and TLS OpenBao fixtures. It checks exact test discovery
before allocating bounded local containers; the HTTP case refuses a nonempty
database before migration. Actual remote Transit signatures retain non-exportable
key custody and one-key signer tokens. The HTTP case verifies persisted/public
JWS equality, repeated reads without resigning, forged tenant header rejection,
transport downgrade rejection and real repository cancellation races during
awaited identity resolution, for both cached public and first owner requests.
The other two cases check immutable reuse and correctly signed invalid client,
key ID, extra semantics, metadata and VCT changes. Exact owned containers and
temporary material are removed. No local signing-key feature is enabled.

This establishes PostgreSQL HTTP/CAS and TLS signing with an application/provider
adapter. It does not establish deployed Signing Keys or Trust Profile governance,
rootless installation, installed-wallet acceptance or official-suite execution.
The managed Trust Profile component below supplies the next owner boundary.
Confirmed-device v2 binding and native opaque consent/preparation/completion
sessions remain unfinished.

Run `scripts/qualify_flow_wallet_verifier_request.py --test-binary /absolute/native/executable`
after building the native library test binary. Full workspace formatting, focused
Flow Clippy with warnings denied and driver lint are required. Independent
source review caught permissive unconfigured authentication and duplicate-token
ambiguity; both were fixed with rejection coverage. Reviewers ran no tests.

## Managed producer trust authority

`MANAGED_FLOW_VERIFIER` is a distinct, public-only source for the explicit
`PRESENTATION_VERIFIER` purpose. It pins a producer ID, canonical HTTPS public
base, supported Flow DID (web, jwk or key), exact signing key ID, public ES256 JWK
and whole-second key-validity interval. Writes preserve source IDs and default
new sources to disabled; profiles remain draft. Issuer relationships, registered
plain clients and machine identity sources never supply this authority.

The producer ID selects one fixed operator-configured HTTPS owner transport.
`WALLET_FLOW_PRODUCER_ID` and `WALLET_FLOW_OWNER_URL` must be configured together
with the existing workload token; optional `WALLET_FLOW_OWNER_CA_FILE` contains
public trust roots. The transport refuses plaintext, credentials, non-root
origins, redirects, proxies, ambiguous JSON, private material and responses over
64 KiB. Caller request locators never select its host. These settings default to
absent; this source change activates no deployment configuration.

`GET /internal/v1/trust-profiles/{id}/wallet-managed-verifier-authority` requires
workload authentication and a server-derived user with current profile-view
permission. Its organization, client and request URI select only a governed
source and exact canonical Flow instance. The owner POST supplies the persisted
original JWS. After that await, Trust Profile repeats permission/profile reads
and requires the original source ID and complete registration to remain equal.
It verifies the signature against the pinned key and matches exact signed
client, key, tenant/instance evidence, nonce, times and response URI. The v2
snapshot binds that one request and one exact callback, with at most 60-second
freshness. A producer base is an identity check, not a callback-prefix grant.
The native wallet must still resolve/bind the actual DID and authenticate all
supported request semantics through Core; this producer does not replace that
consumer boundary or credential-issuer trust.

Flow has an optional owner-only managed HTTPS listener using the existing
`MANAGED_AUTHORITY_HTTPS_ADDR` and remote TLS identity settings. Partial settings,
a missing workload token or listener collisions fail closed. The listener uses
the shared non-exportable TLS signer, binds before readiness and shares graceful
shutdown. Public administration/callback routes are absent from that router.
No listener was activated in an existing installation.

Final ordinary execution reports 89 Trust Profile passes with one guarded
ignore, and 105 focused Flow passes with four ignores. The extended driver,
using `--trust-profile-test-binary`, then explicitly executes three Flow cases
and one Trust Profile case: four passed, zero ignored. It carries a real signed
Flow HTTP proof from fresh PostgreSQL/TLS non-exportable OpenBao into a synthetic
HTTPS owner and in-process Trust Profile HTTP handler. It checks CA/hostname,
token, proxy exclusion, redirect, size, escaped duplicate names, private/unknown
fields and media handling. Deterministic paused-owner races reject producer
replacement, source disabling and membership loss without returning the JWS.
Exact owned containers, TLS server and private temporary material are removed.

Full workspace format, both services' all-target Clippy with warnings denied and
driver lint passed. The contracts CI step selects exact library executables
from Cargo compiler artifacts and invokes this guarded driver through the
existing positive-execution/timing policy. That exact shell step was executed
locally and returned `status: ok`; this is not a hosted-check claim. Independent
source review found the producer-channel race; it was fixed and reviewed with no
remaining actionable finding. Reviewers executed no tests.

These results do not qualify the deployed keyless listener, real control plane,
rootless installation, device v2, native wallet sessions, installed-wallet
acceptance or official-suite interoperability. Those remain separate gates.

## Confirmed device v2 projection

The paired device endpoint accepts an optional `request_uri` alongside the client
ID to select managed v2 evidence from the fixed Trust Profile owner. Those inputs
select a request; they supply no user, organization, profile or holder authority.
One PostgreSQL statement binds the live digest-only bearer, acknowledged pairing,
active registration and both current unrevoked holder key rows. The public scope
includes credential/registration/pairing/device/user/organization/profile IDs,
credential expiry, and each holder key's ledger ID, algorithm, version, public
JWK and RFC 7638 thumbprint. It excludes bearer values and custody references.

Membership is checked before and after the owner lookup, and the full database
scope is read again and compared before returning the bounded no-store
`marty.wallet/device-verifier-governance/v2` envelope. Credential rotation,
deactivation, scope substitution and key/version changes invalidate that
snapshot. The envelope's expiry cannot exceed the credential or verifier
snapshot expiry. The existing v1 registered endpoint remains distinct.

Focused native execution reports 16 unit and eight HTTP behavior passes; guarded
PostgreSQL, Redis and synthetic TLS cases are then explicitly executed with no
ignores. The PostgreSQL case reads actual joined key JSON and exercises device
substitution, key version changes, credential rotation, missing verifier scope
and key revocation. TLS qualification executes the managed-v2 transport with
synthetic response evidence, preserving the existing CA/hostname/token/redirect/
duplicate/size controls. Both recorded CI phase receipts are successful, and
owned containers/server/material are removed. Formatting, all-target device
Clippy with warnings denied and transport-driver lint pass.

These checks do not yet exercise a device HTTP response paused across authority
revocation, deployed governance, native Core authentication or an installed
wallet. The consumer must verify the original JWS/DID, exact request semantics,
issuer evidence and holder binding before consent and again at completion.
