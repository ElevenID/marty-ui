# Delegated-use serving candidate

`marty-delegated-use` is the explicit serving composition for the implemented
managed organization, full-machine, KEY and EXACT_OPERATION profile. It joins
the concrete access, consent, machine, credential, policy, audit, Flow and
receipt owners behind the mandatory certificate-authenticated listener.

The executable is disabled unless `MARTY_DELEGATED_USE_ENABLED=true`. An absent
or false setting exits before reading credentials or CA files, connecting a
database, contacting a provider or binding a listener. There is no plaintext
listener, incoming service-token fallback, local private-key mode, migration
command or startup privilege provisioning. Existing public Gateway routes,
the human lifecycle host, capability discovery and public MIP are unchanged.

`DELEGATED_USE_PUBLIC_CALLER_ENABLED=true` separately installs the managed
machine caller routes described below. The default is `false`; this selection
does not enable anonymous wallets or browser clients. Every caller still needs
an explicitly mapped mutual-TLS certificate and current machine-use access.

Marty records identity and authority evidence for an exact operation. Rifare
continues to own orchestration, domain permissions, budgets, reservations,
execution, business idempotency and outcomes.

## Mounted surfaces

All surfaces below use the same mandatory mutual-TLS listener. Its verified
leaf URI and exact certificate digest must map to a configured full machine.
The health probes also use that exact mapping and reject HTTP identity overrides.

| Method and path | Responsibility |
| --- | --- |
| `POST /internal/v1/organizations/{organization}/delegated-use-commands` | Original START_USE, FINALIZE_USE and RECOVER_RESULT commands |
| `POST /internal/v1/organizations/{organization}/delegated-use/receipts/recover` | Current-authorized recovery of the exact original FINAL_USE receipt JWS |
| `GET /internal/v1/organizations/{organization}/delegated-use/challenges/{challenge}/request` | Current-authorized retrieval of the exact original request JWS |
| `POST /internal/v1/organizations/{organization}/delegated-use/challenges/{challenge}/proof` | Current-authorized immutable proof-byte retention |
| `GET /health` | Authenticated process availability; no authority decision |
| `GET /ready` | Authenticated bounded, read-only checks of actual roles, schemas, selected Flow configuration and dependencies |

Health and readiness return status only, with no-store headers. Readiness checks
the original certificate observation again after its awaited checks. Neither a
successful probe nor an authenticated TLS connection supplies current grant
consent, cryptographic machine proof or a business permit.

### Optional managed machine caller surface

With `DELEGATED_USE_PUBLIC_CALLER_ENABLED=true`, the same listener also mounts:

| Method and path | Responsibility |
| --- | --- |
| `POST /v1/organizations/{organization}/delegated-use-commands` | The same retained START_USE, FINALIZE_USE and RECOVER_RESULT application |
| `GET /v1/flows/instances/{challenge}/request` | The exact original signed request at the advertised URI |
| `POST /v1/flows/instances/{challenge}/submit` | Bounded, authenticated `direct_post` association and proof retention |
| `POST /v1/organizations/{organization}/delegated-use/receipts/recover` | Current-authorized recovery of the original signed receipt |

The public base must be a canonical HTTPS origin, with no trailing slash, path
prefix, user information, query, fragment or implicit normalization. The public
command router supplies the request URI in exactly one `Link` header with
`rel="urn:marty:delegated-use:request"` on a CHALLENGE response, including original
result recovery. It leaves the retained command response and command digest
unchanged. No caller supplies a forwarding identity, tenant override, request
nonce, verifier configuration or authorization snapshot.

The signed request advertises its own `response_uri`. Submission accepts only
`application/x-www-form-urlencoded` with exactly `state` and `vp_token`.
`state` must equal the original canonical challenge UUID. `vp_token` must be a
DCQL JSON map containing exactly the query ID in the frozen request and one
compact JWT presentation under the selected nested VC2 JWT profile. A bare
token, extra or duplicate form/JSON fields, `direct_post.jwt`, an error response,
caller-selected query, unretained request, and a changed request snapshot are
rejected. The retained proof is the exact extracted compact JWT, so equivalent
valid form encodings recover the same proof submission without another write.

Association does not verify the presentation. The existing finalization owner
still authenticates the complete machine proof, current identity, credential,
grant and policy before retaining a decision receipt. Authentication and
current-access bounds remain binding through the existing locked transaction
and COMMIT. The response and all route errors carry no-store protection.

The independent [`marty-delegated-use-client`](../../crates/delegated-use-client/README.md)
crate follows these URLs using explicit HTTPS trust and mutual TLS. It retains
command IDs and independently computes their digests before I/O, performs one
network attempt per call, rejects redirects and response/correlation changes,
and bounds request and response bytes. The caller independently verifies the
request signature and selected fields before supplying a proof; original
receipt bytes go to the separate receipt consumer. Public client transport is
not itself cryptographic receipt verification or business permission.

### Original signed receipt recovery

Send the existing strict `RECOVER_RESULT` command body to the receipt recovery
route, with the original command UUID and expected command digest. The route
accepts no receipt-reference lookup, query options or mutation commands. It uses
the same certificate identity mapping and the existing `RECOVER_RESULT` right;
no additional role, database migration or permission is required.

The response contains `original_response` with `recovered=true`, `receipt_ref`,
`receipt_digest`, `compact_jws` and `semantics: EVIDENCE_ONLY`. The original
FINAL_USE response format remains unchanged. The service binds the artifact to
the original tenant, complete typed actor, command, admission and retained
result. Reads are bounded, use read-only snapshots, and recheck current access
after the artifact read without renewing the original authentication deadline.
An unresolved claim or START_USE result cannot produce a receipt.

An expired or revoked grant can still have an authorized historical receipt.
An inactive caller or revoked recovery right cannot retrieve it. Recovery
returns the original bytes, decision and dates; it does not evaluate the
operation, sign again, extend expiry or confer current business authority.

The independent [`marty-delegated-receipt-consumer`](../../crates/delegated-receipt-consumer/README.md)
crate checks supplied public-key trust, exact original request context and an
independently authenticated retained-result digest. It uses no service or
database dependency. Fresh positive evidence and historical evidence have
separate sealed types. Callers supply their clock and freshness policy; current
revocation, domain permission, replay prevention and business commits remain
outside that offline verification. The signed nonce is part of the receipt;
command, challenge and proof-submission UUIDs remain external correlations.

## Startup sequence and ownership

1. Validate the explicit opt-in, closed configuration, identities, HTTPS origins,
   bounded credential files, public key pin and workload certificate bindings.
2. Connect the fourteen named restricted PostgreSQL pools. Validate their actual
   authenticated identities and effective privileges, preserving source and
   writer separation and the required shared database identity.
3. Build the actual Organization authority, registry, use-access and policy
   sources, Trust Profile/Issuance credential source, machine-policy evidence and
   machine-audit owners, and the concrete same-database Flow finalizer.
4. Connect the selected protected Flow read providers and managed signing
   adapters. Verify readiness with bounded read-only calls. Startup does not mint
   a signing grant or sign a request or receipt.
5. Establish the remote keyless server identity, verify the explicit client CA
   set and bind the mutual-TLS listener. A failed step leaves no serving listener.
6. On shutdown, drain the listener and close the pools. Retained claims and
   evidence are preserved.

The runtime uses the existing current human Organization approval source and
retained consent/assertions. It holds no confirmation or representation-authority
producer writer, migration owner or machine/policy administrator credential.
It selects the exact-operation delegated-use policy and the audited full-machine
verifier. A required attestation has no provider in this candidate and fails
closed. External constraint profiles and represented-subject session grants are
also outside the selected profile.

The public `assemble` library entrypoint is a trusted composition seam for
acceptance tests and separately qualified adapters. The executable always calls
the concrete production `connect` path. Injection into a test does not qualify
that adapter for production.

## Configuration rules

Configuration uses `DELEGATED_USE_*` variables, plus the explicit enable flag.
Unknown names in this namespace, duplicate fields supplied to the parsing API,
invalid booleans, whitespace/control characters in scalar values, foreign or
noncanonical UUIDs and unsupported modes are rejected. Command-line arguments,
including `migrate`, are rejected without echoing their values.

Each database URL or HTTP credential accepts **exactly one** inline value or
`<NAME>_FILE`. Secret files must be absolute regular-file paths and are read with
a byte bound; a terminal newline is removed. Database URLs are at most 8,192
bytes. HTTP credentials are 32–1,024 visible ASCII bytes. Public JSON values also
support `<NAME>_FILE` and are bounded to 262,144 bytes. Diagnostics and Debug
output omit connection strings, credentials, key material and upstream bodies.

### Tenant, authority and Flow selection

| Setting | Meaning |
| --- | --- |
| `MARTY_DELEGATED_USE_ENABLED` | Required exact `true` to start |
| `DELEGATED_USE_LISTEN_ADDR` | Socket address; defaults to `127.0.0.1:8021`; port zero is rejected |
| `DELEGATED_USE_ORGANIZATION_ID` | Canonical, nonnil tenant UUID |
| `DELEGATED_USE_DEPLOYMENT_PROFILE_ID` | Exact full-machine deployment selection |
| `DELEGATED_USE_DELEGATION_POLICY_ID` | Exact Organization-owned delegated-use policy UUID |
| `DELEGATED_USE_APPROVAL_PROFILE`, `_VERSION`, `_ARTIFACT_DIGEST` | Exact approved adapter pin; each name uses the full `DELEGATED_USE_APPROVAL` prefix |
| `DELEGATED_USE_STATUS_REF` | Managed authority status HTTPS URI |
| `DELEGATED_USE_CONFIRMATION_MAX_AGE_SECONDS` | 1–300; default 300 |
| `DELEGATED_USE_AUTHORITY_VALIDITY_SECONDS` | 1–15; default 15 |
| `DELEGATED_USE_FLOW_DEFINITION_ID`, `_VERSION` | Frozen Flow definition identity and positive version; version defaults to 1 |
| `DELEGATED_USE_PUBLIC_BASE_URL` | Selected HTTPS request/response base, without a trailing slash |
| `DELEGATED_USE_VERIFIER_DID` | Explicit `did:web`, `did:jwk` or `did:key` verifier identity |
| `DELEGATED_USE_VERIFIER_DISPLAY_NAME` | Bounded display name |
| `DELEGATED_USE_VERIFIER_LOGO_URI` | Optional HTTPS logo URI |
| `DELEGATED_USE_CHALLENGE_LIFETIME_SECONDS` | 30–600; default 120 |
| `DELEGATED_USE_RECEIPT_LIFETIME_SECONDS` | 1–30; default 30, additionally capped by verified evidence |

Request options are fixed to the standard DID/request-URI profile with strict
client metadata. No HAIP, wallet nonce, X.509 client-ID override, URL-query or
Digital Credentials API mode can be enabled through this host.

The selected Flow definition must omit `trust_profile_id`,
`deployment_profile_id` and `deployment_profile_ids`. Their existing catalog
HTTP readers require human membership and cannot represent this machine actor;
host readiness rejects those optional references. This does not remove the
actual Trust Profile credential-authority check or the explicit machine
deployment/MAP selection. A future catalog adapter needs its own typed machine
authorization contract.

Original Flow request/response URIs remain unchanged. The ordinary public Flow
request endpoints reject delegated instances. This internal host does not make
those public wallet URIs usable; a separately qualified public routing/client
composition is still required.

### Separate database connections

Each setting below takes a PostgreSQL URL or its `_FILE` alternative. Do not
substitute owner connections to make startup pass. The runtime checks actual
roles and storage identity rather than relying on different URL strings.

| Setting | Owner boundary |
| --- | --- |
| `DELEGATED_USE_USE_WRITER_DATABASE_URL` | Original command/use ledger and atomic Flow start/finalization writes |
| `DELEGATED_USE_RUNTIME_READER_DATABASE_URL` | Current grants and retained consent/authority evidence |
| `DELEGATED_USE_ORGANIZATION_AUTHORITY_DATABASE_URL` | Current human Organization authority and RBAC |
| `DELEGATED_USE_REGISTRY_SOURCE_DATABASE_URL` | Full-machine registry and retained registry observations |
| `DELEGATED_USE_ACCESS_SOURCE_DATABASE_URL` | Current full-machine entrypoint rights |
| `DELEGATED_USE_MACHINE_POLICY_SOURCE_DATABASE_URL` | Current machine policy and source observations |
| `DELEGATED_USE_MACHINE_POLICY_EVIDENCE_DATABASE_URL` | Retained MMF machine-policy evaluations |
| `DELEGATED_USE_DELEGATION_POLICY_SOURCE_DATABASE_URL` | Selected delegated-use policy and source observations |
| `DELEGATED_USE_MACHINE_AUDIT_DATABASE_URL` | Exact aggregate machine-authentication evidence |
| `DELEGATED_USE_FLOW_READER_DATABASE_URL` | Flow definitions, challenge bindings and proof state |
| `DELEGATED_USE_FLOW_INGRESS_DATABASE_URL` | Original signed request/proof ingress records and bounded progress |
| `DELEGATED_USE_CREDENTIAL_TRUST_DATABASE_URL` | Actual Trust Profile/issuer/key authority |
| `DELEGATED_USE_CREDENTIAL_STATUS_DATABASE_URL` | Actual Issuance artifact and current status |
| `DELEGATED_USE_CREDENTIAL_EVIDENCE_DATABASE_URL` | Retained credential authority/status observations |

Install reviewed migrations separately using the respective owner procedures.
The serving role checks include PostgreSQL parameter ACLs: administrative SET,
ALTER SYSTEM and parameter grant options are rejected, including authority to
suppress integrity triggers. A role's permitted table/function names apply only
in its actual selected database; matching names elsewhere do not qualify them.
The [database upgrade runbook](../../../docs/delegated-authority-upgrade.md),
[machine registry](../organization/MACHINE_REGISTRY.md),
[use access](../organization/MACHINE_USE_ACCESS.md),
[machine policy source](../delegated-authority/MACHINE_POLICY_SOURCE.md),
[delegated-use policy](../organization/DELEGATION_USE_POLICY.md),
[credential source](../../crates/machine-credential-source/README.md), and
[Flow ingress role contract](../flow/DELEGATED_USE_INGRESS.md) describe the
independent owners. Startup performs no schema repair or historical backfill.

### Protected Flow dependencies

Set `DELEGATED_USE_CREDENTIAL_TEMPLATE_GRPC_TARGET` and
`DELEGATED_USE_PRESENTATION_POLICY_GRPC_TARGET` to their exact HTTPS origins.
Select the outbound remote workload identity with
`DELEGATED_USE_WORKLOAD_TLS_*` as described below and supply its peer CA through
`DELEGATED_USE_WORKLOAD_TLS_CA_CERT_FILE`.

Credential-template and presentation-policy unary reads have ten-second
deadlines covering headers, response bodies and trailers. A peer that sends
headers and then stalls cannot keep a read open indefinitely. These read-only
deadlines do not wrap signing, grant minting or a database COMMIT.

`DELEGATED_USE_SERVICE_TOKEN` authenticates the selected outgoing service calls.
The reference reader additionally requires these HTTPS origins:

- `DELEGATED_USE_ISSUANCE_NATIVE_URL`
- `DELEGATED_USE_CREDENTIAL_TEMPLATE_URL`
- `DELEGATED_USE_TRUST_PROFILE_URL`
- `DELEGATED_USE_DEPLOYMENT_PROFILE_URL`

Its Issuance credential is `DELEGATED_USE_ISSUANCE_API_KEY`. These credentials are
outbound selections only; no incoming request can use them as a substitute for
the machine's verified TLS identity.

### Request and receipt signing

For each prefix `DELEGATED_USE_REQUEST` and `DELEGATED_USE_RECEIPT`, configure:

| Suffix | Meaning |
| --- | --- |
| `_SIGNING_ORIGIN` | Exact HTTPS Signing Keys origin |
| `_READ_CREDENTIAL` | Existing read/resolver HTTP credential, or `_FILE` |
| `_SIGN_CREDENTIAL` | Existing issuer-sign HTTP credential, or `_FILE` |
| `_GRANT_OPENBAO_ORIGIN` | Exact mounted HTTPS OpenBao origin used by the existing GrantMinter |
| `_MINT_TOKEN_FILE` | Absolute token file for that one signing-grant origin |

The existing grant client also requires matching `BAO_ADDR` and its existing
`BAO_CACERT` configuration when applicable. The request and receipt mint token
files must be distinct and must have independently scoped provider policies for
`FlowWalletRequest` and `DelegatedDecision`. Tokens are read by the existing
minter on each operation, preserving rotation behavior.

One Signing Keys deployment has one issuer-sign HTTP credential. Request and
receipt callers may share that transport credential only when their configured
origins match. Read and sign credentials remain distinct, and neither can be
reused for the outgoing service or Issuance API credential. Distinct signing
origins may not share transport credentials. The dedicated signing-grant origin,
exact input binding, managed key purpose and replay checks remain mandatory.

Receipt signing additionally requires:

- `DELEGATED_USE_RECEIPT_ISSUER_DID` — selected Organization-typed receipt issuer.
- `DELEGATED_USE_RECEIPT_ALGORITHM` — `ES256` or `EdDSA`.
- `DELEGATED_USE_RECEIPT_KEY_ID` — exact issuer verification-method fragment.
- `DELEGATED_USE_RECEIPT_KEY_REFERENCE` — selected managed key reference.
- `DELEGATED_USE_RECEIPT_PUBLIC_JWK` or `_FILE` — exact public JWK containing only
  `kty`, `crv`, `x` and, for P-256, `y`. Duplicate/unknown fields, private values,
  metadata substitutions and invalid curve points are rejected.

No sign operation occurs while parsing configuration or running readiness.
The actual receipt adapter independently verifies every returned signature.

### Mandatory remote TLS identities and caller mapping

Configure each of `DELEGATED_USE_TLS` (server) and
`DELEGATED_USE_WORKLOAD_TLS` (outgoing workload) using the existing remote TLS
identity format:

- `_CERT_FILE`: absolute PEM certificate-chain path.
- For OpenBao, `_KMS_PROVIDER=openbao-transit`, `_KMS_ADDR`,
  `_KMS_CA_CERT_FILE`, `_KMS_TOKEN_FILE`, `_KMS_KEY_NAME` and a positive
  `_KMS_KEY_VERSION`.
- For AWS KMS, `_KMS_PROVIDER=aws-kms`, `_KMS_REGION` and an immutable
  `_KMS_KEY_ARN`; authentication uses the existing IAM-role path.

OpenBao addresses must be HTTPS origins. Provider settings cannot be mixed.
Remote signing calls have a five-second configured budget and at most sixteen
concurrent signs per identity. Private-key fields and relative paths are rejected.

`DELEGATED_USE_CLIENT_CA_FILES` is a JSON array of 1–16 absolute DER certificate
paths. Each certificate is at most 65,536 bytes; duplicate paths/contents are
rejected. The listener validates the actual CA material before serving.

`DELEGATED_USE_WORKLOAD_BINDINGS` is a JSON array with 1–128 closed objects:

```json
[
  {
    "workload_uri": "spiffe://trust.example/machine/registered-agent",
    "leaf_sha256": "sha256:<64 lowercase hexadecimal characters>",
    "principal_id": "urn:marty:machine:<registered-principal>"
  }
]
```

Replace the placeholders with the actual reviewed certificate digest and full
registered principal. Duplicate URI or leaf pins, unknown fields and ambiguous
identities are rejected. Reissuing a certificate requires an explicit pin
replacement. This host supplies no SPIRE enrollment, federation, automatic pin
rotation or online CRL/OCSP fetching. CA issuance/revocation and pin lifecycle
remain separately qualified deployment responsibilities.

## Build, validation and recovery

From the repository root:

```sh
cargo build --locked --manifest-path rust/Cargo.toml -p marty-delegated-use --bin marty-delegated-use
cargo test --locked --manifest-path rust/Cargo.toml -p marty-delegated-use --lib
cargo test --locked --manifest-path rust/Cargo.toml -p marty-delegated-use --test host_smoke
```

Configuration tests cover disabled-before-I/O behavior, explicit scope and
bounded profiles, credential separation, malformed/ambiguous mappings, closed
public keys, endpoint/TLS refusal and sanitized diagnostics. Executable smoke
tests launch the actual binary and verify disabled/invalid startup exits before
serving. Cross-owner PostgreSQL tests exercise the actual local composition with
explicit remote test adapters; production provider/CA/custody qualification is
separate from those fixtures.

For the database acceptance suite, explicitly configure
`DELEGATED_AUTHORITY_TEST_DATABASE_URL` to a disposable loopback PostgreSQL
administrator fixture, then run:

```sh
cargo test --locked --manifest-path rust/Cargo.toml -p marty-delegated-use --test runtime_postgres -- --ignored --test-threads=1
```

The suite creates isolated databases and real restricted LOGIN roles. It is
ignored without that explicit fixture and must not be reported as executed by
the normal unit test command.

The owner acceptance test obtains the exact signed receipt through the protected
recovery application boundary and verifies it with the independent consumer.
Its expected context comes from the known public key, original grant, START_USE,
verified request nonce and FINAL_USE response. Separate database assertions
check immutable persistence and audit linkage; storage and unverified receipt
claims never supply the consumer's expected context.

### Actual executable and remote readiness qualification

`tests/live_runtime.rs` starts the actual binary through its production
configuration and `connect` path. Supply independently verified OpenBao 2.5.5
and Redis 7.4.12 executables and the explicit disposable loopback PostgreSQL
fixture. Build the Rust target before provisioning the short-lived providers:

```sh
cargo test --locked --manifest-path rust/Cargo.toml -p marty-delegated-use --test live_runtime --no-run
python3 scripts/with_disposable_delegated_use_runtime.py --openbao /path/to/bao --redis-server /path/to/redis-server -- cargo test --locked --manifest-path rust/Cargo.toml -p marty-delegated-use --test live_runtime -- --ignored --exact actual_executable_qualifies_remote_readiness_mtls_and_fail_closed_startup --test-threads=1
```

The wrapper starts its own TLS OpenBao and password-protected nonpersistent
Redis, provisions nonexportable keys and scoped credentials, and removes their
temporary state when the child exits. Version checks enforce compatibility;
they do not replace independent release checksum/signature verification. The
test uses the actual Signing Keys HTTPS router, its public-key resolver, real
remote keyless server/client TLS and the fourteen restricted database roles.
Template/presentation-policy gRPC metadata and reference health responses are
explicit authenticated wire fixtures. A child-scoped CA file trusts only the
fixture's public CA; peer verification remains enabled.

The gate checks mapped-client health/readiness, missing or unlisted certificates,
wrong pins, spoofed HTTP identity headers, current privilege drift and startup
refusal for invalid remote service credentials, workload identity, availability
or selected public key. It asserts actual remote TLS signing while request and
receipt signing, signing-grant minting and command admission remain absent.
It qualifies this startup/readiness boundary; the full lifecycle across actual
template/presentation-policy owners is exercised by the separate gate below.
Production custody qualification remains separate.

### Actual executable and managed lifecycle qualification

`tests/live_lifecycle.rs` runs the selected operation through the actual
executable, its production `connect` path and protected HTTP routes. It adds
production Credential Template and Presentation Policy gRPC services backed by
their actual repositories, fresh machine credential issuance, and three
purpose-separated managed signing keys behind the real Signing Keys HTTPS
service. The host uses its own
`spiffe://marty.internal/service/delegated-use` workload identity. The policy
service permits that identity to read the selected policy, while presentation
evaluation remains restricted to its existing callers.

Build before provisioning the short-lived providers, then run with the same
explicit disposable loopback PostgreSQL fixture used above:

```sh
cargo test --locked --manifest-path rust/Cargo.toml -p marty-delegated-use --test live_lifecycle --no-run
python3 scripts/with_disposable_delegated_use_lifecycle.py --openbao /path/to/bao --redis-server /path/to/redis-server -- cargo test --locked --manifest-path rust/Cargo.toml -p marty-delegated-use --test live_lifecycle -- --ignored --test-threads=1
```

Fresh issuance invokes the real in-process initiation, pre-authorized token exchange,
PostgreSQL nonce and transaction owners, native holder-proof verifier, managed
signing grant and HTTP credential builder. The builder selects the explicit
native Signing Keys owner API and independently opts into the selected machine
nested VC2 JWT profile. That producer selection binds the nested `vc.id` and
signed `jti` to the same reserved credential ID; legacy issuance defaults remain
unchanged. Original credential bytes and status are retained by Issuance; the
gate does not insert a completed credential or sign it with a local issuer key.
The selected credential is a one-day, no-status `MachineCredential`.

The machine caller performs START_USE, retrieves and independently verifies the
signed request, submits its real holder proof, finalizes the exact operation,
recovers the original receipt, and verifies it with the independent consumer.
Consumer expectations come from provisioned public trust, the original grant,
authenticated command responses and the verified request nonce. Later SQL
inspection checks persistence and audit linkage; it supplies no consumer trust.
Provider audit counts distinguish request, credential and receipt signing
invocations from remote TLS signatures. Exact command/request/proof retries and
receipt recovery must preserve bytes and produce no additional artifact signatures.

The gate also checks a grant revoked after proof submission, historical receipt
recovery after revocation, current access withdrawal, wrong recovery digests,
unmapped caller certificates and identity-header spoofing. Denied finalization
must leave the pending proof unconsumed and retain the previously issued receipt.

Two explicit tests run this lifecycle with fresh owners: the unchanged internal
surface and the separately selected public machine caller. The public gate
uses the independent Rust client, follows the authenticated returned request
link and the independently verified signed response URI, and submits the exact
frozen DCQL query ID. It also tests absent-by-default routes, missing client
certificates, submission before request retention, wrong or duplicate form/query
fields, bare tokens, unsupported media types and identity-header spoofing.
Rejected submissions retain no proof or consumption and add no signature or
signing grant. After finalization, exact proof recovery must return the original
submission and preserve every claim, proof, receipt and consumption count.

Both tests have explicit setup boundaries.
Organization/registry/trust/grant and active catalog records are
provisioned under disposable administrator authority. The fourteen restricted
database identities belong to the delegated-use child; the in-process catalog
servers and Issuance bootstrap use the disposable administrator pool. Their
separately provisioned serving-role qualification remains outside this gate.
Human authentication and the machine holder are test actors. The selected
no-status issuance lifecycle
ports are closed bootstrap fixtures; Issuance's public HTTP handlers, human
catalog administration, Compliance evaluation, revocation publication and
Presentation Policy evaluation are not qualified here. Four unselected reference providers share
one authenticated readiness-only fixture origin; attempted record reads fail
and are asserted absent. The public caller follows the selected guarded wallet
URIs, while the internal caller remains a regression view. General wallet
interoperability, production deployment and Rifare's business execution remain
separate gates.

Stopping or disabling the process preserves every command/request claim, nonce,
proof, source observation, evaluation and signed result. An uncertain signing
or commit outcome is not permission to retry, delete a claim or reuse its
identity. Original-result recovery requires fresh current access and preserves
the original evidence times. A future reconciliation workflow needs its own
reviewed contract.

This executable remains a default-off serving candidate. Its optional managed
caller contract is separately selected and locally qualified; general wallet
interoperability, production request/receipt custody, network/CA/role
qualification, required attestation and Rifare business integration remain
separate exit gates. See the
[runtime milestone checkpoint](../../../docs/agent-trust-runtime-milestones.md).
