# Internal delegated-use serving candidate

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
| `GET /internal/v1/organizations/{organization}/delegated-use/challenges/{challenge}/request` | Current-authorized retrieval of the exact original request JWS |
| `POST /internal/v1/organizations/{organization}/delegated-use/challenges/{challenge}/proof` | Current-authorized immutable proof-byte retention |
| `GET /health` | Authenticated process availability; no authority decision |
| `GET /ready` | Authenticated bounded, read-only checks of actual roles, schemas, selected Flow configuration and dependencies |

Health and readiness return status only, with no-store headers. Readiness checks
the original certificate observation again after its awaited checks. Neither a
successful probe nor an authenticated TLS connection supplies current grant
consent, cryptographic machine proof or a business permit.

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

Stopping or disabling the process preserves every command/request claim, nonce,
proof, source observation, evaluation and signed result. An uncertain signing
or commit outcome is not permission to retry, delete a claim or reuse its
identity. Original-result recovery requires fresh current access and preserves
the original evidence times. A future reconciliation workflow needs its own
reviewed contract.

This executable is a concrete internal serving candidate. Deployed request and
receipt custody, production network/CA/role qualification, required attestation,
public wallet contracts and independent consumer qualification remain separate
exit gates. See the [runtime milestone checkpoint](../../../docs/agent-trust-runtime-milestones.md).
