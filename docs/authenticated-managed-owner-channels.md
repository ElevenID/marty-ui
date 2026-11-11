# Authenticated managed credential owner channels

This W05 increment authenticates the acquisition of Trust Profile snapshots and
trust assessments, and Issuance-managed SD-JWT status observations. It continues
the native [SD-JWT prerequisite producer](sd-jwt-prerequisite-evidence.md) and the
landed [Flow verification receipt](flow-verification-receipts.md).

The contract is deliberately narrower than completed prerequisite issuance.
Canonical evidence composition and an Issuance-owned, expiring, single-use
continuation remain required. The canonical validator and existing atomic
`claim_for_signing` boundary are unchanged.

## Acquisition and native provenance

Policy uses a dedicated client for the three managed owner operations. Both
owner origins and their public CA bundle must be explicitly configured. General
control-plane URLs provide no defaults or fallback for these operations.

The client selects Rustls explicitly, trusts only the operator-supplied CA
certificates, and verifies the server certificate against the configured
hostname. It requires HTTPS, disables environment proxies and redirects, and
constructs fixed operation paths internally. A credential identifier, request
field, response, or caller-supplied URL cannot select another destination.
Private DNS names and explicit HTTPS ports are supported.

Only HTTP 200 with an `application/json` media type is accepted as an observation.
The request body is bounded by the frozen-contract limit. Snapshot responses
are bounded by the same limit; trust and status responses are bounded to 64 KiB.
Both declared and streamed response lengths are checked. Direct strict DTO
deserialization rejects duplicate and unknown fields before any provenance is
created. Trust-owner HTTP 409 remains the distinct restart-required authority
revision error.

After acquisition, the response must validate against the original tenant,
profile or exact credential selection, and current observation time. Only then
does the client create `AuthenticatedOwnerResponse<T>`. That type has no public
constructor, deserializer, serializer, or mutable DTO accessor. Its debug output
does not print the private status request or credential identifier.

The native resolver traits return these opaque responses, including for snapshot
freezing. The orchestrator retains the trust and status acquisitions until all
later metadata and policy awaits finish. It revalidates the native proof and
both exact owner observations against the final evaluation instant before
constructing `VerifiedManagedCredentialAuthority`. Role checks prevent a status
acquisition from being substituted for a Trust Profile acquisition.

An authenticated response can deny trust or report a revoked or suspended
credential. Authentication does not turn those outcomes into permission.
Serialized projections still cannot reconstruct native provenance or become
`AuthenticatedOid4vpEvidenceV1`.

## Policy configuration

Configure all three settings together:

| Setting | Meaning |
| --- | --- |
| `PREREQUISITE_TRUST_OWNER_URL` | HTTPS origin of the Trust Profile owner, for example `https://trust-profile:8443` |
| `PREREQUISITE_ISSUANCE_OWNER_URL` | HTTPS origin of the Issuance owner, for example `https://issuance-native:8444` |
| `PREREQUISITE_OWNER_CA_CERT` | File containing the public CA certificates authorized to identify these owners |

Origins must have no userinfo, non-root path, query, or fragment. Empty and
partial configurations fail startup. An unreadable, empty, or invalid CA bundle
also fails startup. Configured but unreachable owners fail the operation; they
are never retried through legacy HTTP. Ordinary verification profiles can run
without managed-owner configuration, but the managed prerequisite profile
cannot freeze or evaluate owner evidence in that state.

Policy continues to use `GRPC_SERVICE_TOKEN` for the Trust Profile requests and
`ISSUANCE_API_KEY` plus the exact organization header for Issuance requests. These
authenticate the requesting service at the existing owner handlers. Server
certificate verification authenticates the response channel. This HTTPS
boundary uses server TLS and existing request credentials; it is not described
as mutual TLS. Flow-to-Policy workload mutual TLS remains independently required.

## Direct keyless owner listeners

Trust Profile and Issuance each support an optional direct HTTPS listener. The
same configuration names are scoped to the respective service process:

| Setting | Meaning |
| --- | --- |
| `MANAGED_AUTHORITY_HTTPS_ADDR` | Listener socket, for example `0.0.0.0:8443` on Trust Profile or `0.0.0.0:8444` on Issuance |
| `MANAGED_AUTHORITY_TLS_CERT_FILE` | Public leaf certificate and chain for this owner hostname |
| `MANAGED_AUTHORITY_TLS_KMS_PROVIDER` | `openbao-transit` or `aws-kms` |

For OpenBao Transit, also configure:

```text
MANAGED_AUTHORITY_TLS_KMS_ADDR
MANAGED_AUTHORITY_TLS_KMS_CA_CERT_FILE
MANAGED_AUTHORITY_TLS_KMS_TOKEN_FILE
MANAGED_AUTHORITY_TLS_KMS_KEY_NAME
MANAGED_AUTHORITY_TLS_KMS_KEY_VERSION
```

For AWS KMS, configure the existing remote identity's region and key ARN:

```text
MANAGED_AUTHORITY_TLS_KMS_REGION
MANAGED_AUTHORITY_TLS_KMS_KEY_ARN
```

The AWS provider uses its existing credential resolution. OpenBao tokens should
be scoped to the exact remote key's read/sign operations. The public certificate
must match the selected remote key and include the exact configured owner DNS
name, or IP SAN when an IP origin is deliberately used. Certificate renewal or
an approved key-version change requires the corresponding new public certificate
and remote version. No application private-key file or local signing fallback
is accepted by either provider configuration.

The listener and remote identity must be configured together. Blank TLS settings,
incomplete provider settings, a reused ordinary listener address, and missing
owner request credentials fail startup. Remote identity connection, certificate
admission, and socket binding complete before readiness. Listener errors
propagate through the service's main future. Shutdown drains the HTTPS server
with a bounded grace period.

The direct HTTPS routers expose only these existing operations:

| Owner | Operation |
| --- | --- |
| Trust Profile | `POST /internal/v1/trust-profiles/{profile_id}/credential-authority-snapshot` |
| Trust Profile | `POST /internal/v1/trust-profiles/{profile_id}/credential-trust-evaluations` |
| Issuance | `POST /internal/issuance/sd-jwt-status/observe` |

They reuse the existing owner domain operations, tenant checks and credential
checks. General management, issuance, and administration routes are absent from
these listeners. Existing HTTP and gRPC listeners retain their roles.

This is opt-in service configuration. It does not provision deployment
certificates, publish ports, enable a policy, activate issuance, or change
deployment defaults. A deployment must expose the selected internal HTTPS ports
and provision the named owner certificates before selecting the managed profile.
An explicitly trusted TLS termination layer can serve as the configured owner
origin, but direct listeners keep the certificate boundary at the owning service.

## Validation and remaining boundary

Native evidence tests use a crate-private, `cfg(test)` provenance constructor.
The earlier verification behavior suite now runs as library unit tests so no
test constructor or production feature can manufacture owner provenance from a
DTO. The existing integration target retains consumer-facing rejection tests;
no new integration-test target or release-context exception is needed.

The existing `control_plane_behavior` target includes an explicitly ignored live
keyless owner contract, to be selected only with a fresh isolated OpenBao fixture.
It uses the production remote identity and HTTPS listener and exercises valid
acquisition, wrong CA, wrong owner hostname, malformed or mismatched responses,
redirect/body bounds, owner failure, and approved key rotation. Execution
receipts and exact source identities belong in the publishing PR; an ignored
test is never counted as a completed live gate.

After verifying an official OpenBao 2.5.5 executable, build the existing target
and run it through the disposable fixture:

```sh
cargo test --manifest-path rust/Cargo.toml --locked \
  -p marty-presentation-policy --test control_plane_behavior --no-run

python3 scripts/with_disposable_policy_owner_kms.py --openbao /path/to/bao -- \
  cargo test --manifest-path rust/Cargo.toml --locked --offline \
  -p marty-presentation-policy --test control_plane_behavior \
  managed_authority_http::live_keyless_managed_owner_channels -- --ignored --exact
```

Run the same command with `--poison-proxy` before `--` to test proxy isolation.
The normal fixture removes proxy variables so the legacy HTTP decoy remains
reachable. The proxy case sets an unusable proxy and empties the bypass list in
the test child. Both must pass. Each invocation starts a fresh loopback OpenBao,
creates a nonexportable workload key and scoped signer token, checks cross-key
signing denial, and generates the valid, wrong-hostname and version-2 public
certificates. It then removes its owned process and files. The administrative
token stays within fixture provisioning; no existing KMS endpoint is contacted.

The next W05 step must combine authenticated native/owner observations with
Flow's durable replay receipt while preserving policy-observation and
nonce-consumption times separately. Issuance must then bind that evidence to the
tenant, applicant, authorization session, credential configuration, exact
dataset, saved policy revision, and holder, and atomically consume the expiring
continuation during `claim_for_signing`. None of those broader guarantees follows
from HTTPS authentication alone.
