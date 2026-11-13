# Explicit JWT-VC issuance

The pre-authorized issuance API can explicitly select the direct VC 2.0 JOSE
profile supplied by Core. Selection is retained from the template through the
offer, signing claim, and completed response. Existing templates and transactions
without a profile retain their historical behavior and issued bytes.

## Supported selection

| Boundary | Direct profile value |
| --- | --- |
| Securing profile | `w3c_vc2_jose_2026_v1` |
| Template payload format | `VC_JWT_DIRECT_V1` |
| Template gRPC/public format alias | `vc_jwt_direct_v1` |
| Credential media format and signing capability | `application/vc+jwt` |
| Configuration ID | `<credential_type>#vc2-jose-2026-v1` |
| Discovery marker | `marty_securing_profile` |
| Issuance protocol | `OID4VCI_PRE_AUTH` |

This batch supports the ordinary organization issuer metadata route and
`wallet_only` pre-authorized issuance. It does not enable authorization-code,
Canvas/application, renewal, DIDComm, Apple Wallet, or Credential Manager routes
for this profile. It does not change historical JWT aliases or introduce
automatic profile detection. The profile is an explicit deployment extension;
these changes do not assert OIDF certification, OB3 JWT-proof conformance, or
independent-wallet qualification.

## Register explicit signing authority

Use a separately registered opaque signing service, with an appropriate existing
Transit/KMS key binding, an active issuer profile, and **an explicit
`application/vc+jwt` entry in `credential_formats`**. The issuer profile selects
`VC_JWT_DIRECT_V1` and `vc_jwt_issuer`. Existing organization, key-purpose,
algorithm, key-reference, one-use grant, and payload-digest checks still apply.
The direct profile requires `ES256`, `ES384`, `EdDSA`, or `RS256`; unsupported
direct issuer algorithms are rejected before selection or publication. Historical
algorithm admission remains unchanged.

Missing or empty capability lists, and a list containing only `jwt_vc_json`, do
not authorize the direct format. Recognized media/protocol aliases undergo the
same capability check. A direct request paired with OAuth or LTI signing purpose
is rejected before purpose-based remapping.

The generated `managed-openbao-transit` service stays read-only and retains its
existing capability list. Editing a stored copy of that generated service does
not enable this profile. Register an explicitly scoped service instead; no
private key or provider credential belongs in template configuration.

## Create a template

Create a new template through the authenticated public
`POST /v1/credential-templates` API. Its active, organization-authorized compliance
profile must select `VC_JWT_DIRECT_V1` and `OID4VCI_PRE_AUTH`. Its selected issuer
must resolve to the same direct format. The gateway preserves the policy and
continues checking those exact bindings before forwarding the write.

The following public synthetic example shows the profile-specific fields and
the existing template prerequisites; referenced organization, compliance,
revocation, and issuer identities must already be valid for the caller.

```json
{
  "organization_id": "org-example",
  "name": "Employee credential",
  "credential_type": "EmployeeCredential",
  "compliance_profile_id": "direct-credential-compliance",
  "revocation_profile_id": "credential-status-profile",
  "issuer_did": "did:web:issuer.example",
  "credential_payload_format": "VC_JWT_DIRECT_V1",
  "supported_formats": ["VC_JWT_DIRECT_V1"],
  "issuance_protocol": "OID4VCI_PRE_AUTH",
  "privacy_posture": "standard",
  "claims": [{"name": "employee_id", "type": "STRING", "required": true}],
  "validity_rules": {
    "default_validity_days": 2,
    "not_before_offset_seconds": -30,
    "renewable": false
  },
  "jwt_vc_profile": {
    "contract": "marty.jwt-vc-template-profile/v1",
    "securing_profile": "w3c_vc2_jose_2026_v1",
    "signature_lifetime_seconds": 3600
  }
}
```

Activate through the existing template activation API after its usual status,
issuer, revocation, and trust checks. This profile requires exactly one supported
format, no wallet-specific configurations, and no selective-disclosure or ZK
fields. Retired DTC/MRV credential-type identities remain unavailable.

Omitting `jwt_vc_profile` preserves legacy behavior. An explicit null, unknown
contract/profile, extra policy member, or conflicting format is rejected. A
legacy draft or a new version of a legacy template cannot be converted by PATCH;
create a fresh direct template with its own compliance binding. An already
direct draft may update its policy, and new versions of a direct template retain
that policy. The compliance identity is not an updateable template field.

The equivalent gRPC create/update/response field is `jwt_vc_profile_json`; an
empty string means omission. A nonempty value must contain the same closed JSON
policy. New issuance reads require the actual supplied positive bounded validity
rules, template version, and credential type; they do not substitute legacy
defaults for an incomplete direct template response.

## Discover, offer, and redeem

Organization metadata at
`/.well-known/openid-credential-issuer/org/<organization_id>` exposes one exact
suffixed configuration ID, `format: application/vc+jwt`, and
`marty_securing_profile: w3c_vc2_jose_2026_v1`. Duplicate selected configuration
IDs fail closed. Apple Wallet and Credential Manager metadata do not advertise
this selection.

Call `POST /v1/issuance/initiate` with the active template ID and existing issuer,
subject, claims, and authorization inputs. The reservation freezes the exact
profile/configuration, template identity/version, timing policy, dataset, and
issuer target before exposing the offer. Idempotent initiation recovers that
reservation before rereading the template. Later template edits cannot rebind it.

Use the offered pre-authorized token exchange and submit the exact
`credential_configuration_id` to `POST /v1/issuance/credential`, together with
the required proof and existing bearer/DPoP authority. Missing, conflicting,
unoffered, or legacy configuration selections are rejected for direct
transactions, including completed retries. Do not send the removed `format`
member or substitute a legacy wallet-variant ID.

Direct issuance accepts supported claims or an explicit credential subject. A
caller-supplied complete credential document or top-level JWT/credential timing
claims is rejected instead of being repaired or silently ignored.

## Independent time policy and replay

Offer/access-token expiry remains authorization lifetime. The JWT lifetime
starts only when the winning `authorized` to `signing` claim holds the existing
transaction/session locks and passes fresh database wall-clock authority checks.
One whole-second signing time produces the retained `iat`/`exp` and independently
derived credential `validFrom`/`validUntil`.

For the example, a signing time `T` yields JWT expiry `T + 3600`, credential start
`T - 30`, and credential expiry `T - 30 + 172800`. A future credential start is
allowed only inside the JWT lifetime; the intervals must have a nonempty overlap.
Signature lifetime is bounded to 366 days and credential duration to 1095 days.

The winning claim commits all concrete times with the reserved credential ID
before remote signing. Concurrent recovery compares the full frozen selection
and policy; an already concrete expected timing cannot be normalized away.
Completed replay returns the original raw credential and response selection
without resigning, refreshing expiry, or consulting a current template. The
existing terminal failure and in-progress behavior is retained.

## Database and mixed-version rollout

The additive template migration `0004_explicit_jwt_vc_profile.sql` owns nullable
`jwt_vc_profile`. Issuance migration `0013_explicit_jwt_vc_profile.sql` owns
nullable selection and signing-timing columns. Historical NULL rows are not
backfilled or rewritten.

Direct template storage uses a distinct `jose1_*` status namespace. New services
expose the ordinary public statuses; old active/draft queries cannot discover
these rows. The new protobuf payload discriminator survives an old decoder and
is rejected by its strict issuance format admission. Database checks refuse
stale old UPSERTs and old signing claims that omit the required profile/timing.

Auth-session and transaction triggers reject unsupported direct authorization
routes, including pre-existing sessions and old bind operations. Template
creation/activation requires the exact validated issuance check and both enabled,
unfiltered triggers. Startup validation binds check calls to the exact predicate
function/signature, argument names, body and metadata, as well as the exact trigger
definitions. A same-name constraint or disabled/filtered trigger is insufficient.

Install and validate the issuance guards before opting in any template. Route
template-management traffic to upgraded services: old unfiltered template-list
readers reject an unknown `jose1_*` row and can fail the complete list. This is
fail-closed compatibility, not transparent availability for old management nodes.
Existing legacy rows and their filtered discovery behavior remain unchanged.

These source changes do not run a live migration or authorize deployment.

## Validation boundaries

Native tests cover strict policy transport, old protobuf admission, capability
aliases, exact public discovery/offer selection, independent timing, concurrent
comparison, issuer-target changes, and replay without resigning. The existing
provider-gated JWT-VC builder test now signs both historical and direct complete
synthetic OB3 credentials through a disposable remote Transit key and verifies
the direct result with Core's authenticated profile API. Signature/profile/expiry
failures remain failures; issuer trust, credential status, and holder policy are
reported separately as not checked by that proof-only API.

The real database controls are included in the existing
`credential_postgres_contract` executable and `issuance_credential` CI obligation.
They exercise both real migration owners, template-first refusal, stale writers,
drift, historical rows, old authorization binding, and concurrent signing claims.
They require `ISSUANCE_POSTGRES_TEST_URL` pointing to a disposable database whose
name ends in `_test`. A run without that variable does not execute those controls
and must not be reported as database validation. Existing template migration
tests retain historical JSON-column coverage.

The bounded frozen-verifier path is documented in
[Explicit JWT-VC verification](explicit-jwt-vc-verification.md).
Independently implemented wallet/verifier qualification remains separate work.
Issuer support alone does not establish full end-to-end policy acceptance or
close Core issue 421.
