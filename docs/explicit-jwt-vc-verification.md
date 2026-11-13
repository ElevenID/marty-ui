# Explicit JWT-VC verification

Presentation policies and standard OID4VP Flow requests can explicitly select
the historical nested JWT-VC profile or the direct VC 2.0 JOSE profile. The
selection is saved with the policy, retained in the frozen DCQL query, and checked
against authenticated issuer and holder signatures. Omitting the selection
preserves the existing claim-based policy and request behavior.

## Supported scope

The initial explicit path requests **one required whole credential by type**.
It requires a cryptographically authenticated presentation from its holder and
the existing nonce, audience, and replay controls. It accepts no requested claims,
global claim requirements, alternate requirements, or additional credential-type
obligations. Existing issuer trust, status, freshness, and authorization controls
continue to apply.

| Boundary | Explicit historical | Explicit direct |
| --- | --- | --- |
| `expected_securing_profile` | `marty_nested_vc2_jwt_v1` | `w3c_vc2_jose_2026_v1` |
| Saved policy / authorization format | `VC_JWT` | `VC_JWT_DIRECT_V1` |
| Template gRPC payload format | `jwt_vc` | `vc_jwt_direct_v1` |
| DCQL credential format | `jwt_vc_json` | `application/vc+jwt` |
| Advertised presentation format | `jwt_vp` | `application/vp+jwt` |
| Template `jwt_vc_profile` | Absent | Explicit direct issuance policy |

The direct template must already meet the requirements in
[Explicit JWT-VC issuance](explicit-jwt-vc-issuance.md). Its supported format list
must contain exactly `VC_JWT_DIRECT_V1`. The historical template must have its
existing `VC_JWT` capability. A template's format, policy, and capability must
agree with the selected verifier profile; Flow never derives an explicit profile
from a wallet's capability list or a returned token's shape.

The supported request modes are standard OID4VP `request_uri`, signed request by
value, and bounded unsigned URL-query requests. Lissi/Presentation Exchange,
HAIP, Digital Credentials API, and SIOP cannot carry this profile. A SIOP-only
start must omit the presentation-policy ID; a supplied ID is rejected instead of
being ignored. Managed SD-JWT prerequisite policies remain a separate existing
profile and cannot be combined with the explicit JWT-VC branch.

## Create the policy

Use the authenticated public `POST /v1/presentation-policies` route. The following
synthetic example assumes the organization, template, and trust profile already
exist and the caller has the usual organization permissions:

```json
{
  "organization_id": "00000000-0000-0000-0000-000000000001",
  "name": "Verify an employee credential",
  "required_claims": [],
  "accepted_credential_types": [],
  "credential_requirements": [
    {
      "credential_template_id": "employee-direct-template",
      "display_name": "Employee credential",
      "required": true,
      "credential_payload_format": "VC_JWT_DIRECT_V1",
      "expected_securing_profile": "w3c_vc2_jose_2026_v1",
      "requested_claims": [],
      "require_fresh_issuance": false
    }
  ],
  "holder_binding": {
    "required": true,
    "binding_methods": ["DEVICE_KEY"],
    "proof_profiles": ["OID4VP_VERIFIABLE_PRESENTATION"],
    "proof_freshness": {
      "challenge_required": true,
      "audience_binding_required": true,
      "replay_detection_required": true
    }
  },
  "trust_profile_id": "00000000-0000-0000-0000-000000000002",
  "freshness": {"require_not_revoked": true}
}
```

The gateway checks the public requirement and substitutes the template owner's
authoritative payload format. The policy owner independently validates the full
saved policy. Activate the draft through the existing policy activation route.
Create, PATCH, and readback retain `expected_securing_profile`; an omitted field
is not replaced with an explicit historical value. Explicit null, unknown
profiles, mismatched formats, optional requirements, and nonempty requested
claims are rejected. When holder binding is required, the public gateway requires
its binding methods, proof profiles, and `proof_freshness` object. Keep the
challenge, audience, and replay flags enabled as shown. The existing holder-only `presentation_proof_required`
behavior is unchanged; it is not the credential-holder authority for this path.

For the explicit historical branch, choose a historical template and replace
the format/profile pair with `VC_JWT` / `marty_nested_vc2_jwt_v1`. A bare credential
does not satisfy either profile's presentation request.

The service gRPC requirement JSON retains the same optional profile member.
`PolicyResponse.holder_binding_required` (tag 16) carries the saved policy owner's
holder requirement to Flow. An old response omits this new field and decodes to
false, so it cannot produce an explicit profile request.

## Start and freeze the request

Use the existing authenticated `POST /v1/flows/verify` route with the active
policy ID, organization, verifier issuer DID, and the selected standard request
transport. Flow resolves the policy and templates once. It uses Core's explicit
query builder and stores the exact resulting query, its digest, the policy
revision, instance, organization, and nonce in private persisted context.

For a direct employee policy, the selected query has this shape; the ID is the
actual saved credential requirement ID:

```json
{
  "credentials": [
    {
      "id": "00000000-0000-0000-0000-000000000005",
      "format": "application/vc+jwt",
      "meta": {
        "marty_securing_profile": "w3c_vc2_jose_2026_v1",
        "type_values": [["VerifiableCredential", "EmployeeCredential"]]
      },
      "require_cryptographic_holder_binding": true
    }
  ]
}
```

Marked queries admit only the documented top-level, credential, and metadata
members. Unsupported `credential_sets`, `claim_sets`, `multiple`, trusted
authorities, extra metadata, mixed credential arrays, null profile markers, or
nonempty claims fail before a typed projection can discard their meaning.
Open Badge type aliases are mapped to the same `OpenBadgeCredential` type used
by the issuer's existing preparation adapter.

Request retrieval uses the frozen query even if current policy/template providers
change or become unavailable. Evaluation separately requires the current saved
policy revision to match. Profile-specific client metadata advertises only the
selected credential and presentation formats. No usable Presentation Exchange
definition is emitted for marked queries; the private snapshot has an exact
empty-object sentinel, which every marked producer/loader checks before signing
or emission. Unmarked snapshots and their query digests keep their existing
representation.

## Authentication and evaluation

The policy owner selects the profile from the saved requirement and validates it
against the exact trusted Flow query before parsing the presentation. Ordinary
public request context cannot supply profile authority, verification time, or
authenticated proof. A failed explicit parse never falls back to historical
token interpretation.

The native verifier authenticates the outer presentation and the exact embedded
credential with Core's explicit profile API. It consumes Core's authenticated
credential document, ID, issuer, subject, types, and proof time. Direct documents
retain their direct representation; they are not rewritten into a historical
`vc` member. The returned material must cover the one frozen query and its type
obligation, with an authenticated holder, matching nonce, and audience.

Registry-backed issuer resolution uses the exact saved authorization format.
An active `VC_JWT` registry binding cannot authorize a `VC_JWT_DIRECT_V1`
credential. Organization scope, method pins, assertion relationships, algorithm,
public key, and source provenance remain enforced. Linked Cedar policy receives
the same distinct direct format, so existing `VC_JWT` allow rules are not
silently widened. Cryptographic success does not establish issuer trust,
credential status, or replay success.

The service evaluates time from its own clock. After issuer resolution, trust,
status, template, and linked-policy awaits complete, it reauthenticates the exact
retained presentation and credential bytes with the pinned public verification
tuple at the final server time. Credential JWT validity, credential document
dates, and presentation validity remain independent. It does not infer proof
expiry from its issuance time. Retained authentication evidence is not
deserializable and redacts raw presentation and credential values in Debug.

## Rollout and validation boundaries

No new SQL migration or backfill is needed for the verifier. The existing saved
policy JSON and private Flow snapshot retain the selection. Upgrade the policy
management/evaluation and Flow nodes before opting in policies. Older policy
readers already reject unknown requirement fields; a saved explicit profile
therefore fails closed on them. Old unfiltered policy lists can fail when such a
row is present, so management traffic must use upgraded nodes. Existing
unmarked policies omit the new member and retain their serialized meaning.

Native tests exercise genuine synthetic issuer and holder signatures, exact
registry and Cedar format identity, independent expiry, final-time rechecks,
trust/status/replay denial, content tampering, and refusal of altered or
JSON-roundtripped proof evidence. Public HTTP/gRPC/gateway and OpenAPI tests
cover policy reachability and readback. Flow tests cover production construction,
freeze/refetch, unsigned and signed request adapters, and unsupported-mode
refusal before signing. Existing legacy vectors continue to guard omitted
profile fields and historical query/digest behavior.

This source feature does not perform a live deployment, change issuer migration
ordering, or establish OIDF certification, OB3 JWT-proof conformance, or
independently implemented wallet/verifier interoperability. Public HTTPS/DID/status
qualification and an independent-wallet run remain separate work. Core issue
421 remains open until those broader qualification obligations are complete.
