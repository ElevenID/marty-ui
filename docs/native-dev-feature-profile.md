# Native development feature profile

This profile includes the implemented agent, delegation, verification, wallet,
and external application capabilities in a fresh native installation. A selected
capability, a healthy service, an owner-configured flow, and a successful user
journey are separate results. Record each result against the exact application
source, installer, bundle, service image, and frontend build used to obtain it.

The profile is opt-in through `--feature-profile-file`. Omitting it preserves the
ordinary installation contract. It requires native managed local PostgreSQL and
cannot be combined with the external PostgreSQL or foundation input. Existing
external OIDC authentication and an externally hosted application remain valid
selections. The fresh application, Flow, and delegated authority state live in
the same local PostgreSQL instance; an existing provider database is not
rewritten or adopted.

## Selection and first installation

The source document has schema `elevenid.installer-feature-profile/v1` and two
closed optional sections, `agent_trust` and `workflows`. At least one capability
must be selected. Unknown fields, arbitrary environment keys, custom Compose
layers, caller-selected credential names, and alternate internal service origins
are rejected. The native owner retains the exact source bytes and a typed
selection, then binds imported and generated material in its credential manifest.

The workflow section has the following first-install shape. The producer name
is an explicit local identity and must match the later governed Flow binding.
This example creates no organization, credential, policy, or authority.

```json
{
  "schema": "elevenid.installer-feature-profile/v1",
  "workflows": {
    "public_verification": {
      "activation": "awaiting_owner_configuration"
    },
    "wallet_governance": {
      "flow_producer_id": "flow-primary"
    },
    "verification_prerequisite": true,
    "application_ownership": true,
    "external_associations": true,
    "external_observations": true
  }
}
```

Agent trust selection additionally deploys the directory, enrollment, human
command, and approval capabilities. Its organization must equal the actual
`MARTY_ORG_ID` record created by Organization's native startup bootstrap; model
admission checks that binding. An arbitrary nonexistent organization UUID is not
an acceptable substitute. Delegated use is an explicit selection within that
section. Its governed profile, policy, definition, workload mapping, and signing
key references come from authenticated owner operations. The native activation
owner binds those inputs after the human has signed in and has current
organization membership. The startup organization record alone grants no human
membership or consent.

Public verification initially has no active catalog or demo-holder mint file
mounted into Flow. Its explicit unavailable response is expected in that state.
Delegated use similarly cannot claim readiness before its actual Flow and policy
references resolve. These states must remain visible in the deployment receipt;
they are not successful end-to-end qualification.

Source contracts: [feature selection and activation owner](../rust/crates/deployment-catalog/src/installer_features.rs),
[workflow selection](../rust/crates/deployment-catalog/src/installer_workflow_features.rs),
and [native command selection](../rust/crates/deployment-catalog/src/installer_command.rs).

## Feature matrix and actual user journeys

| Capability | Deployed dependencies and authority | Owner configuration and minimum acceptance |
| --- | --- | --- |
| Native external OIDC lifecycle | External provider, native authorization application, Auth, Gateway, and the exact console/API origins. Keep the configured issuer and native authorization endpoint. An upstream logout origin is only needed when the provider exposes that actual redirect flow. | Sign up, confirm email, sign in, complete or cancel MFA, recover a password, and sign out. Verify the intended `next` route survives cancellation/retry and no previous cancellation alert appears on a successful new attempt. Confirm session restoration and current organization membership separately. |
| Agent directory, enrollment, human grant commands, and exact-terms approval | Gateway and Organization backend gates, service authentication, separate enrollment/command/approval hosts and database roles. UI build flags alone do not enable these backends. Organization seeds its permission catalog; a successful external login alone grants no organization role. | Open `/console/org/agents` as the intended owner; register and enroll a test agent, inspect enrollment-pending status, edit metadata, replace a key, suspend, revoke, and retire as applicable. Use the native/API grant command flow to produce a real grant link. Review `/console/org/delegation-grants/:grantId/approve?revision=...&terms_digest=...`, confirm the exact terms, and withdraw consent. After withdrawal, the earlier success alert must disappear and a fresh authority check must deny use. |
| Delegated use | Separate authority, consent, organization, Flow, replay/receipt, and credential-source roles; a shared Flow/delegated-authority database; current governed deployment/policy/definition pins; verified owner HTTPS; exact mTLS workload mapping; separately scoped request and receipt signing credentials. | Register the actual native caller identity and bind its actual leaf fingerprint. Activate the actual grant using the supported command flow. Exercise native `START_USE`, one allowed action, one out-of-scope action, `FINALIZE`, and recovery. Replay or withdrawal must not create fresh authority. This is a native/API flow; there is no browser-only “log in as agent” wizard. |
| Public verification | Flow, Issuance, verification/presentation owners, Signing Keys, a separate demo-holder mint capability, and a bounded catalog bound to the console origin and owner-created organization/principal. | Create the governed issuer, holder/verifier references, profiles and scenarios through their owner APIs. Activate the exact catalog in a new native generation. Exercise `/verify`: select a scenario, obtain and complete the supported verification flow, inspect its result, switch scenarios, retry, and cancel. Check that prior result/QR/error state resets and limits remain effective. The website's synthetic interaction is not this backend proof. |
| Paired wallet issuer and verifier governance | Device Registration reads Trust Profile over verified HTTPS; Trust Profile reads the real Flow owner over verified HTTPS. Existing service authentication remains required. The Trust Profile server uses its own nonexportable workload key. | Create and enable the real governed issuer/verifier profiles. Exercise `/wallet/setup`, select the intended organization and profiles, and use a compatible native wallet consumer for pairing and verification. Changing organization or profile invalidates the old challenge/QR. An available selector alone does not prove an issued credential or accepted presentation. |
| Verification before issuance | A dedicated Flow-to-Issuance capability, verified Flow owner HTTPS, exact template/policy/definition revisions, and existing issuer signing authority. | Configure `managed_sd_jwt_dcql_same_holder_v1` with the matching managed presentation policy and supported `SD_JWT_VC` / `OID4VCI_PRE_AUTH` flow. Prove a valid same-holder result permits the intended issuance; a different holder, expired proof, changed revision, and replay must fail. Configuration and issuance are API/native flows, not a new console wizard. |
| Application ownership, external association, and external observation | A restricted canonical Issuance role plus separate association and observation producer roles, migrated by their source owners before runtime validation. Both Issuance aliases use the restricted role; neither receives the broad schema-owner password. | Propose, confirm, inspect and revoke real application ownership through owner APIs. Exercise `/console/identity/associations/:organizationId/:challengeId` for consent, deny, relink/unlink and recovery with the intended human. Submit and materialize an observation through its producer API; preserve its `UNVERIFIED` / `UNSIGNED_PRODUCER_ATTESTATION` meaning. Observation materialization must not create a verified credential or silently upgrade trust. |

The agent directory and approval UI use `VITE_AGENT_ADMIN_ENABLED=true` and
`VITE_DELEGATION_APPROVAL_ENABLED=true` only when the matching backend profile is
selected and its readiness checks pass. Feature availability must not be inferred
from `web.enabled_sections`; that setting controls the local website/application
hosting selection.

Detailed owner contracts:
[agent identity and approval](agent-identity-and-approval-candidate.md),
[enrollment](managed-agent-enrollment-candidate.md),
[human commands](../rust/services/delegated-authority/COMMAND_HOST.md),
[delegated use](delegated-use-runtime-candidate.md),
[wallet authority](development/paired-wallet-verifier-authority.md),
[verification before issuance](verification-before-issuance.md),
[application ownership](external-application-ownership.md),
[external association](architecture/external-learner-association.md), and
[observation materialization](architecture/external-observation-materialization.md).

## Owner activation and immutable generations

After actual human login, establish current membership in the intended
startup-owned organization and use the existing authenticated owner APIs to
create its policies, profiles, definitions, signing key references, and workload
mapping. Retain the exact owner response identifiers
and revision/digest values without copying user credentials into a public
receipt. An activation document is evidence binding, not a substitute for the
owner's authorization or readiness check.

Initial owner activation is once-only. Configure every selected pending runtime
in the same activation input: if both delegated use and public verification were
selected, both must be ready before activation. The native owner refuses an
input that leaves either runtime awaiting owner configuration. Later generations
renew credential material; they do not perform a second policy activation. See
the [activation coordinator](../rust/crates/deployment-catalog/src/installer_feature_activation.rs)
for the exact binding and recovery contract.

Public verification activation uses
`elevenid.installer-public-verification-activation/v1`. It binds installation ID,
feature profile hash, exact catalog hash, owner API receipt hash, console origin,
organization ID, and principal. Its catalog is bounded, rejects duplicate JSON
members, and is still validated by Flow's full configuration contract. The
native activation coordinator must retain the exact bytes, create a new
generation, qualify the resulting model and service readiness, and then activate
that generation. Editing a retained catalog, selection, or credential file in
place is not an activation operation.

The separate `feature-profile-generations` owner retains
`feature-profile-generations.json`; it does not take over the baseline
application-generation directory. An unrecorded generation directory is refused.
The first activation receipt, `feature-profile-activation.json`, and prior
generations remain retained evidence. An interrupted activation must be inspected
and recovered through its native owner rather than retried by overwriting files.

## Credentials, TLS and database boundaries

All feature credential inputs live under the native owner's private
`feature-profile-secrets` directory. Runtime services receive individual read-only
file mounts at `/run/feature-profile/<fixed-name>` with automatic host path
creation disabled. No service receives the whole directory. The manifest binds
the exact inventory after generated and imported materials are complete. Neither
the ordinary `secrets` directory nor an unrelated temporary directory is an
acceptable substitute.

The one-shot `marty-feature-identity-bootstrap` helper is part of the exact
authenticated services image and is selected only as a native setup job. It uses
the existing workload CA and OpenBao primitives, preserves the baseline sixteen
workload identities, and adds only the selected fixed feature identities. Workload
private keys remain nonexportable in OpenBao. A separately owned local PostgreSQL
transport key has its own native custody and is not a workload signing key.

| Material | Permitted consumer |
| --- | --- |
| Public verification catalog and demo-holder mint token | Flow |
| Flow/Issuance prerequisite capability | Flow and the two Issuance aliases |
| Trust Profile server certificate and remote signing token | Trust Profile |
| Feature signing custody and grant-verification tokens | Signing Keys |
| Distinct Signing Keys read credential | Existing fixed internal readers and delegated-use request/receipt readers |
| Canonical Issuance, association and observation database URLs | The two Issuance aliases, with the exact separately configured pools |
| Feature renewal AppRole role ID and secret ID | The native renewal helper owner; never a serving application |

Signing Keys reads must use a credential distinct from Issuance and signing
authority. The profile updates all existing internal readers together so that a
new read credential cannot strand the old consumers. Mint tokens cannot verify
as an authority shortcut, and grant-verification tokens cannot mint grants.

Credential Template, Deployment Profile, Trust Profile and Flow expose the
required owner routes over their actual managed HTTPS listeners. Client trust
uses the bound workload CA and fixed service origins. Redirects, ambient proxies,
plain HTTP substitution and private key export are not part of the profile.

Database owners run the source migrations once, then serving roles validate
their exact grants. The canonical Issuance role permits four connections across
two pools capped at two each. Each observation and association role permits two
connections across two pools capped at one each. Delegation roles have their own
bounded pools. A successful broad-owner connection does not qualify any of these
restricted-role paths. The real PostgreSQL qualification must exercise the
canonical materialization lock helpers as well as the intended denial cases.

## Renewal, retention and acceptance evidence

Feature workload leaves and runtime OpenBao tokens have a maximum eight-hour
lifetime. The separate `native-feature-renewal` AppRole retains a private role ID
and secret ID with no time or use limit, so stopping the dev host overnight does
not destroy its ability to renew. Each login receives only the fixed feature
renewal policy and an explicit maximum of ten minutes; normal completion revokes
that session. Its permissions cannot create or rotate keys, change policies or
roles, or renew its own login token. Initial provisioning alone uses root.

Renewal binds five individual inputs: the current authenticated OpenBao CA,
the exact selection, the original role ID and secret ID, and the workload CA.
The two owner credentials remain byte-identical in subsequent generations and
are never mounted into a serving application. Renewal creates new immutable
output; it must not rewrite the original helper output or credential manifest.
A renewed native caller certificate changes its leaf fingerprint. The native
material owner carries an existing owner-approved mapping forward only when it
matches the previous owned certificate and the renewed certificate has the same
public key, subject, and exact native workload URI. It replaces that one pin,
preserves the principal and every byte of all other workload bindings, and binds
the old and new mapping hashes in the immutable renewal receipt. A missing native
mapping remains absent; a mismatched pin, identity, or key is refused. This
bounded continuity does not create an agent or grant. Acceptance still requires
the newly selected runtime and the actual allowed and denied delegated actions;
a historical readiness result does not qualify the renewed deployment.

`feature-identity-output` is retained against its completed helper receipt and
exact file hashes. Its certificates are rechecked at the recorded qualification
time when inspecting historical evidence, so later expiry does not erase that
evidence. Current readiness must separately check the active generation at the
current time. The host inventory recognizes only the selected native owners for
`feature-profile-secrets`, `feature-postgres-transport`,
`feature-identity-output`, and `feature-profile-generations`. Unselected
installations retain their previous inventory serialization and fixed census;
similarly named paths do not become adopted storage. Inventory remains metadata
only and never authorizes deletion.

Complete qualification requires the following evidence for the exact head and
prepared output:

1. Normal public repository CI, including the source test suites and packaging
   contracts. A focused local harness is supplementary evidence and does not
   qualify the full native installer or service image.
2. The actual fresh managed PostgreSQL role/migration/grant/TLS checks, including
   denied broad authority and the declared alias pool budget.
3. The actual feature identity helper, certificate chain/EKU/SAN/key checks,
   token policy and lifetime checks, and recipient-scoped Compose admission.
4. Initial pending-state receipts, followed by authenticated owner configuration
   and native immutable activation. Every selected flow in the matrix must reach
   its owner-configured state before it is reported ready.
5. Browser and native/API happy-path, cancellation/retry, denial, withdrawal and
   recovery checks from the matrix. Bind source hashes, image digests, runtime
   configuration, origins, owner identifiers and test results in the deployment
   record; do not put private credentials in that record.
6. A real restart after an expired login session, a fresh scoped AppRole login,
   and a staged renewal/activation check that preserves prior
   generations and confirms the newly active caller/certificate bindings.

The development target uses the existing host, retained local Docker image
capacity, and existing free provider projects. Do not create a new paid service,
increase a provider tier, or route private repository Actions into this
qualification. Measure host disk and pool capacity before building or starting
the selected services, and keep all older installations and their evidence
outside this fresh profile's ownership.
