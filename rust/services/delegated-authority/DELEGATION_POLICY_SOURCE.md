# Concrete delegated-use Cedar policy source

`OrganizationDelegationCedarPolicySource` implements the existing
`CedarPolicySource` port with actual Organization ownership. Construction pins
the tenant and policy UUID. It returns the exact active policy revision/digest,
the fixed `MartyDelegatedUse/1.0` schema, two attribute-free entities bound to the
actor/resource, and the canonical MMF engine.

The Organization source retains the complete original request, policy snapshot,
schema/actions, entities, history digest and source times before returning an
opaque current observation. The adapter verifies scope and original time bounds
again after MMF compilation. Missing, draft, archived, foreign or expired source
state fails closed. Runtime input cannot provide an allow flag, an entity graph
or another policy identifier.

The existing `MmfCedarEvaluator` evaluates the actual requested Action URI against
the finite owner-approved action set. Existing delegated-use behavior remains:
proof, exact grant/consent and operation constraints must qualify first; a
completed Cedar policy denial becomes signed DENY evidence; source errors remain
errors and cannot be fabricated into a completed decision. The original receipt
records the selected immutable policy identity, revision and digest.

This source selects **EXACT_OPERATION** only. Its scope must contain the precise
service-built constraint record and original operation digest. It supplies no
domain entitlements, business resource ownership or budget state. An
EXTERNAL_PROFILE request requires a separately owned adapter and is rejected by
this concrete selection. Rifare retains domain permissions and all execution,
reservation, provider and business outcome responsibilities.

## Composition

Construct `PgDelegationUsePolicySource` from its restricted Organization source
connection, then `OrganizationDelegationCedarPolicySource` with the selected
organization and policy UUID, then supply that source to `MmfCedarEvaluator`.
The original grant, consent, machine proof, Flow and receipt owners remain
explicit inputs to the larger `DelegationUseAuthorizer` composition. No
delegated-use executable, Gateway route or public capability is enabled here.

The source's private append-only observations preserve full source provenance;
historical retrieval never creates fresh authority. The current signed receipt
shape and previously published Delegated Authority migrations are unchanged.
No new Delegated Authority migration is needed for this source selection.

## Qualification

Local tests run the actual Organization owner and restricted source with the real
MMF engine. They cover permit/deny decisions, exact request/action/resource/
audience/revision binding, immutable source history, archival, cross-tenant and
delegate substitution, unsupported external context and clock regression.
Those test requests are internal policy fixtures. The tests do not independently
qualify caller authentication, cryptographic proof, grant/consent lifecycle,
production custody, public transport or Rifare business execution.

See [Organization ownership and schema](../organization/DELEGATION_USE_POLICY.md)
and [retained delegated-use commands](USE_COMMANDS.md).
