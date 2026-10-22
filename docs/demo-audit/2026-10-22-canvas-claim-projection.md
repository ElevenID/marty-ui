# Canvas claim projection: source checkpoint

The applicant's shared Rust claim mapper now also serves Canvas approval,
offer preparation, reconciliation and the signing guard. `FORM_FIELD` and
`SYSTEM` retain their configured roles. `EVIDENCE_EXTRACTION` selects one
verified current fact by requirement ID or fact type and reads a JSON pointer
under assertion, scope or the observation/effective timestamps. It cannot read
provider credentials or verification internals. Missing or ambiguous evidence
removes the mapped claim, including any forged form fallback.

Canvas supplies only current-head facts with matching tenant, application,
subject, requirement, source and scope, verified status and bounded freshness.
One shared PostgreSQL query supplies those heads. Mapped manual approval also
checks their identities under row locks before committing. Signing reprojects
against current facts and rejects changed or injected claim values. System
dates retain the reservation clock while evidence freshness uses the actual
signing clock. Mapped transaction reuse and offer refresh update authoritative
claims without rotating existing holder capabilities. Unmapped legacy templates
retain their historical reuse semantics.

Both native and gateway badge seeders now configure all eighteen claims from
issuer-owned constants, the signed Canvas course context, learner identity and
verified score facts. REST activity names enter both the assertion and its
normalized observation hash input, so a name change cannot reuse stale evidence.
These are regeneration inputs, not evidence that a demo passed.

Focused source verification includes the signing-time change/recovery control,
mapped reuse/capability preservation, activity-name/hash binding, the shared
mapper's ambiguous/fallback/timestamp controls, the native template mapping,
existing approval/KMS-boundary behavior, applicant claim assembly, and an actual
disposable PostgreSQL approval contract including mapped row-lock execution.

This source is not deployed or qualified as D07/D08. Next, update the existing
template through its production API, deploy a provenance-bound local source
runtime, and run fresh wallet receipt, verification, negative/recovery and cleanup
operations. AGS-only results still lack an authoritative activity label and may
lack an effective timestamp; do not invent those fields to satisfy this mapping.
They need supported provider enrichment before an AGS-only badge can qualify.
The admin claim editor also needs evidence-selector controls beyond its existing
source picker; the current seeders use the production template API. No imported
report, synthetic source control or successful compilation establishes a live
demo result or official OID4VC conformance.
