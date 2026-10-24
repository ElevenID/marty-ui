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
One shared PostgreSQL query supplies those heads. Manual approval now requires
all required heads and the selected PolicySet to permit the operation before it
reserves a transaction, using the same evidence/policy kernel as signing. This
deliberately tightens the previous behavior, which allowed an unsigned reservation
and deferred the policy decision to signing. Approval locks and checks current
head identities and the selected PolicySet before committing, including templates
without evidence claim mappings. A null binding policy falls back to the template
policy. Reconciliation and legacy atomic writes retain the same snapshot custody.
The final signing check remains mandatory after approval. Signing reprojects
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

The earlier projection source and an eighteen-rule template have been exercised
on beta's explicitly local 68da runtime. The manual-approval tightening described
above is not yet deployed or qualified as D07/D08. Deploy the new guard with exact
local source binding, then run fresh wallet receipt, verification, negative/recovery
and cleanup operations. AGS activity labels are read from the selected standard line item
when configured claim rules request that field. Missing result event timestamps
already use the fact processor's real observation time; no provider event time is
invented. This source support still needs fresh deployed AGS qualification.
The admin claim editor now exposes requirement ID, fact type, public JSON pointer
and optional date format for evidence rules. Clearing optional selectors removes
their keys, preserving the shared Rust contract. Five focused editor tests pass,
including both typed-value and date-format saves through the production API
client boundary. The current seeders use the same production template API. No imported
report, synthetic source control or successful compilation establishes a live
demo result or official OID4VC conformance.

Review corrections bind reconciliation to the repository's existing current-head
reader, preserving immutable history separately. A real PostgreSQL contract now
retains two revisions for one logical fact, proves only the explicit current head
enters the reconciliation snapshot, and commits recovery against that snapshot.
Automatic approval receives the same guard configuration as manual approval and
signing, using evidence age for mapped facts and readiness age for the binding.
The two opposite age configurations are covered by one focused behavior check.
Seven approval behavior checks, two actual disposable PostgreSQL contracts,
targeted Clippy (library and main binary), and formatting pass. These checks
address the reviewed source risks; they do not qualify a demo recording.

The remaining PR1464 followups are consolidated from its published incremental
range d098a5e3..4fdcfd3c. Mutable Canvas course progress uses fresh observation
ordering so an old completion date cannot prevent recovery. Flow retains verified
SOD fields only across the same immutable passport job and rejects contradictory
signed material. The adapters retain owned resource cleanup, native callback
denials, actual launch/job correlation and bounded verifier failure diagnostics.
The earlier adapter workaround that omitted denied management approval is not
adopted: a fresh HTTP409 and zero reservation, claim and credential are required.

CI39861914435 exposed a concrete assertion-shape regression: missing REST activity
names added a null field to facts. The shared Rust name selector now adds the
field only for a nonblank authoritative name, consistently in the assertion and
hash input. The unchanged published successful-fact contract is checked directly;
no frozen outcome is rewritten to accept the regression. Focused consolidation
verification passed six Rust controls (including an actual local REST provider),
77 Python controls and 70 Node adapter controls. Existing live R34 results remain
historical and source-bound; this consolidation is not a fresh demo or official
conformance result.

The next exact-source CI39864089970 passed the timeout/lease preflights and
109 worker controls, but rejected the course fact in the issued-facts replay:
its effective_at used the observation clock despite a valid provider updated_at.
The course helper now preserves explicit revision timestamps and falls back to
observation time only when no valid revision exists; completed_at remains excluded
because it identifies the first completion event. Both single and bulk reads use
that helper. The focused recovery control covers valid/missing/invalid revisions,
and the real HTTP contract retains all four original timestamp expectations.
Frozen oracle files and their hashes remain unchanged.

The AGS enrichment uses the standard [read-only line-item service](https://www.imsglobal.org/spec/lti-ags/v2p0/)
and Canvas's [LineItem label](https://developerdocs.instructure.com/services/canvas/resources/line_items).
The provider reuses shared claim selectors, token grants, origin/TLS trust and
bounded response handling. It reads metadata only for a valid matching mapping,
binds nonempty results to the selected learner and line item, and rejects foreign
line-item IDs or unusable labels. The label enters both assertion and observation
hash input. Unmapped legacy observations retain their original field set. AGS
result URLs preserve line-item routing queries. The real repository resource read
now includes the owner-defined rules so enrichment works outside test fixtures.
Focused verification is source/transport/database evidence, never a live Canvas
result or official OID4VC conformance claim.

AGS source verification passed three shared claim-mapping controls, three scoped
AGS controls with actual HTTP grant/metadata requests, and the real PostgreSQL
management/resource contract in both JSON and JSONB configurations. The owned
scratch database was removed by exact inspected container identity after the
contract passed. Library Clippy and formatting passed. Production tool
registration already advertises lineitem.readonly together with result.readonly
when AGS capability is selected. Fresh stock Canvas execution remains required.

The latest recorder D07 attempt (660a1ec2) exposed an unsigned reservation while
current authoritative evidence denied eligibility. It remains failed; its pending
transaction was revoked and owned Canvas resources retired. No signing bypass was
established. Focused controls cover HTTP409 with zero reservation for missing,
failing, stale, unverified or policy-denied evidence and successful recovery. A real
disposable PostgreSQL contract exercises changed heads and PolicySet edits between
snapshot and reservation, template-policy fallback, successful recovery, and the
existing automatic/legacy paths. These checks do not qualify a demo recording.

Current-main reconciliation replaces the shortened policy table in the approval
contract with the production Organization migration, valid UUID identifiers,
foreign keys and required timestamps. That stronger fixture exposed a production
query binding defect: the shared policy lookup bound text parameters directly to
UUID columns. Its parameter casts now preserve indexed UUID comparisons for both
approval/reservation locking and the signing-time guard. The original failed
control remains recorded. Fresh native verification passes the approval PostgreSQL
contract, both Organization migration controls on the same database afterward, and
five manual-approval HTTP cases. Stock D07/D08 execution remains required; these
source controls do not qualify a demo recording or official conformance.
