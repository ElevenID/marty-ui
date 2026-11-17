# External learner association

The storage and typed adapters in `0017_external_associations.sql` and
`external_association.rs` implement independently approved producer sources and
explicit learner consent. The protected schema owner registers migration 17 and verifies its catalog;
the read-only startup qualifier checks the actual authenticated LOGIN and all
reachable roles. Public Gateway routes, activation wiring and browser/connector
integration remain development work and must be completed before activation.

## Authority

All connector traffic uses the public Common Gateway. Only Gateway-authenticated
canonical API-key identity may enter the producer transport. The exact
`identity:attest` scope is separate from `evidence:submit`; neither a wildcard nor
an evidence grant grants identity authority. Independently authorized Core
administrators need `external-association:manage` to register and approve a source.
Creation, key replacement and expiry changes leave that source inactive.

A source pins its canonical organization key and key revision. It only permits
challenges for current, active Core bindings of the same source. Core derives the
application, subject and learner from the binding and confirmed application
ownership. The producer supplies an opaque SHA256-shaped account reference;
that reference, provider claims, email and roles never select the canonical user.

## Challenge and consent

The connector must generate a fresh random 32-byte code and persist the original
operation, challenge, intent and recovery pointers before dispatch. The displayed
code is canonical unpadded base64url (43 characters). Its SHA256 over the decoded
32 bytes is sent with challenge creation. Core stores the hash; the learner
transport decodes and hashes the original code before binding SQL parameters.
Codes must stay out of URLs sent to servers, logs, referrers and analytics.

A challenge lives at most five minutes and cannot outlive its source or current
application. Creation captures source, key, binding, application and ownership
revisions. Explicit consent requires the captured authenticated learner and the
original code. Core revalidates every captured authority row before and after
atomic challenge, identity, binding-edge and audit writes. A pending challenge
creates no identity relationship. Association creates no verified evidence,
approval, signing permission or issuance authority.

## Current state and recovery

Inspect and receipt recovery use distinct `kind: current` and `kind: receipt`
envelopes. Original receipts belong to the original actor, organization and
resource. Replaying an original operation never reapplies it or restores authority.
Failed or malformed mutation responses after dispatch are uncertain; recover the
original pointer instead of generating a new operation or retrying automatically.

Current inspection dynamically checks canonical authority and the active identity
and binding edge. A confirmed relationship can outlive its proof-code lifetime;
the expired code cannot confirm another operation. Producer inspection omits the
Core application, subject and identity record. Learner inspection exposes only
the captured learner's resource and matching identity summary.

## Unlink, relink and closure

Only the canonical learner can unlink an identity. Unlink deactivates all its
binding edges and increments its durable consent generation. Every challenge
captures that generation; confirmation and reads reject older generations even
after a different challenge relinks the identity.

Relink is an explicit action requiring the expected inactive identity revision
and a fresh challenge from the current generation. It activates only the newly
consented binding edge. Earlier edges and codes remain unusable. The account
reference cannot silently move to another canonical user.

The original producer may abandon a pending challenge or record its actual
expiry. Neither operation creates consent. The learner may deny a pending
challenge even after source revocation. Terminal challenges and immutable
operation records are retained; retention policy and deployed-role qualification
remain activation requirements.

## Protected schema and runtime role

The owner command applies migration 17 and verifies the exact catalog on both
migration and verification. Association, ownership and canonical binding
relations are pinned, including column collations, guard/helper bodies, indexes,
constraints, triggers, rules and PUBLIC privileges. The observation validator
keeps its original catalog for databases at 14/15 and uses an exact extended
catalog for the incoming binding foreign-key triggers installed by 17.

Runtime installs no DDL or grants. Its authenticated LOGIN must match the current
role and use `session_replication_role=origin`. Qualification rejects dangerous
attributes, predefined roles, parameter grants, database/schema creation,
function/table ownership, canonical table writes (including column INSERT),
immutable-column/journal updates and destructive table privileges. Reachable
memberships are checked even when their inheritance flag is false. The explicit
required function and mutable-column grants must also exist.

## Local qualification

`python3 scripts/run_application_ownership_contract.py --source-contract` uses a
disposable pinned PostgreSQL 16 instance, an actual restricted LOGIN, exact
production Rust modules and production-lock registry dependencies. It exercises
concurrent original-operation replay, privacy, current versus historical reads,
canonical revisions, code handling, unlink/relink generations, abandonment,
expiry and rollback of injected audit-time authority or edge changes. This does
not qualify deployed roles, public HTTP authentication or a browser journey.
