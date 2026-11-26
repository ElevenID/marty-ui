# Native feature database profile

The optional installer feature profile gives a **fresh, native-managed PostgreSQL database** separate credentials for delegation, delegated use, and the selected Issuance workflows. Supabase can remain the external identity provider. This profile does not move an existing database or alter a retained installer's receipts.

The selection is admitted through `--feature-profile-file` and the closed `elevenid.installer-feature-profile/v1` input. It requires managed PostgreSQL. An external PostgreSQL selection is refused for this initial integration; the unused external candidate database can remain intact.

## Database and transport ownership

All application, Organization, Flow, delegation, and credential-source schemas use the same managed database. In particular, the delegated-use writer and Flow state must share the actual PostgreSQL backend so their existing atomic operation remains intact.

The installer generates 26 distinct database passwords from operating-system entropy. It validates the complete fixed inventory and each URL before retaining them. Every URL selects `postgres:5432/marty`, `sslmode=verify-full`, and the public CA at `/run/feature-profile/feature_postgres_ca`. Missing, duplicate, aliased, changed, or plaintext credentials are refused.

Feature files live in the separately bound `feature-profile-secrets` directory, with an owner credential manifest. A runtime receives individual read-only files at `/run/feature-profile/<name>`. No feature URL or password inventory belongs in the broadly mounted legacy secret directory. Only the roles setup operation receives `feature_database_passwords`; each migration operation receives only its own owner URL and public CA.

PostgreSQL's infrastructure transport owner retains its generated CA key and server key separately. Only PostgreSQL receives the private server-key projection. Application services receive the public CA, never a database private key. The native transport owner controls expiry checks, leaf replacement, PostgreSQL reload, and verification. This is not an application PEM-upload mechanism or a reason to relax existing keyless-workload checks.

The retained `installer-ingress` process carries the fixed PostgreSQL TLS probe because it has no database startup dependency. After normal OpenBao recovery, the maintenance owner can start only the exact retained PostgreSQL and ingress container IDs under recorded running intent. It does not wait for an expired public ingress certificate to become healthy, start setup jobs, recreate a container, or publish a database port. The PostgreSQL-specific command sends only SSLRequest and a verified TLS handshake; it never sends a password or SQL.

Renewal preserves the CA, server key, and directory mount, records its intent before atomically replacing the public leaf, and sends only HUP to the owned PostgreSQL container. A bounded convergence check must observe the new exact leaf fingerprint over a fresh connection before completion is recorded. The full Docker reload/probe transaction has one shared 60-second deadline. Generic Docker exec and kill remain unavailable. Failed or uncertain start/renewal evidence is retained and blocks an automatic repeat; it cannot count as successful recovery. An expired leaf is accepted only by the retained renewal owner, with all original custody, issuer, key, hostname and receipt-chain checks intact.

## Fixed migration and runtime roles

Every feature role is `NOINHERIT`, `NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`, `NOREPLICATION`, and `NOBYPASSRLS`. No runtime role owns a schema, table, or function, or receives a membership in an owner role.

| Database role | Authority |
| --- | --- |
| `feature_delegation_owner` | One-shot owner of the source-owned delegated-authority migrations. |
| `feature_credential_owner` | One-shot owner of the source-owned machine-credential-source migration. |
| `feature_approval_runtime` | Read delegation state and existing approval evidence. |
| `feature_approval_consent` | Append the exact consent/review/confirmation records permitted by the approval producer. |
| `feature_approval_authority` | Append current Organization authority observations and their bound assertion records. |
| `feature_approval_organization` | Read the authoritative Organization membership and permission source. |
| `feature_command_writer` | Apply the existing bounded grant lifecycle command transaction. |
| `feature_command_runtime` | Read existing approval, consent, and authority evidence. |
| `feature_command_organization` | Read current Organization command authority. |
| `feature_use_writer` | Apply the existing delegated-use transaction and its precisely allowed Flow writes. |
| `feature_use_runtime_reader` | Read existing grant and approval evidence. |
| `feature_use_organization_authority` | Read current Organization authority. |
| `feature_use_registry_source` | Read machine registry state and append its observations. |
| `feature_use_access_source` | Read machine-use access and history. |
| `feature_use_machine_policy_source` | Read machine policy and history. |
| `feature_use_machine_policy_evidence` | Append machine-policy evaluation evidence. |
| `feature_use_delegation_policy_source` | Read delegation-use policy and append its observations. |
| `feature_use_machine_audit` | Append the existing machine-authentication audit records. |
| `feature_use_flow_reader` | Read the selected Flow definition and state. |
| `feature_use_flow_ingress` | Apply the precise source-owned proof-ingress contract. |
| `feature_use_credential_trust` | Read Trust Profile authority and maintain its bounded revision record. |
| `feature_use_credential_status` | Read the original Issuance credential and transaction. |
| `feature_use_credential_evidence` | Append machine-credential-source evidence. |
| `feature_issuance_runtime` | Canonical Issuance runtime rights, with scoped application-ownership writes and read-only observation journals. |
| `feature_observation` | Restricted observation ingress and administration; no canonical application/evidence writes. |
| `feature_association` | Restricted association source/consent journal; no canonical ownership or Organization authority writes. |

The exact SQL privileges are in `deploy-config/compose/selfhost-installer/feature-profile/database-grants.sql`. The 14 delegated-use roles follow the serving code's `ROLE_CONTRACTS`; runtime startup independently checks their effective privileges, reachable roles, owner identities, and shared database relationships.

## Ordered native setup

The native owner runs these operations through the authenticated service image and migrations image selected by the release. These are setup dependencies, not manual Compose overlays:

1. Prepare and qualify PostgreSQL's private TLS state, then start the managed database.
2. Run `database-setup.sh roles` from the fixed feature-profile code directory. It authenticates as the existing PostgreSQL owner over verified TLS, requires the fresh database, and creates the exact role inventory in one transaction.
3. Run the normal application schema owners. Run `/usr/local/bin/marty-delegated-use-migrate delegated-authority` using the delegation owner, and the same binary with `machine-credential-source` using the credential owner. Each owner migrator retains its required public CA and `verify-full` check and uses one connection.
4. Run `database-setup.sh grants` after all source migrations finish. It verifies the original owners and migration ledgers, revokes the two owners' temporary database CREATE authority, then applies the fixed grants.
5. Start the selected runtime hosts only after final grants succeed. They qualify the actual connected roles and source boundaries before becoming ready.

The roles phase is intentionally fresh-only. Replaying it refuses without rotating an existing password. An incomplete setup remains an installer-owned recovery task; do not alter receipts, substitute owner credentials into a runtime, or add broader grants to make a readiness probe pass.

## Pool and listener boundaries

Approval and command pool settings preserve their former maximum of eight when absent. The selected native profile supplies bounded limits. The approval authority pool requires at least two connections because an existing authority transaction performs a separate read through that pool. Other new host limits accept one through eight.

The 24 runtime database roles have an aggregate maximum of 50 connections: 23 roles allow two each, and the canonical Issuance role allows four for its two cap-two aliases. Observation and association each use a cap-one pool per alias. The two migration owners allow one connection each. The installer also bounds ordinary service pools and reserves database administration headroom; these are maxima, not claims that all connections are always open.

Credential Template and Deployment Profile expose their existing authenticated resource-owner projections on optional managed keyless HTTPS listeners. The native selection uses `https://credential-template:8443` and `https://deployment-profile:8443`. These listeners require a complete remote TLS identity and strong service credential, refuse collisions with existing listeners, and expose no ordinary management routes.

Delegated use keeps its mutual-TLS business listener and certificate-to-machine mapping. Its optional `DELEGATED_USE_HEALTH_ADDR` accepts only a separate loopback address, selected as `127.0.0.1:8022` by the native profile. Both local GET probes, `/health` and `/ready`, call current runtime readiness and return only an empty, uncached 200 or 503. The port is not published, and it has no business route or identity fallback.

## Immutable observation locking

Canonical materialization needs PostgreSQL row locks on observation bindings, receipts, audit rows, and heads. A direct `FOR SHARE` requires UPDATE privilege even when the caller only reads. The additive `0019_observation_materialization_locks` migration installs three precisely scoped, fixed-search-path owner functions instead. It leaves all prior migration bytes unchanged.

The canonical runtime receives EXECUTE on these helpers and SELECT on the journal, with no journal UPDATE, DELETE, or TRUNCATE authority. Exact helper definitions, owners, security mode, search path, and absence of PUBLIC execution are checked before materialization. The original authorization, application revision, admission lock order, snapshot checks, and replay behavior remain in the canonical transaction.

The prerequisite transaction guard has the same PostgreSQL row-lock requirement on Credential Template rows. Additive Issuance migration `0020_verification_prerequisite_template_locks` moves only those exact lookups into a fixed-search-path owner helper; the transaction trigger remains SECURITY INVOKER, with its original intent, tenant, immutability and continuation checks. Credential Template migration `0006_verification_prerequisite_template_locks` pins the new invoker body and helper before permitting a guarded template. The canonical runtime keeps SELECT-only access to templates. Its real database regression covers ordinary and guarded writes, omitted intent and wrong tenant refusal, competing owner edits, direct template UPDATE denial, and helper execution revocation.

## Qualification and activation

The `managed_postgres_contract` acceptance target contains an explicit real PostgreSQL case for the exact profile SQL, TLS trust/name failures, owner migration order, bootstrap replay, all role readiness checks, actual denied operations, aggregate Issuance connection limits, and privilege drift. CI invokes this ignored case explicitly and requires one executed passing test; merely collecting it does not qualify the profile. The separate observation journal suite exercises real restricted-role materialization, replay, concurrent row locking, immutable write denial, and helper tampering.

The actual delegated-use executable test also exercises the loopback health listener and a real database privilege drift, while retaining the existing no-certificate, unmapped-certificate, and forwarded-identity rejections on the business listener.

Feature deployment still requires the exact selected release and profile to pass full CI, owner startup, and the applicable feature activation checks. Real organization, Flow, deployment, policy, and managed-key selections must be created and qualified through their owners. No fixture identifier is an activation receipt. Physical-passport external integration remains unselected until its provider and scoped runtime boundary are separately qualified.
