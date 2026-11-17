# Issuance schema boundary

The provider-neutral issuance baseline is `issuance_service_baseline_v2`.
Fresh databases contain platform application, evidence, credential, delivery and
protocol records. External provider tables and foreign keys to provider bindings
are absent. Delivery records use generic delivery target/mode and metadata.

The public Common Gateway is the sole external integration point. Connectors own
their provider data in their own repository and database; they must not read or
write the platform schema or use its private service interfaces. Canonical user,
application, ownership and approval authority remain with the platform.

## Existing databases

V1 migration ledgers do not satisfy the v2 protected schema contract. Startup and
the migration owner reject an old ledger. They do not relabel it as v2, drop
provider tables, migrate provider credentials or rewrite user data. Current local
qualification uses a disposable fresh database; it is not a production cutover.

TODO(platform/database owner): define and review an explicit legacy upgrade and
data-retention/export plan before deploying v2 against an existing database.
Leave that upgrade disabled until qualified. Production cutover and complete
connector adapters are separate work from repository boundary cleanup.

The migration role owns DDL. The application-role verification path stays
read-only; canonical ownership/association validation and tenant constraints
remain required. Provider-specific catalog and index checks are removed; generic
catalog, private-key-storage rejection, protocol and protected ownership checks
remain enabled.
