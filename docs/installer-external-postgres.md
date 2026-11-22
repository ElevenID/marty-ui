# External PostgreSQL with self-hosted ElevenID

The fresh Linux installer accepts `--external-postgres-file ABSOLUTE_PATH` to
use a database that you have already provisioned. Pair it with
[`--external-oidc-file`](installer-external-oidc.md). The application services,
Redis, OpenBao, signing keys and workload TLS remain on your host; PostgreSQL
and Keycloak do not run locally in this selection.

This is an opt-in deployment integration, not a qualification of a particular
Supabase project. It does not create a provider account, change a plan, provision
roles or databases, migrate an existing installation, or establish a backup
contract. Use a release containing this option and complete the checks below
before relying on the installation. Existing release authentication, readiness
holds and provider-qualification requirements still apply.

## Supported configuration

Use a private, owned regular JSON file with mode `0600`. Its referenced password
file must also be an owned regular file with mode `0600`, outside the checkout.
Both paths must be absolute. For example:

```json
{
  "schema": "elevenid.installer-external-postgres/v1",
  "external_postgres": {
    "host": "aws-0-REGION.pooler.supabase.com",
    "port": 5432,
    "username": "elevenid.PROJECT_REF",
    "database": "postgres",
    "password_file": "/home/operator/elevenid-input/postgres-password"
  }
}
```

Replace the endpoint, role, project reference and database with the actual
connection details. The role in the example must exist and have the permissions
required by the migrations. A Supabase project API key, publishable key or
service-role JWT is not a PostgreSQL password. Keep the password as exact text
with no final newline. The installer rejects empty, non-ASCII, control-character
and multiline password files. Other punctuation is URL-encoded by the existing
runtime secret loader; do not pre-encode the password.

The endpoint is assembled from validated fields. There is no arbitrary URL,
connection-options or insecure-TLS override: every selected connection uses
`sslmode=verify-full`. The server certificate must validate against the
application image's trusted roots and match the endpoint hostname. This first
profile does not import a custom database CA; use a publicly trusted endpoint.
Username and database name are percent-encoded separately.

Example argument selection, with a reviewed release that contains this change:

```sh
sh install.sh --version "$RELEASE_TAG" \
  --external-oidc-file /home/operator/elevenid-input/oidc.json \
  --external-postgres-file /home/operator/elevenid-input/postgres.json \
  --hosting-file /home/operator/elevenid-input/hosting.json
```

The option is also forwarded by the existing exact-nightly `--candidate-test`
path. It cannot be combined with a managed Keycloak install, `--foundation-file`,
host checks or compatibility-only checks. Windows ownership and in-place
database switching are outside this profile.

## Supabase setup and connection budget

For an IPv4-only host, select the shared **session pooler on port 5432** from
the project's Connect panel. Supabase's direct endpoint is normally IPv6; the
dedicated IPv4 add-on is a separate paid option. The transaction pooler on port
6543 changes connection/session semantics and is not the qualified target of
this profile. See [connecting to Postgres](https://supabase.com/docs/guides/database/connecting-to-postgres).

The default free-project session pool is too small for the full application
pool budget. Supabase's current Nano table lists 60 maximum database connections,
200 pooler clients and a default pool size of 15. These are different limits:
200 client connections does not give a session-pooled role 200 active database
connections. See [compute and connection limits](https://supabase.com/docs/guides/platform/compute-and-disk)
and [session pool exhaustion](https://supabase.com/docs/guides/database/prisma/prisma-troubleshooting).

This profile sets the following limits, without changing local-install defaults:

| Pool owner | Maximum connections |
| --- | ---: |
| Each of 13 primary runtime pools | 2 |
| Primary runtime total | 26 |
| Each selected one-shot migration/bootstrap pool | 1 |
| Conservative primary runtime plus maintenance allowance | 28 |
| Suggested dedicated application session-pool size | 30 |

The runtime owners are Auth, organization, credential-template, trust-profile,
issuance, issuance-native, notification, compliance-profile,
presentation-policy, deployment-profile, flow, revocation-profile and
device-registration. Applicant is file-backed in the native service and does
not add a database pool. The four setup roles are revocation-profile-migrate,
db-migrate, kms-initialize and issuance-migrations; they are not four permanent
servers. Their existing ordering and profiles are retained.

Before installation, review Database Settings and configure enough session-pool
capacity for the selected application role/database, with room for Auth,
Storage, administration and provider maintenance. A size of 30 is a planning
target, not an observed capacity result. Supabase warns that pool allocations
multiply by role/database combinations, and recommends reserving capacity for
other services. Do not assume multiple replicas, multiple installs or optional
external-observation/association pools fit the same budget. See
[connection management](https://supabase.com/docs/guides/database/connection-management).

The migration/bootstrap credential needs to create the application's schemas,
tables and indexes in the chosen database. Provision that scope deliberately;
the installer neither creates a remote database nor needs a Supabase management
API token. A dedicated application role is preferable to a project-wide
administrative role. Runtime and migrations currently share that application's
credential; separating migration and runtime roles is a further deployment
change.

Keep all ElevenID internal tables and schemas outside the Supabase Data API.
Do not add service schemas to the exposed schema list. Review the shared
bootstrap tables too. For a project used only for managed Auth and direct SQL,
disable the Data API if it is unnecessary; otherwise configure grants and RLS
before importing application data. Moving SQL to Supabase does not convert
ElevenID's authorization model into Supabase RLS. See
[securing the Data API](https://supabase.com/docs/guides/api/securing-your-api).

## What the installer retains

The installer records the nonsecret selection and a fingerprint of the password,
binds the record's hash into the installation journal, and imports the password
only during provisioning. It rejects a changed secret between preparation and
import. The imported file is `external_postgres_password`; the existing
container secret target remains `/run/secrets/marty_db_password`.

The selected Compose layer runs after the external-OIDC and runtime layers.
It removes the PostgreSQL service and every local PostgreSQL health dependency,
replaces all 18 inherited database URL templates, and caps the active pools.
The immutable credential generation, retained maintenance model and log
redaction retain the imported credential. The source file can be removed from
the operator's input directory after a successful import; the installation's
retained credentials remain necessary for restart and recovery.

Local generated PostgreSQL credentials and an empty state directory may remain
as unused installer bookkeeping. They do not create a database process, and
the runtime selection cannot fall back to them. Existing cleanup semantics
continue to retain state. Removing local PostgreSQL from a new installation is
not permission to delete data from an existing one.

Doctor and lifecycle reports include an `external_database` section for this
selection. It verifies the retained configuration but reports provider health,
backup and restore observations separately as unobserved. Those commands do not
contact the database or read the operator's original password input. A healthy
local service inventory is not evidence of a remote database backup or recovery.

The local writable-state inventory and recovery rehearsal explicitly refuse
external database selections, including a mixed model that retains an unused
local PostgreSQL mount. Arrange a provider-aware database backup and a coordinated
restore with local OpenBao/Redis state before relying on recovery. The refusal
occurs before the rehearsal creates its work directory or starts containers.

## Source validation

The 2026-11-21 implementation was checked with Rust 1.95.0, locked workspace
dependencies and Docker Compose 5.6.1. The completed targeted checks were:

| Check | Result |
| --- | --- |
| Installer, database URL, Compose ownership, bundle closure, optional-secret, runtime-plan and recovery Python tests | 667 passed, 6 skipped |
| Deployment-catalog PostgreSQL selection, application settings, command, environment, ACME preparation, credential-alias, Doctor and lifecycle Rust tests | 75 passed |
| Native packaged-source and filtering/merge/restart Compose integration tests | 2 passed |
| Notification email adapter and bounded database-pool Rust tests | 10 passed |
| Issuance primary database-pool configuration Rust test | 1 passed |
| Actual migration, role-permission and TLS qualification on owned PostgreSQL 17.12 | 1 passed |
| Static Supabase sign-in/consent protocol, controller and real-SDK transport tests | 78 passed; synthetic static build and output/header checks passed |

The native Compose checks exercise the real Compose executable against the
packaged installer layers, including external OIDC plus external PostgreSQL,
startup and retained maintenance models, password interpolation, secret aliases
and dependency closure. They render configuration without starting containers.
Their baseline assertions name every expected core service; the optional tunnel
add-on is checked separately.

The notification and issuance checks run inside their actual workspace crates.
Email tests use local mock HTTP servers and synthetic credentials. The Python
skips include fixture-dependent checks and the explicitly opt-in Docker recovery
smoke test. Rust checks cover the selected components rather than the complete
workspace suite.

The PostgreSQL test invokes the actual migration APIs for all 12 native service
schemas plus the MMF outbox. Its application role has database `CONNECT` and
`CREATE`, but no database ownership, superuser, role-creation, database-creation,
inheritance, replication or RLS-bypass privilege. `public` schema creation is
revoked. Protected synthetic `auth` and `storage` rows, ownership and ACLs remain
unchanged. Repeating migrations preserves the application object inventory, and
the existing schema validators pass. No extension beyond built-in `plpgsql` is
required. The exercised paths share a two-connection pool.

It also sends a password containing reserved URL punctuation through the real
secret loader and SQLx/SCRAM authentication. Typed negative controls establish
that `verify-full` rejects an untrusted certificate and a wrong hostname. A
private test CA is confined to this disposable fixture; the production selector
continues to require a publicly trusted endpoint.

To reproduce that test, run as an unprivileged user from `rust/`, with an absolute
directory containing local `initdb`, `postgres` and `pg_ctl` executables:

```sh
MARTY_TEST_POSTGRES_BIN_DIR=/usr/lib/postgresql/17/bin \
  cargo test --locked -p marty-selfhost-acceptance \
  --test managed_postgres_contract -- --ignored --exact \
  restricted_role_migrates_without_touching_provider_schemas --test-threads=1
```

The fixture creates and stops its own loopback-only database and accepts no
remote database URL. This establishes local SQL, permission and TLS behavior.
The selected Supabase project's restrictions, Supavisor session transport,
certificate chain, concurrent runtime capacity, browser authentication and
coordinated recovery still require the following deployment qualification.

## Deployment qualification

Follow the [Supabase deployment runbook](supabase-deployment-runbook.md) for
credential provisioning, staging isolation, acceptance and recovery.

Use a disposable provider database and the exact intended release to verify:

1. The session endpoint accepts the selected role and validates its certificate
   from the workload image. A wrong hostname, invalid certificate or password
   must fail; do not reduce TLS verification to make the test pass.
2. Native revocation, shared bootstrap and issuance migrations complete against
   the restricted role. Observe the database after a restart and after an
   interrupted migration; do not infer migration success from a Compose render.
3. Login, organization membership, issuance, revocation and notification
   persistence work with the same database. Measure peak connections and pool
   wait time under concurrent requests and maintenance.
4. Retained restart/maintenance models contain no local PostgreSQL or Keycloak
   server and still use the selected secret generation. Imported-password
   mutation must be refused. An external-database outage must not trigger a
   silent local fallback.
5. Exercise a restore with both remote database data and local OpenBao/Redis
   state. The local backup/restore procedures do not automatically include the
   remote database. External PostgreSQL credential rotation is not implemented
   by this fresh-install selector; do not edit immutable evidence to rotate it.

Supabase OIDC remains a separate qualification. Enable its OAuth server,
configure its login/consent UI and client, and test the actual browser flow,
verified-email claims, logout and requested fresh authentication using the
[OIDC provider checklist](oidc-provider-qualification.md). A PostgreSQL
connection does not qualify a login provider. Supabase Auth email is configured
in Supabase; ElevenID application email uses the separately opt-in
[notification adapter](notification-email.md).

The [static Supabase sign-in/consent companion](supabase-auth-ui.md) supplies an
existing-account browser path without another application server. Review the
[Supabase freshness and MFA source findings](oidc-provider-qualification.md#supabase-freshness-and-mfa-source-review)
before choosing the login provider: a successful callback does not prove that
Supabase enforced Marty's request for fresh authentication or a second factor.

Cloudflare DNS/Tunnel and static delivery can be selected independently. Use
the existing [Cloudflare hosting integration](hosting-cloudflare-addon.md) for
the public origin. Pages does not replace workload key custody, Redis or a
database, and moving application UI assets to Pages needs its own frontend
configuration check.

## Cost and operational boundaries

As of 2026-11-21, the Supabase Free plan lists a 500 MB database, up to 0.5 GB
shared compute memory, and inactivity pausing. Moving the database to that plan
reduces host processes; it does not prove that the full ElevenID workload fits
the provider's memory, I/O or connection budget. Review actual project usage,
egress, backups and plan selection before deployment. Provider quotas and
optional add-ons can change; see [Supabase pricing](https://supabase.com/pricing).

The self-hosted machine, persistent disks, domain renewal and any email-provider
overages remain separate costs. No cloud plan, resource, email or deployment is
created by selecting or rendering this profile.
