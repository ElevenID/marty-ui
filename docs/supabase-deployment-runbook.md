# Qualify a Supabase-backed self-host installation

Use a fresh installation and the designated ElevenID Supabase test project.
Keep the existing edge routes on their current origin during qualification.
The candidate needs its own installation directory, Compose project, listener,
volumes, Redis instance, OpenBao custody and workload TLS. Use synthetic
accounts and credentials. Record the source SHA, admitted release, image
digests and observations in the private deployment audit.

## 1. Capture the baseline and admit the candidate

- Record host OS and architecture, CPU and memory, free space on the host
  volume backing Docker, Docker and Compose versions, running projects and
  containers, state mount locations, and gateway, Redis and OpenBao health.
  Capture separate loopback and public gateway observations. Record Tunnel
  connector health and the dashboard's hostname-to-origin bindings.
- Find an admitted release that contains both external dependency selectors.
  Confirm that its Linux installer and Compose version are supported by the
  candidate host. On a Windows owner host, establish an isolated supported Linux
  runtime and account for its memory and virtual disk in the host budget.
  Use the release verification and candidate-test paths in the
  [Compose installer guide](compose-installer.md).
- Reserve an unused loopback listener and identify the actual canonical
  staging origin. Verify their separation from production and other active
  installations before allocating candidate state.

## 2. Provision and preflight PostgreSQL

1. Confirm the project reference in the dashboard. Copy the exact shared
   Session Pooler hostname, database name, and username format from **Connect**
   when IPv4 is needed. Use port 5432, the restricted application login, and
   the root certificate from **Database Settings**. Check the account's active
   plan and add-ons. Review the configured pool size and reserve capacity for
   Supabase Auth, Storage and administration. The
   [external PostgreSQL profile](installer-external-postgres.md) budgets 26
   primary connections plus two for concurrent setup and maintenance.
   [Supabase connection and certificate instructions](https://supabase.com/docs/guides/database/connecting-to-postgres#ssl)
2. In a protected owner-only directory, take a schema snapshot before applying
   any application changes. Use `pg_dump --schema-only` with the project
   administrator, the approved TLS endpoint and an interactive password prompt.
   Capture object ownership and grants. Once the candidate has application data,
   retain an encrypted, access-controlled data backup as well. Confirm the dump
   completed and record its digest and project reference in the private audit.
3. Use the password manager to generate a high-entropy password. From an
   interactive `psql` administrator session with `sslmode=verify-full` and
   `sslrootcert` set to the downloaded certificate path, confirm the session
   targets the intended project. Set `password_encryption` to `scram-sha-256`,
   run `\password elevenid_app` and enter the password at the hidden prompts.
   Enable the role with `ALTER ROLE elevenid_app LOGIN;` after provisioning.
   Select the application role for Marty runtime and migrations.
4. Use a secure editor or secret manager to write the same password as exact
   printable ASCII bytes with no trailing newline into a mode `0600` file in
   an owner-only mode `0700` Linux directory outside the checkout. Store the
   [private PostgreSQL selector](installer-external-postgres.md#supported-configuration)
   beside it with mode `0600` and use the password file's absolute path.
   Enter connection passwords at prompts or through the supported file transport.
5. Connect from the candidate host as the application role through the exact
   selected endpoint, using the downloaded CA and `sslmode=verify-full`.
   Record the role, database and a TLS observation. Confirm CONNECT and the
   schema privileges required by the native DDL, including database CREATE
   where the native migration issues `CREATE SCHEMA IF NOT EXISTS`. Check
   the 13 application namespaces and the role's effective privileges. Require
   no role creation, database creation, superuser or RLS-bypass authority,
   no privileged memberships, and no write privileges on managed `auth` or
   `storage` objects. Compare to the pre-migration object inventory.
6. Prove certificate and hostname verification from the actual migration and
   workload images. A successful host-side `psql` probe only covers the host
   client. The current installer profile has no explicit CA input. For a
   deployment that requires the project CA, hold migration until the admitted
   profile can supply it to every database consumer and preserve it across
   restart and recovery. Keep `verify-full` enabled.

## 3. Wire the authorization UI and qualify OIDC

Read the canonical ElevenID callback from the staging hosting configuration and
the Rifare callback from its deployed customer-auth provider configuration.
Register distinct clients with those exact HTTPS URIs, using authorization
code with S256 PKCE. Configure the client authentication method against the
issuer metadata, use the published asymmetric signing key, and store any
confidential-client secret outside the checkout. Keep Rifare's existing
machine-to-machine credentials and provisioning independent.

Build the [authorization UI](supabase-auth-ui.md) with the frozen Bun lockfile.
Use the Supabase project URL, publishable key, exact callback allowlists, client
IDs, and the approved staging Pages origin. Deploy the complete static output,
including `_headers` and `_redirects`, to a staging Pages project on Free. Verify
the exact consent route, CSP, no-store and no-referrer headers. Set the Supabase
Site URL and OAuth authorization path to that staging UI.

Run the [OIDC provider qualification](oidc-provider-qualification.md) for each
client. Verify first login and consent, denied consent, signed claims and exact
callback handling. Start with an aged provider session and previously granted
consent, request `prompt=consent login` and `max_age=0`, and observe whether the
browser forces new interactive authentication. Compare signed `auth_time` to the
actual authentication event. Verify signed MFA assurance and that logout prevents
silent reuse of the old provider session. Keep the current alternative provider
available if any required behavior fails.

## 4. Start the isolated Compose candidate

Use the signed installer, with the existing `--external-postgres-file`,
`--external-oidc-file` and `--hosting-file` selections, and the reviewed release
or exact admitted nightly. Review the resolved startup and retained maintenance
models in private before the migration jobs run.

- Confirm the PostgreSQL, Keycloak and Keycloak configurator services are absent
  from both application models. Review all 18 database templates, the password
  and CA inputs, the single-connection setup pools and the two-connection
  primary pool limits. Check that no dependency points to local PostgreSQL
  and that private services have no public listeners.
- Let the installer run the native revocation, shared and issuance migration
  jobs in dependency order. Use the packaged migration bootstrap
  `--verify-only` and the applicable native `verify-owned-schema` commands with
  the same admitted images, resolved database inputs and workload credentials.
  Retain job outcome and schema-verification evidence. Compare application
  object namespaces, ownership and grants to the preflight inventory and
  confirm the managed schemas are unchanged by these jobs.
- Use a separate Cloudflare staging hostname and the documented keyless
  origin TLS settings in the [Tunnel add-on guide](hosting-cloudflare-addon.md).
  Check the public gateway routes and the absence of public routes to Redis,
  OpenBao administration, PostgreSQL, internal gRPC and management endpoints.
- Keep [Resend application delivery](notification-email.md) disabled until
  sender verification, secret provisioning, rate limits and delivery tests
  are complete. Handle Supabase Auth email credentials separately.

## 5. Record acceptance and recovery evidence

| Check | Required observation |
| --- | --- |
| Startup and isolation | All expected application services healthy, setup jobs complete, and neighboring deployments undisturbed. |
| PostgreSQL | Restricted role and verified TLS in use. Native migrations and read-only verification succeed. Schema and grant inventory match expectations. |
| Internal security | Workload TLS and service authentication succeed. OpenBao issues and verifies the expected signature. Duplicate use fails Redis-backed replay checks. |
| Credential lifecycle | Issue, present, verify and revoke a synthetic credential. Verify the revoked result after restarting the candidate. |
| Persistence | The retained lifecycle stop/start resumes only the candidate. Confirm database and local state survive, with the original completed migration jobs and no local database fallback. |
| Public ingress | Staging tunnel healthy, exact gateway origin verified, only intended paths public, and existing production routing observed separately. |
| Human OIDC | Both clients complete the browser checks, including prior consent, freshness, MFA assurance and upstream logout. |
| Rifare | Complete the existing machine-to-machine integration journey, including its expected failure cases, using staging credentials and endpoints. |
| Capacity and cost | Compare baseline and candidate CPU, RAM and Docker storage. Record Supabase database size, peak connections, query latency, auth usage, email use and Tunnel health. Confirm Free plans, usage headroom, and absence of paid add-ons or new cloud resources. |

Record an observation time and evidence location for each row. A failed or
unobserved row holds cutover. Treat resource savings as a measurement from a
comparable workload window.

For recovery, retain an encrypted Supabase application dump and a coordinated
checkpoint of the installation's OpenBao, Redis and other persistent local
state, including the retained credential generation and release bindings.
Rehearse restoration to an isolated compatible database and isolated local
state before proposing cutover. The external database requires its own backup
and restore procedure. Confirm recovery can sign and verify with the expected
keys and preserve revocation, replay and audit state to the stated recovery
point.

Keep the previous origin and its data intact. Before a separately reviewed
traffic switch, record the current routing and the reversal procedure. Define
how to reconcile writes made after a switch before routing back to the previous
database. If staging fails, preserve its logs and state for diagnosis, and use
the installer's scoped stop for the candidate if needed.
