# Retiring the original OpenBao bootstrap root

Root retirement is a separate installation completion transaction. Local control
enrollment, a successful application startup, or an isolated official-binary
proof does not authorize it. The host must first bind the selected and rollback
generations, fresh independent scoped credentials, current application validation
and installed restart/restore evidence to its immutable retirement intent.

## Operator gate

```text
/absolute/installation/marty-deploy root-retirement status --install-dir /absolute/installation
/absolute/installation/marty-deploy root-retirement retire --install-dir /absolute/installation --evidence /absolute/private/references.json
```

Both actions accept an optional `--docker-bin ABS` for the retained local Docker
boundary. Status performs read-only inspection. Retire requires an existing
durable running lifecycle intent; a paused or security-sealed installation does
not qualify. Neither action starts services or manufactures qualification.

The optional evidence input is an owner-controlled regular single-link `0400`
or `0600` JSON file beneath a private `0700` directory. It contains only these
optional artifact references, each with `name` and `sha256`:

```json
{
  "application": null,
  "scoped_authorities": null,
  "restart": null,
  "restore": null
}
```

Unknown fields, duplicate JSON members, symlinks, hardlinks, unsafe permissions
and changed files are rejected. Supplying a reference does not qualify its
artifact: the gate independently reads the retained record under the installation
lock, verifies its digest, strict installed-proof schema, exact scope and complete
required checks. The reference file cannot supply checks or readiness claims.

The generation owner must first expose a completed current/rollback pair. The
gate binds both generation digests and native helper receipts, the selected
Compose session/configuration, completed activation/selection receipts, public
renewal enrollment and retained scoped-identity digests. It also binds the release,
exact owned OpenBao container/census, enrolled cluster, issuer, CA and node key.
No private initial-root or recovery-share digest enters this context.

The four installed proof categories have distinct requirements:

| Category | Required installed observation |
| --- | --- |
| Application | Canonical HTTPS, selected generation active, authenticated credential journey |
| Scoped authorities | Independent current and rollback workload logins/signatures, public renewal, ACME account, ingress CSR and local TLS recovery authority; exact scope and verification-token retirement |
| Restart | Same retained cluster and static key after restart; scoped authority and application recovery while the initial root is unavailable; no initialization or unseal replay |
| Restore | Original static key, cluster, issuer/transit keys, scoped identities and both generations restored through the normal snapshot endpoint with the source offline; protected external files, installed image and customer backup transport qualified |

These records use `elevenid.installed-root-retirement-proof/v1` and must finish
within 15 minutes before a new retirement intent. They explicitly identify
`installed_deployment`, bind the complete context and require no use of the
installation's initial root. A disposable destination's distinct bootstrap for
the documented restore API is a separate restore-owner responsibility; it is not
authority to reuse the installation's initial root or initialize retained state.

There is currently no production installed restart/restore qualification writer.
The existing read-only deployment report also skips the credential journey.
Those gaps remain explicit blockers. The official binary proofs documented below
do not fill them. No command in this slice fabricates a positive installed proof.

After qualification, the host persists `openbao-root-retirement-intent.json`
before invoking the helper. Lost responses resume that exact UUID and intent
digest. Proof freshness is checked at initial authorization; a retry after long
downtime revalidates the immutable original proof records and bindings instead
of authorizing a different operation. A changed selection blocks an unfinished
retirement. After a completed retirement, legitimate later generation selection
does not undo that historical operation or create another root-retirement attempt.
The separate `openbao-root-retirement-complete.json` is written only after the
exact helper result, unchanged ownership and retained intent are verified.

Generation activation and root retirement exclude one another while either
transaction is unfinished. Lifecycle maintenance first restores local OpenBao
TLS, then resumes an existing authorized root-retirement intent, then advances
application generations. This keeps a lost revoke response recoverable across
reboot without allowing another generation to invalidate the pending intent.
The lifecycle resume entry point cannot create a new retirement attempt or mint
qualification; absent or already completed retirement work is a no-op.

The fixed in-container command is:

```text
/usr/local/bin/selfhost-root-retire --installation-id <UUID> --attempt-id <UUID> --intent-sha256 <64 lowercase hex digits>
```

The host invokes that command as `0:0` in the exact owned OpenBao container, with
working directory `/`, after validating the complete retained Compose resource
receipt. The command has no arbitrary path, URL, operation, token, or signal
argument. Its 90-second deadline and the host's bounded Docker operation do not
imply that cancellation of the Docker client terminated the in-container helper.
A retained nonblocking filesystem lock serializes surviving helper processes.

## Original authority and private journal

Fresh static initialization writes `/bao/data/static-init-authority.json` as
root-owned `0400` before publishing its initialization result. The private record
binds the installation, initialization attempt, cluster and exact original
`root.token` and `recovery.key` files, including inode, ownership, mode, size,
timestamps and private content digests. It is never sent to the host, printed,
or included in support output. The host does not receive its digest either.

Retirement requires that private binding, the unchanged recovery share and the
completed local-control identity/enrollment for the same cluster. It refuses a
leftover initialization response, a legacy unseal key, replaced files, unsafe
ownership, malformed records or a different attempt. It never calls `sys/init`,
`sys/unseal`, token generation, policy creation or key creation.

The root-owned private `.root-retirement-transaction.json` records three durable
phases under `.root-retirement.lock`:

1. `prepared` binds the public host intent digest to the original private
   authority and exact attempt before any root-authenticated request.
2. `revocation_observed` records a confirmed `403` from lookup of that original
   root on the initialized, unsealed Unix listener for the enrolled cluster.
3. `completed` records removal of the original root file and the synced parent
   directory, with the recovery share and original-authority record preserved.

The only root-authenticated operations are `GET auth/token/lookup-self` and
`POST auth/token/revoke-self`. An active root must have the original token ID,
root-only policy, root creation path, service type and orphan state. If a revoke
response is lost, the same attempt looks up that same retained root again. A
`403` confirms success; an active original root permits a bounded revoke retry.
An unavailable listener or ambiguous response leaves the same attempt resumable.
The root file is never removed before durable confirmation. After completion,
the same attempt returns its retained public result without another root request.

## Public result and release boundary

The command prints one JSON object with schema
`elevenid.openbao-initial-root-retirement-result/v1`. Its fields are
`installation_id`, `attempt_id`, `intent_sha256`, `cluster_id`,
`root_rejection_observed`, `root_token_removed`, `recovery_key_preserved`,
`original_authority_verified`, `authority_record_preserved`,
`initialization_replayed` and `installation_ready`. The first five boolean proof
fields are true; the last two are false. No token, accessor, recovery share or
private digest appears in the result. Completion of this local operation alone
does not claim full application or customer reboot qualification.

The private static seal key is untouched. The recovery share and protected
backups must remain available. Restoring a pre-retirement Raft snapshot can
restore earlier token state, so a separate production restore owner must bind
the backup's revocation history and external authority files. The helper's
completed receipt records the revocation it observed; it is not permission to
adopt an arbitrary restored store.

Focused tests inject interruptions at every journal/publication boundary, lost
revoke results, transient lookup/revoke errors, replaced original files, malformed
authority records and competing helper locks. The opt-in official 2.5.5 restore
proof exercises this actual core before snapshot acquisition and verifies that
retirement survives restoration with the exact seal key. See
[the static-seal proof](installer-openbao-static-seal.md) for its remaining
container, customer backup and installed restore boundaries.
