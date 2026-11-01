# ACME credential ownership

This slice supplies separate, durable account and CSR identities for the initial
ACME enrolment worker. It creates no CA account or order, exports no private key,
and activates no certificate. The existing private-CA renewal AppRole and its
policy inventory are unchanged.

## Authority boundaries

Names include both the installation UUID and the explicit `staging` or
`production` environment. Each environment has its own AppRole mount, two owner
roles, two owner policies, and two token roles. The existing nonexportable ingress
key is shared by the certificate identity; ACME account keys remain distinct
between environments and from that ingress key.

| Identity | Operations | Hard limits |
| --- | --- | --- |
| Account owner AppRole | Read its exact role, role ID, owner/operation policies, token role, and account key metadata; mint only the account operation token; inspect tokens; revoke its own login | No default policy; one owner policy; service token; 60-second TTL, maximum TTL, and explicit maximum TTL; no renewal permission |
| CSR owner AppRole | The same management actions, confined to its CSR role and retained ingress key | The same 60-second owner limits |
| Account operation token | Sign ACME JWS inputs with the original account key, version `"1"`, SHA-256, un-prehashed input, and JWS signature encoding | Only the account operation policy; no default or identity policy; orphan; nonrenewable; 300-second TTL and explicit maximum TTL |
| CSR operation token | Read the original ingress metadata and request only the exact DNS/IP public CSR template at version `"1"` | Only the CSR operation policy; the same 300-second operation limits |

The owner policies cannot sign, request a CSR, create an arbitrary token, renew a
token, rotate a SecretID, modify a policy or role, enable or tune an auth mount,
rotate/export a key, or use the other purpose/environment's token role. Operation
tokens have no management permission. Revoking the short owner login does not
revoke the orphan operation token.

OpenBao 2.5.5 token roles expose `token_explicit_max_ttl`, but do not expose
`token_ttl` or `token_max_ttl`. The implementation therefore combines the role's
300-second explicit maximum with an exact mint request enforced by the owner ACL:
`ttl="5m"`, `explicit_max_ttl="5m"`, `renewable=false`,
`no_default_policy=true`, and the one assigned policy. Every field is required;
extra parameters are denied. Returned token metadata is checked independently.
AppRole owner service tokens are internally marked renewable by OpenBao; their
policy has no renewal permission, and their explicit maximum is still 60 seconds.
These distinctions follow the [2.5.5 token implementation](https://github.com/openbao/openbao/blob/v2.5.5/vault/token_store.go)
and [AppRole implementation](https://github.com/openbao/openbao/blob/v2.5.5/builtin/credential/approle/path_role.go).

## Fixed bootstrap helper boundary

The rootless installer must not read or chown the OpenBao state directory to gain
access to `root.token`. The credential API has separate host and container sides:

1. `prepare_for_install` validates the held installation, explicit ACME
   configuration, recorded custody, and retained public keys. It observes the
   verified OpenBao cluster and writes the immutable environment setup intent
   before any remote mutation. It needs no bootstrap root authority.
2. `CredentialResourcePlan::public_bytes` and `sha256` produce the public helper
   input and its independently retained digest. The fixed container helper
   admits it through `parse_authenticated(bytes, expected_digest)`. The digest
   must come from the authenticated host intent, not from the input file itself.
3. `provision_resources` runs within that fixed helper using the existing initial
   root authority. It needs no host installation path or flock. It validates both
   live public keys and the already installed operation policies, refuses any
   existing owned mount/policy/token role, creates the two exact owner profiles,
   and creates one SecretID per purpose. It returns no bootstrap root authority.
4. `ProvisionedCredentialIdentities::write_private_transfer` writes only
   `account-identity.json`, `csr-identity.json`, and public `plan.json` to an empty
   0700 transfer folder, with 0600 files. The existing fixed-helper orchestration
   must authenticate the job/image and transfer these to installer-owned private
   storage.
5. `admit_for_install` checks the transferred plan and identities, creates the
   private identity directories, validates both scoped logins without root, and
   writes immutable completion. It does not advance installer phase.

The direct `provision_for_install` wrapper composes the same stages for a caller
that already possesses initial authority, including the isolated OpenBao proof.
It is not the rootless host's bootstrap integration. The preceding account-key
custody setup exposes the same host/helper split and returns only public key and
policy observations. The fixed Compose orchestration must connect both jobs and
their authenticated output transfers before a fresh rootless installation can
use this entire path.

An incomplete initial setup is never replayed. Auth mount, policy, token-role,
AppRole, and SecretID creation are retained for explicit setup recovery. Existing
resources are not adopted or repaired. Completed restoration is read-only and
uses no root authority.

## Runtime use and refresh recovery

`restore` validates the exact saved configuration and custody receipts, OpenBao
origin, and private filesystem bindings, then returns `CredentialProviders`.
`account()` supplies the enrolment worker's `Arc<dyn WorkloadCredentials>`.
`account_credentials().verified_key()` reconstructs `AccountKeyBinding` from
retained SPKI and scoped authenticated live metadata. `csr().retained_key()` does
the equivalent for ingress custody.

The caller must first ask the enrolment ledger for `retained_csr`. Only when no
CSR is retained should it call `csr().signed_csr()`. That operation reads key
metadata before and after OpenBao signs the exact template, verifies the CSR
signature/SPKI/SANs, and returns `ValidatedCsr`. The worker must retain those exact
bytes before creating an order and reuse them for every known-order resume.

Every authentication checks the owner/operation ACL text, owner role, fixed token
role, role ID, live key custody, returned login token, and returned
operation token. No login path creates or repairs configuration. Owner tokens and
operation tokens are used in memory and never enter diagnostic receipts or logs.
Backend response bodies and credential-bearing transport errors are replaced by
fixed refusal messages.

Bootstrap root also verifies the dedicated auth mount's 60-second default and
maximum TTL once. Runtime owners have no mount-tuning authority, including its
privileged read endpoint. Their own role and actual returned token independently
carry the same 60-second explicit maximum, so increasing a mount ceiling cannot
increase their permitted lifetime.

The credential refresh has a six-second total deadline inside the account
signer's ten-second budget, leaving up to four seconds for its Transit signature.
CSR signing uses the same bounded refresh plus a separate four-second request
budget. There is at most one login and one requested operation token per call;
the provider does not run a scheduler or retry in a loop.

Each purpose's private directory has a nonblocking lock, one durable current
intent/result, and the last 32 immutable uncertainty observations. Successful
refreshes replace the current checkpoint instead of accumulating lifetime files.
The lock serializes credential I/O without acquiring a second installation lock.
Current-state replacement verifies the old bytes, publishes the complete new file
atomically, and fsyncs it and its parent before any authentication side effect.
An interrupted preparation cannot leave a partly written current record. Read-only
restore leaves unpublished preparations untouched; an active refresh removes
those private incomplete writes under its lock. Older validated uncertainty
observations are pruned only after the current checkpoint is durable.

If a call is interrupted after its intent, the next caller records
`unknown-bounded-authentication`. It does not claim the lost token is known,
revoked, or already expired. Such a call may have created an additional narrowly
scoped token; overlapping short-lived authentication tokens are expected and do
not constitute a new key, account, or order. A later attempt can proceed after
persisted exponential backoff of 5 to 300 seconds, plus the previous six-second
request allowance. This is an authentication retry, not a replay of provisioning.

Backoff uses the verified OpenBao HTTPS response's `Date`, cross-checked with
`sys/health` server time and the retained cluster UUID. Host wall-clock changes
cannot clear it. A server-time rollback, changed cluster, changed identity inode,
unsafe permissions, symlink, malformed receipt, or broken sequence is refused.
This does not claim an exact census of all expired or active tokens; bootstrap
root retirement and installed-generation retirement need their own evidence.

There is no configured lifetime limit on authentication attempts. A regression
test crosses the former 2,048-attempt boundary, then retains only the latest 32
uncertainty observations across repeated failures and a successful recovery.
SecretID rotation, account migration,
certificate activation, automatic certificate renewal, and deployed reboot/load
qualification remain outside this module.

## Focused verification

The ordinary tests exercise exact public-plan admission, environment and purpose
separation, role/token constraint failures, private inode/permission custody,
concurrent refresh refusal, an interrupted refresh followed by server-time
backoff and successful recovery, read-only restoration, and setup non-replay.

The opt-in test
`official_openbao_proves_separate_owner_leaf_credentials_readonly_restore_and_denied_escalation`
uses the verified official OpenBao 2.5.5 binary over local TLS. It exercises actual
AppRole setup, scoped login, orphan token minting and lookup, JWS signing, exact
DNS/IP CSR signing, immutable restoration, rejected authority crossings, denied
renewal/rotation/export/repair, exact mint parameter enforcement, and drift
refusal. It contacts no live CA and exports no operational private key.
