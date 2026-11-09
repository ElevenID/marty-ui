# Retained Kubernetes development credential recovery

## Problem and scope

The legacy Kubernetes bootstrap at runtime source
`3ff1328d163f2dca38e369f17bda77b6334808eb` retained the original OpenBao
initialization, namespace/cluster binding, producer nonce, workload project,
credential files and TLS key metadata. It did not enroll the later application
authority or the existing self-host TLS renewal AppRole. The development TLS
certificates and service tokens expire after eight hours. Once that happens,
normal renewal enrollment correctly refuses the invalid original generation.

This is a distinct operator recovery profile for that original bootstrap. It
does not change `renewal-inventory`, ordinary renewal enrollment, bootstrap, or
their validity requirements. It does not initialize or adopt an installation,
enroll a replacement identity, create policies/roles/keys/CAs, rotate keys, change
organization or issuer identity, or extend the development credential lifetime.

**The first increment is inspection only.** It must establish the retained
identity and evidence contract before any credential-issuing or Secret-updating
entry point is enabled. An inspection result is not permission to bypass the
existing producers or to issue credentials with arbitrary OpenBao commands.

## Ownership

The native deployment operator owns credential inventories, policy bodies,
certificate/issuer/key validation, request scope and recovery receipts. The
existing self-host identity crate owns the public TLS role definitions. The
existing OpenBao HTTPS client and native certificate verification remain the
protocol and cryptographic implementations.

A Python adapter owns only private-file transport, authentication of the
original and selected signed artifact closures, Kubernetes observations,
bounded producer-pod lifetime, evidence export, and eventual guarded activation.
It must not render a new credential protocol, decide policy permissions or
invent historical enrollment evidence.

The original runtime source and the selected recovery-operator source are
different identities. Both must be authenticated independently. A future signed
recovery operator can inspect the original installed generation without
upgrading any running application image.

## Inspection inputs

All private inputs remain in operator-owned encrypted storage. Read them as
bounded, single-link regular files beneath canonical private directories; reject
symlinks, ownership/mode drift, duplicate JSON members and concurrent changes.

| Input | Purpose |
|---|---|
| Original signed installer closure | Authenticates the original runtime, operator, image inventory and initializer |
| Selected signed recovery closure | Authenticates the exact recovery operator and producer image |
| `bootstrap-complete.json` | Original successful legacy bootstrap and runtime/namespace/cluster identity |
| `initialize-requested.json` | Independent original namespace UID, producer nonce and workload project |
| `tls-key-metadata.json` | Exact sixteen original TLS role/key/version mappings |
| Original credential generation | Retained public certificates, trust anchors, scoped inputs and unchanged static data |
| Original root authority | Read from retained initialization under private custody; never emit it or recovery keys |
| Fresh namespace observation | Independently obtained name and UID, compared before private upload and at phase boundaries |

The adapter must upload only the required root token to a bounded, memory-backed
producer pod. Recovery shares/keys and the Kubernetes administrator kubeconfig
must not be uploaded. The complete original initialization file remains private
on operator storage. No credential values or token hashes belong in public
summaries or GitHub evidence.

## Required read-only proofs

1. Require the known legacy runtime source and a successful original bootstrap.
   Reject receipts containing later application authority instead of silently
   selecting privileged recovery over an available routine path.
2. Match bootstrap ID, namespace name/UID, producer nonce and workload project
   across the original records. Independently observe the actual namespace UID.
3. Before uploading root authority, the adapter calls the native unauthenticated
   `operator kubernetes-legacy-recovery-target CA CLUSTER_ID` probe from its
   observed producer pod. Both native commands fix the existing service address
   to `https://openbao:8200`; inspection takes its CA directly from the retained
   generation. Read OpenBao health through that CA and require the original
   cluster ID, initialized/unsealed state, active role and original OpenBao
   server version `2.5.5`. Bind the submitted
   root token to the trusted retained initialization input. Lookup-self checks
   root authority shape only: later `generate-root` tokens have the same root
   policy, path, parent and TTL metadata, so those fields do not prove original
   token lineage.
4. Check the expected existing mount types. Observe whether renewal/application
   authority already exists; refuse to recreate or substitute for it.
5. Require all sixteen original version-one P-256 TLS keys to remain
   non-exportable and non-backup-exportable. Check the two Keycloak RSA signers,
   existing HMAC signers and JWE key versions through their native owner. These
   observations bind the current symmetric key/version selected for recovery;
   they do not establish historical symmetric key-material continuity.
6. Compare the retained workload CA bytes with the current workload issuer.
   Verify each retained leaf's signature and issuer relationship, validate the
   observed issuer's current constraints and lifetime, and match the leaf's
   public key with the current version-one signer. This does not invent an
   earlier observed enrollment time, require an unrecorded historical issuer
   certificate, or treat an expired leaf as currently valid for TLS.
7. The legacy generation did not retain a separate Keycloak CA certificate.
   Consequently, the recovery record must state its actual evidence basis:
   the current issuer verifies both retained Keycloak leaf signatures, and each
   leaf SPKI matches its retained version-one remote signer. Record the current
   issuer fingerprint as an observation, not as a fabricated original CA
   receipt. The bounded recovery preserves this observed issuer and its
   demonstrated relationship to the retained leaves. Historical CA certificate
   byte identity is a claim limitation, not an additional forensic admission
   requirement.
8. Read exact existing TLS policy bodies derived from the original workload
   project/key names, Keycloak policy bodies derived by its native owner and
   original nonce, and ordinary policy bodies from the original signed
   initializer. No caller-supplied ACL is accepted.
9. Validate the existing PKI roles against the original configured fields and
   capture the full returned role documents. The original bootstrap did not
   retain the complete OpenBao-default-expanded role documents. Therefore the
   snapshot is an observation of the current role, not proof that every optional
   field was unchanged since bootstrap. Later staging must preserve that full
   observed document, satisfy the original producer's closed security fields,
   and retain the original leaf identity and usage. It never writes a role.
10. Preserve a private input/snapshot binding and reread the namespace/cluster
    identity before returning a nonsecret inspection summary. The summary must
    explicitly say that credentials and Secrets were not changed.

## Bounded later staging increment

Only after the inspection contract has independent review and tests, a distinct
native recovery staging operation may use the retained root authority. It must
repeat all live proofs immediately before the first credential-producing
request, against the bound private inspection snapshot.

The closed replacement inventory is sixteen TLS tokens/certificates, two
Keycloak signing certificates and five Keycloak tokens, and twelve ordinary
runtime tokens. The initial two-hour migration token is excluded. The legacy
`OPENBAO_SERVICE_TOKEN` alias remains a separate runtime input in this recovery
profile; this does not widen the later routine application authority.

Allowed mutations are existing-key version-one CSR creation, certificate signing
through the original PKI roles, and token creation with the exact existing policy
bundles. Replacement tokens must be distinct, orphan, nonrenewable, omit the
default policy and have an explicit maximum lifetime no greater than eight
hours. Certificates retain the original identity/usage, issuer and SPKI, and
their lifetime remains bounded by the development profile.

The operation must not call mount/auth initialization, key creation/rotation,
policy writes, role writes, CA creation or new enrollment. A closed request-trace
test must enforce that boundary. Native postconditions verify actual scopes,
lifetimes, signer version, signatures, certificate chains, unchanged CAs and
foreign-key denial before a complete candidate is acknowledged.

Each potentially mutating request requires a durable private attempt record
before it is sent. Preserve the opaque response before interpreting it. A lost
response, timeout, failed export or interrupted process is uncertain; do not
automatically replay issuance or delete its only evidence. Candidate staging
must not update the original generation or any Kubernetes Secret.

## Separate guarded activation

Activation is a later explicit phase over an already qualified private candidate,
not a side effect of inspection or staging. Its native plan must enumerate the
closed existing Secret names and fields. For each Secret, an atomic JSON Patch
must test its UID, resource version and expected old data before replacing only
the intended fields. Preserve unrelated data, labels and annotations.

Activation must hold the operator lock, recheck cluster/namespace identity and a
separately verified bounded runtime window, retain private preimages and each
successful response, then perform only the required workload restarts and
bounded readiness checks. It must not run migrations or Keycloak configuration,
reset passwords, change images, alter issuer/DID/origin settings, or create a
missing Secret as a substitute for retained state.

Partial activation is explicitly recorded. Expired old credentials are not a
useful automatic rollback target. Do not hide a partial update behind a generic
success receipt or remint credentials during activation retries. Any continuation
must reconcile the retained attempt and current resource versions first.

## Meaningful qualification

- Positive legacy fixture: expired original leaves are accepted only by the
  distinct recovery inspection after their signatures, issuer and signer
  identities are proven; ordinary renewal/enrollment still rejects them.
- Before-mutation refusal matrix: wrong source/binding/retained root input, changed CA,
  changed key/SPKI/version/exportability, changed policy/PKI role, existing later
  enrollment, missing/duplicate inputs, symlink/hardlink or concurrent input drift.
- Recorded request trace: inspection makes only bounded reads; staging cannot
  invoke forbidden creation, rotation, ACL or role mutation endpoints.
- Cryptographic cases: wrong issuer, substituted leaf/key, altered subject/SAN/EKU,
  invalid chain, future original leaf, and expired or insufficient-lived issuer.
- Issuance fault cases: response loss after certificate/token creation, invalid
  returned scope/TTL/lineage, failed private evidence export and pod timeout.
- Activation fault cases: stale UID/resource version, changed old data, missing
  Secret, unrelated data retention, partial sequence failure, changed namespace
  and deadline expiry.
- Two independent final audits, exact-source normal CI, and authenticated matching
  artifacts are required before any live recovery trial. Source-only tests are
  not evidence that the retained installation has recovered.

The first native checkpoint exposes only the public contract, unauthenticated
target probe and `operator kubernetes-legacy-recovery-inspect OUTPUT` command.
Inspection receives its closed context on stdin, writes the detailed report to
a new private file and emits only a bounded nonsecret summary. It exposes no
staging, activation or arbitrary OpenBao request command.

Its focused Rust tests use an ephemeral test CA and retained public-only leaf
keys. They exercise the expired legacy generation, independent live issuer
selection, future/short-lived issuers, root-input and cluster mismatch, policy
and key custody drift, unsafe file links/modes, concurrent input drift and the
unchanged refusal of expired leaves by ordinary live certificate validation.

## Private inspection transport

`scripts/inspect_kubernetes_legacy_credentials.py` receives separate original and
recovery artifact directories and their exact release source/run identities. It
uses the existing installer closure verifier for both, checks the retained
original operator and image records, and requires the known legacy chart pin
`0.30.6`. The live OpenBao container must retain the original authenticated
repository and digest; its optional descriptive image tag does not change that
digest binding.

The adapter holds a nonblocking lock on the retained directory without modifying
it. It creates a separate private attempt directory and a disposable producer pod
with a 1,200-second total lifetime, one authenticated image, one memory-backed
volume and no service-account token. Admission uses the API-assigned UID and
effective live pod specification. It refuses injected containers, environment,
storage or privileges, then freezes and rechecks the admitted specification at
every private phase. The public CA and signed operator arrive before the native
unauthenticated target probe; current credentials and the extracted root token
arrive only after that probe and fresh namespace/pod checks.

The native private report and an opaque evidence archive must be retained before
the pod is deleted with a UID precondition. A changed pod, uncertain command
outcome or failed export withholds completion and retains the pod only within
its original lifetime. Retained initialization bytes and current credentials
are compared again before a completion record is written. These transport
checks have mocked orchestration tests; they do not claim a live recovery trial.

The selected recovery operator requires a matching signed release closure.
Ordinary pull-request build artifacts and the stable workflow's unqualified
installer-input artifact do not satisfy the verifier. Both accepted producers,
`cd.yml` and `nightly-release.yml`, require protected-main source. A reviewed,
merged change therefore needs a matching signed nightly or stable release
before this adapter can run against an installation. The installed application
images remain the original runtime during credential recovery.

## Mutation checkpoint and private evidence

The next native checkpoint contains staging, candidate qualification and a pure
Secret planner under test-only module wiring. It adds no release dispatch yet.
The separate mutation increment requires its own independent audits before that
wiring is enabled and a signed recovery artifact is produced.

Staging has a fixed inventory of **18 certificates and 33 tokens**. Every leaf
retains its subject, SANs, key usage, extended key usage, issuer and signer SPKI.
Each replacement token uses only its existing policy bundle, is an orphan service
token, is nonrenewable, omits the default policy and has an explicit eight-hour
maximum lifetime. Issued credentials need at least seven hours remaining at
qualification. No request can supply a policy body or a new key, role, issuer,
CA, auth mount or credential lifetime.

A complete positive stage has 120 bounded POST requests: existing-key CSRs and
certificate signing, token creation and lookup, and same-key signature proofs.
Each request has an exclusively created, durable private intent before network
transmission. The opaque bounded response is persisted before decoding, including
HTTP errors, malformed JSON or incomplete bodies. The retained root token is
never written into request evidence. A failure after the attempt begins leaves
the evidence in place and produces no completed candidate. Reusing the same
operation directory is refused; selecting another directory is not an automated
retry or evidence that an uncertain prior issuance did not occur.

The completion receipt includes SHA-256 bindings for all 120 request records
and all 120 opaque response captures. Qualification requires that exact record
set and rechecks every bound byte after its live proofs. Missing, additional or
changed records prevent a plan, including CSR/certificate captures that do not
need semantic replay. The intermediate replacement inputs must also match the
candidate exactly. These checks concern this newly created recovery evidence;
they do not add an unrecorded historical-bootstrap proof requirement.

Only after every postcondition succeeds is the candidate assembled. It has the
same filenames and modes as the original generation. Exactly 51 files change;
all other bytes, including static keys, passwords, CA inputs and the initial
migration token, remain unchanged. The original generation is never edited.

Qualification is a distinct native command over that completed stage. It checks
the exact retained stage evidence, repeats the live cluster, issuer, key, role
and policy admission, and proves the current validity and scope of all candidate
credentials without creating replacements. It validates the observed Secret
preimages and emits a private plan with a five-minute use deadline. The plan
binds the original and candidate file hashes/modes, exact inspection bytes,
exact staging receipt bytes, namespace/cluster identity, and all observed Secret
UIDs and resource versions. Public summaries contain only counts, status and
whole-artifact digests; the plan and response evidence remain private.

The qualified plan also binds all 51 qualification request records and all 51
opaque response captures by SHA-256. Native qualification rechecks that exact
private journal after its final live inspection. The transport compares every
exported record against the plan before the first Secret patch, so evidence
changed after qualification cannot accompany an otherwise valid plan.

The pure planner derives every changed field from the native Secret publication
catalog. It permits exactly **51 field replacements in 34 existing Secrets**,
including both Notification Secrets. It requires the exact normalized old field
values and tests each Secret's UID, resource version and complete data object
before replacements. A missing Secret, changed scope, extra input, mode change,
unchanged replacement or stale preimage fails admission. Unrelated fields and
metadata remain intact. Updates are atomic within one Secret, not across the
whole set; a partial or ambiguous sequence needs explicit operator reconciliation
from the retained preimages and responses.

The local tests include real ephemeral RSA/P-256 signatures and a local TLS
server for the production response-capture path. They cover malformed and lost
responses, oversized/truncated bodies, incorrect returned credentials, drift
after issuance, stale private evidence and Secret state, and refusal to replay
a completed or partial operation. These checks do not constitute a live cluster
recovery result.

## Later enrollment and runtime upgrade boundary

Recovery restores credentials for the installed application images. It does not
claim that code changes in a later native runtime are active, and it does not
run a database migration or change the original bootstrap receipt.

Fresh recovered credentials can satisfy the existing TLS enrollment guard:
`provision_selfhost_renewal_identity.py` calls native `renewal-inventory`, which
proves all 21 scoped TLS/Keycloak tokens have at least one hour remaining and
checks the current certificates and issuers before `approle-bootstrap renewal`.
The native application enrollment owner likewise proves the namespace/cluster
binding, existing policies and 11 live ordinary runtime token inputs before it
creates its separate scoped application AppRole and leaf roles. Neither guard
needs to accept expired credentials or fabricated enrollment receipts.

There is still a Kubernetes adoption boundary. The routine application staging
adapter requires the original bootstrap's `applicationAuthority` record, its
retained identity directory and authenticated original operator bytes. The
supported legacy bootstrap has no such record. The fresh-bootstrap helper is
currently the owner that creates it; successfully invoking native enrollment
later does not authorize rewriting historical `bootstrap-complete.json` or
pretending it was present originally. A separately reviewed retained-Kubernetes
enrollment/adoption owner must bind real new enrollment evidence before that
routine adapter can be used for this installation.

A migration grant is separate again. The routine application authority contains
only 11 runtime replacement roles. It excludes the initial migration credential
and the legacy `OPENBAO_SERVICE_TOKEN` alias; the TLS authority covers only its
21 TLS/Keycloak scoped tokens. Neither grants migration minting. This recovery
keeps the initial migration token unchanged, so a separately reviewed signed
runtime upgrade that needs migrations still requires an explicit existing-target
migration-authority path. No fresh bootstrap, manual receipt repair or expanded
renewal policy is implied by recovery completion.
