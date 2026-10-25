# Disposable self-host clean-install rehearsal

This procedure runs the exact prepared ZIP on an isolated Linux amd64 host. It
does not qualify or publish the bundle: the runner writes an **unqualified**
component report. Stack release now builds mandatory installer inputs and requires
its independent image digests on every dispatch. The public
release must already identify the same source commit. Do not use production
credentials, a real CSCA/DSC, or a customer organization.

The Stack publisher needs no tag secret. The first release run qualifies and
promotes the five images, uploads `stack-release-promotion-complete-<run-id>`,
then stops at the late tag gate. Its prepared inputs remain unqualified and
cannot pass the terminal-success producer binding. There is no preparation
bypass: the obsolete `prepare_selfhost_lock` dispatch input has been removed.
From a clean checkout of the
**same current main commit**, an operator with local `gh` authentication including workflow
permission runs:

```bash
python3 scripts/push_promoted_release_tag.py \
  --promotion-run-id <first-stack-release-run-id> \
  --claim-run-id <prepare-stack-claim-run-id>
```

The helper validates the promoted transaction, current main, and all five
registry digests before pushing the exact annotated tag. Resume Stack release
from the same source with `claim_run_id`, `resume_run_id=<first run ID>`,
`resume_artifact=stack-release-promotion-complete-<first run ID>`,
and the **same four immutable external-image digests**. The resumed run verifies the tag, publishes the release, and, when
all its jobs succeed, owns the prepared self-host bundle as a terminally
successful producer. Reusing the first failed promotion run as a producer is
not valid. Installer inputs bind the exact workflow run **and attempt** through
local attestation bundles. After a failed build or publication attempt, use a
**fresh Stack release dispatch** with the supported same-source transaction
checkpoint described above. Rerunning failed jobs cannot relabel older artifacts
with the new attempt; existing run-ID artifact names must not be overwritten to
bypass that check. `installer-inputs-unqualified-<run-id>-<attempt>` is a mandatory
build prerequisite, not installer acceptance or admission. Stack publication
now signs the installer payloads and inventory and includes five verified offline
provenance files in its exact 32-asset release set. Normal one-line installation
still requires separate acceptance and admission evidence; publishing these
inputs does not grant it. Existing stack qualification gates remain mandatory.
The operator-only download helper also accepts the exact historical 19-asset
release set through an explicit legacy policy; the publisher does not downgrade.
An immutable-release retry verifies the original producer's proofs and compares
the four actual installer payloads with the new candidate. A differing same-source
rebuild refuses the retry and preserves the original release; reproducibility
is not assumed, and signatures or inventory are not overwritten. Never put a
cross-repository access token into an Actions secret for this handoff.

The current qualification target is 32 GiB RAM and 20 GiB free disk for all
locked images and fresh database state. The component rehearsal also requires
Docker Compose, Python 3.12 with the pinned integration test dependencies,
Rust 1.95.0 with locked Cargo dependencies, OpenSSL, and anonymous registry
access. The host must have
no existing qualification project. Canvas qualification may use the same host
sequentially, after its Docker project and state have been removed. The local
Windows Docker/WSL configuration is not a suitable 32 GiB qualifier.

Acceptance requires 32 GiB of guest-visible RAM and 20 GiB free on Docker's data
filesystem before image pulls. The report validator enforces these byte thresholds;
the harness must establish measurement location and timing. Provision extra VM memory
for kernel reservations; nominal VM allocation is not the guest measurement.
Measure the Docker data filesystem, which may differ from the installation
directory's filesystem. These are qualification gates, not consumer installer
minimum-memory checks. A smaller disposable host may be used for an exploratory run
of this same ZIP and journey, but record its physical/VM RAM, CPU, free disk,
peak container and host memory, swap activity, OOM kills, and any failed
health or business step. Keep the result **unqualified** until the complete
journey and custody checks pass, the lower-memory operating envelope is
reviewed, and this qualification target is updated. A Compose render or image
pull alone does not establish a smaller supported minimum.

The active capacity experiment starts with a disposable 4 GiB, two-CPU VM and
a 32 GiB disk. Run the same installation and business/custody journey, with
memory, swap, OOM and disk observations retained alongside failures. Increase
resources only when the measured failure calls for it. The 32 GiB target is not
an established product minimum and must not prevent this smaller-host trial.

### One-line installer host observation

The component rehearsal above uses source and development tools. It is not the
clean guest required for one-line installer acceptance. The acceptance controller
must establish a fresh guest image and disk, keep its GitHub credentials outside
the guest, and collect observations before any image pulls or neighbor fixtures.

Transfer the reviewed standalone `scripts/installer_host_probe.py` into that guest
without transferring the repository, then run it with the guest's Python runtime:

```bash
python3 installer_host_probe.py --docker-bin /usr/bin/docker > host-observation.json
```

The probe queries the fixed local Docker socket and measures guest RAM, Docker
RAM, and free space on Docker's data filesystem. It records initial Docker
resources and limited credential-file, environment-name and development-tool
presence observations. It does not read credential contents or mutate Docker
resources. Its only local write is a private temporary directory for isolated
Docker client configuration, removed on normal completion.

Exit zero means observation succeeded; it does not mean the host qualifies.
Inspect the separate capacity and Docker-clean predicates. The observation is
not an atomic snapshot and cannot establish source absence, credential absence,
VM origin, physical backing capacity or pre-pull timing. Those remain controller
responsibilities. Permission failures or incomplete reads fail the probe rather
than substituting a different filesystem or claiming a clean host. This record
cannot replace the signed installed-journey acceptance report.

### Candidate execution boundary

`scripts/installer_candidate_authorize.py` verifies the five staged subjects and
their original build proofs before writing an unsigned, acceptance-only grant.
Its caller must supply an authenticated acceptance-run API snapshot, independent
invocation context, and pinned verifier binaries. It does not sign or dispatch
the grant, and cannot produce an installed-acceptance report.

The main-only `installer-acceptance.yml` workflow now prepares staged execution
grants from an exact successful nightly build. Configure repository variable
`INSTALLER_CONTROLLER_USER_ID` to the approved controller operator's numeric
GitHub user ID before dispatch. Shared Actions bot credentials are not accepted.
The workflow signs the authorization, creates a unique draft release for receipt
transport, and uploads `installer-staged-grant-<run-id>-<attempt>` containing the
authorization, its two proofs and the exact transport descriptor.

The controller must authenticate that package and its independently selected
invocation, observe the intended guest/disk/Engine, and durably consume the nonce
outside the guest. Upload only the returned receipt bytes as
`installer-controller-consumption.json` to the descriptor's numeric draft release
ID using the approved account. Do not overwrite an asset or retry an uncertain
consumption. Keep GitHub credentials outside the guest. The workflow polls for
at most 15 minutes, leaving at least two minutes before authorization expiry.
It binds the uploader, asset ID, digest and exact candidate context, checks for
replacement during download, then signs the receipt in the same hosted invocation.
The final `installer-candidate-execution-grant-<run-id>-<attempt>` artifact contains
both grant triplets and transport evidence. Guest execution and installed-journey
report collection are still separate work; this workflow cannot promote a release.

Draft transport is authenticated coordination, not anonymous public acquisition.
GitHub permits release-asset updates, so names alone cannot identify the receipt
([asset API](https://docs.github.com/en/rest/releases/assets)). Preserve the exact
draft and any partial evidence until the controller archives their identities and
hashes. Cleanup must remove only that owned draft, never publish it, and retain
the external nonce ledger permanently. The workflow does not delete transports
automatically; failed creation retains a local intent for reconciliation.

After receiving the final execution grant, the Linux controller uses
`scripts/installer_candidate_dispatch.py` to transfer the exact 15 staged inputs,
the two signed grant triplets, and pinned verifier binaries over SSH. Supply
private `--context-file` and `--target-file` records from the independently chosen
invocation and live controller observations, plus `--ledger` pointing to the
original durable consumption record. The target record has exactly `guest_id`,
`disk_id`, `engine_id`, and `installation_id`; copying these from an unverified
download is not a physical target observation.

The helper requires a dedicated non-root guest account with a private `0700`
home at `/home/<user>`, a private key and pinned known-hosts file outside the
guest, and root-owned SSH/SCP executables. It disables ambient SSH configuration,
agents, proxies and forwarding. It verifies all seven signed subjects before
creating a durable dispatch intent, checks expiry before every remote action,
and checks transferred executable hashes before invoking `install-candidate`.
Any interrupted transfer or incomplete installation preserves the intent and
guest state and refuses a second dispatch. A zero command exit is recorded only
as a transport result; it is never an installed-journey acceptance report.

Candidate testing must use acceptance-only authorization rather than a fabricated
consumer admission. The native candidate preparation library authenticates the
acceptance workflow invocation, the exact inventory and all four payloads before
extracting the bundle. Local verification alone does not prove an anonymous
public download. The controller must independently supply the expected invocation
and nonce, retain a durable consumption record outside the guest, and use the
guest's shared private nonce registry before provisioning. Neither a copied
authorization nor the guest registry provides global replay prevention.

The internal `marty-deploy install-candidate` command requires both the signed
candidate authorization and a signed controller-consumption receipt, verified
against the independently selected acceptance workflow invocation. The receipt
binds the authorization, inventory, guest, disk, Docker engine and installation
UUID. The controller library persists its exact unsigned receipt outside the
guest before returning it for signing and dispatch. A failed or uncertain write
consumes that dispatch; it must not be silently retried.

The command fixes the guest nonce registry at
`~/.marty-installer-candidate-nonces` using the account's recorded home directory.
The controller must create this private directory before dispatch and retain it
across failures and uninstall. After consuming the nonce, the command creates an
acceptance-only journal, verifies every payload, rechecks authorization expiry,
and invokes the same provisioning path as normal installation. These journals
cannot use ordinary provisioning resume or claim the consumer `Ready` phase.
External acceptance evidence must assess the actual runtime and journey. This
entry does not itself prove guest origin, anonymous public acquisition, or a
completed acceptance workflow; controller provisioning and release qualification
remain required.

### Native renewal bootstrap and root retirement

The internal `installer-renewal-bootstrap` helper creates the existing scoped
workload/Keycloak renewal identity from fixed, read-only container inputs. It
validates the current 21-policy inventory, verifies a scoped login and retires
that temporary verification token. Identity files remain private; pending and
completed receipts distinguish an interrupted attempt from completed bootstrap.
The renewal policy grants self-revocation so temporary operators can retire
their own login without bootstrap root. It does not grant revocation of other
tokens or change CA-rotation authority. Successful self-revocation must be
followed by a denied authenticated token lookup. Existing renewal identities
using the older exact policy are incompatible and fail validation; do not
silently rewrite that policy or replay bootstrap against retained state.
Use a fresh owned stack for qualification of the new policy. Migration of an
existing installation requires a separately reviewed recovery procedure.
Native installation runs it after ingress provisioning and before application
startup, through the internal `installer-renewal-bootstrap-transfer` wrapper in
a recorded, owned helper container. Forty reviewed inputs are staged read-only.
Root-owned originals remain private under `renewal-transfer/output`; exclusive
copies of the three identity files and two receipts are delivered as `0600`
files under the installation owner's `0700` `renewal-transfer/delivered` directory.
The container is removed only after output validation and a durable result.
Uninstall refuses a partial renewal stage or a still-present helper. Recovery
retains these directories and receipts; it does not automatically repeat minting.
Offline contract tests do not establish successful live bootstrap or renewal.

For source-based Linux ownership qualification, run
`bash scripts/qualify_installer_ownership.sh` as a developer with the build
dependencies installed and passwordless sudo for the compiled test executable.
This runs one explicitly selected root-only test with synthetic temporary files.
It checks the real recipient UID/GID, clears supplementary groups, proves the
recipient can read the delivered copy, and requires permission-denied errors for
root originals and another user's access. On WSL without passwordless sudo, the
same exact compiled test can be invoked with `wsl -u root` after verifying its
test listing. This is component evidence, not clean-host release acceptance.
The reviewed OpenBao image produces its public CA as UID 100. The fixed CA input
therefore permits UID 0 or 100 with the existing read-only, mode and link checks;
the root token still requires UID 0 and `0400`. This is compatibility with the
pinned producer, not a general trust rule for certificates owned by UID 100.

The opt-in `installer_openbao_engine` test
`actual_renewal_bootstrap_uses_live_keycloak_and_workload_inputs` exercises actual
OpenBao, Keycloak credential provisioning, workload TLS and renewal bootstrap.
It requires explicit `MARTY_INSTALLER_TEST_ENGINE_ID`,
`MARTY_INSTALLER_TEST_OPENBAO_IMAGE`, `MARTY_INSTALLER_TEST_SERVICES_IMAGE` and
`MARTY_INSTALLER_TEST_OPERATOR` values. Use immutable published image digests and
a current-source Linux amd64 static operator build; the test validates the ELF
and persisted hash, while the caller records source/build provenance. Set
`TMPDIR` to a persistent private recovery parent before running the exact test
with `--exact --ignored --nocapture`. A failure retains owned resources and
private state. Successful helper removal precedes exact four-role OpenBao
cleanup and comparison with the original neighboring resource sets. This
fixture has synthetic release admission and cannot qualify a version release.

This component fixture passed against installer source
`8392d2ba461f945b2ffb5023b9eadf0fdfc7a71b` with a freshly built static operator
(SHA-256 `a7184acd9a157ef5e996116b63669ecaa6870c262d1dd156d177f836240fd3c6`).
It verified the live 21-policy inventory, scoped login, verification-token
revocation, private identity delivery and owned-resource cleanup with unchanged
neighbor identities. It did not replace application credentials, retire root,
renew ingress credentials, or qualify a complete installed journey.

The same fresh-stack fixture also passed against source
`574a8eade92d8a7d43e81ab57b8de9dd4355b66c`, using static operator SHA-256
`896b45b040d9eac06b9e6d9f80807444e23656671005bccf5d98d7da4fae2d70`.
That run exercised the new renewal-only self-revocation permission and denied
lookup afterward. The fixture removed its owned resources and retained private
recovery data, with unchanged neighboring resource identities. This does not
qualify the candidate-generation helper described below.

This step retains the bootstrap root. Initial workload and Keycloak credentials
are root descendants, so revoking root before replacing them would break the
installation. Replacement credentials need orphan-token verification, durable
generation staging, controlled container recreation and rollback checks. The
installer's UUID-specific ingress authority is separate from the 21-policy
inventory and still needs its own renewal path for eight-hour credentials.
Scoped snapshot/recovery checks and before/after lineage audits must pass before
root revocation. Deleting `root.token` alone is insufficient: initialization
records also contain that credential, and the separate orphaned `kms-bootstrap`
token needs its own disposition.

The internal `installer-generation-provision --installation-id UUID` helper
implements candidate credential production only. It requires an externally
admitted container with the pinned services image and current static operator,
fixed read-only mounts for the forty current inputs, three private renewal
identity files, OpenBao CA, and original Keycloak removal receipt. A fresh,
root-owned private `/output` holds the durable intent and surviving outputs.
It receives no bootstrap root. Workload and Keycloak producers use the scoped
renewal login, retain existing remote key versions and issuers, and stage forty
files with thirty-nine replacements and an unchanged CA. Live checks require
orphan tokens, correct scopes, certificate chains and sufficient remaining
lifetime before the completed receipt can be written. Known login tokens are
self-revoked even on producer failure; lost responses can leave unknown orphan
leaves, so an interrupted attempt requires recovery and must not be replayed.

The owned `installer_generation_host` stage runs the transfer wrapper with the
same pinned services image and current static operator. It stages the forty
inputs and three identity files separately, binds the original Keycloak and
renewal removal evidence, and records the helper identity before starting it.
Root-owned originals remain under `generation-transfer/output`; the owner gets
forty candidate files and three receipts under a private `delivered` directory.
Source and candidate hashes must match before a result is recorded and the
helper is removed. Partial generation state blocks normal uninstall; host data
is retained. This stage does not activate credentials.

The opt-in test
`actual_orphan_generation_stages_verified_candidate_without_activation` uses
the same exact-engine and static-operator requirements as the renewal fixture.
It exercises fresh Keycloak/TLS/renewal setup, candidate generation, output
delivery and exact helper removal before infrastructure cleanup. Contract tests
alone do not qualify that actual execution or clean-host installation.

Normal installation does not invoke this stage yet. The explicit
`prepare_with_generation` path assembles the complete application credential
snapshot under private `application-generation`, after optional storage and
operator-password staging. It replaces exactly the40 renewable inputs and
copies the referenced unchanged scalars, initializer token and ingress inputs.
Snapshot files are read-only; original files and recovery evidence remain intact.
The final selection receipt binds the snapshot inventory and exact application
environment, plan and Compose bytes. Startup, mount admission, log filtering and
uninstall verify that selection; partial selection is refused. Logs filter both
the original credentials and selected snapshot. Only unused tunnel services are
pruned; the selected29 services and KMS initializer keep their dependency order.
Actual candidate production has passed the opt-in fixture; full application
activation, rollback and clean-host release acceptance remain unqualified.
Do not replace individual files in the existing `secrets` directory or treat
candidate production or model preparation as readiness or root retirement.

The separate opt-in
`actual_application_generation_prepares_full_snapshot_without_starting_services`
fixture exercises the production packager, ingress provisioning, complete
snapshot preparation and filesystem admission without creating application
containers. In addition to the operator, Engine and image inputs above, provide
`MARTY_INSTALLER_COMPOSE_EXECUTABLE`, `MARTY_INSTALLER_TEST_ORIGINAL_IMAGE_LOCK`
and `MARTY_INSTALLER_TEST_IMAGE_LOCK`. Preserve the downloaded nightly lock;
the second lock is an explicitly unqualified local fixture copy whose only
changed field is the release label matching the current source base version.
All32 image mappings must remain identical and helper digests must match them.
The fixture records both lock hashes/releases, source commit and operator hash.
This adaptation tests current-source interoperability with immutable images;
it supplies no signed release admission or source-image provenance proof.

## Experimental preview installer path

An [experimental tester preview](https://github.com/ElevenID/marty-ui/releases)
has a Linux-only staging helper that verifies all downloaded checksums,
the exact source/receipt lineage and the extracted ZIP, then creates a new
operator-private root with disposable scalar credentials. From a **clean,
matching source checkout**, use an operator-owned `0700` parent and a fresh
child path:

Before staging, install the checkout's direct verifier dependencies in a
disposable Python 3.12 environment **outside** the source checkout. These are
separate from the pinned integration-test dependencies; the release workflow
installs the same direct versions. For example, after activating that environment:

```bash
python3 -m pip install --requirement scripts/selfhost-preview-tools.requirements.txt
```

Use the preview's own attached tester guide and exact source commit. A newer
stable Stack tag is not interchangeable with an older preview's assets.

If you already ran staging from the preview's tester guide, do **not** repeat
that command against the same private root. Continue with the OpenBao,
Keycloak, workload TLS, and installed-journey steps using those same verified
assets, source checkout, and private root.

```bash
python3 scripts/stage_selfhost_disposable_preview.py \
  --assets-dir /absolute/path/to/downloaded-preview-assets \
  --source-checkout /absolute/path/to/matching-clean-source \
  --private-root /absolute/path/to/operator-private/new-run
python3 scripts/start_selfhost_disposable_openbao.py \
  --private-root /absolute/path/to/operator-private/new-run \
  --host-port 18200
# First install and source the signed marty-deploy.lock matching this source/release.
sudo --preserve-env=MARTY_DEPLOY_BIN,MARTY_DEPLOY_BIN_SHA256,MARTY_DEPLOY_SOURCE_SHA,MARTY_DEPLOY_RELEASE_TAG python3 scripts/stage_selfhost_keycloak_inputs.py \
  --private-root /absolute/path/to/operator-private/new-run
```

Then stage workload TLS from the **extracted bundle's** helper, whose parent
contains the exact image lock (the source checkout root does not). The project
name is public metadata in `openbao.json`; do not print any token files:

```bash
private_root=/absolute/path/to/operator-private/new-run
openbao_project=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["project"])' \
  "$private_root/openbao.json")
sudo env PYTHONDONTWRITEBYTECODE=1 python3 "$private_root/install/selfhost-prepared/scripts/provision_selfhost_disposable_tls.py" \
  --secret-root "$private_root/secrets" \
  --openbao-state-root "$private_root/openbao-state" \
  --openbao-project "$openbao_project"
```

The helper also records verified, non-secret TLS key names and pinned version
1 for its 16 workload roles in `$private_root/selfhost-tls-kms-roles.json`. This
diagnostic record is separate from the 33 certificate/token secrets. It is not
a complete Compose environment file or evidence that the stack is ready.
The helper also writes `$private_root/selfhost-tls-kms.env.fragment`, containing
only the 16 verified `*_TLS_KMS_KEY_NAME` and 16 pinned
`*_TLS_KMS_KEY_VERSION` assignments. It checks their exact one-to-one mapping
against the shipped production example and Compose required-variable references.
This non-secret, private file is a fragment for an operator to review; it
contains no OpenBao address, domain, DID, token or other required environment
values. It is not a runnable `.env` file or installation qualification.

The OpenBao helper renders and checks the three-service Compose model before
starting a fresh project. It uses only the locked plugin image, an isolated
state directory and a selected loopback port. The Keycloak bridge runs the
existing remote-key provisioner in a root-owned temporary directory, then
transfers only its seven scoped/public outputs to the private secret root;
the root token remains in the OpenBao state directory. These steps do not
qualify the stack or complete custody or the installed business
journey.
The bridge verifies that the locked, healthy OpenBao container owns the exact
loopback port before contacting it. The Linux host must expose the **same
rootful Docker daemon** to the non-root starter and `sudo` bridge; rootless
Docker contexts are not yet supported by this installer path.
These helpers do **not** make the older `v1.1.247-selfhost-preview.2` image
installable. Use assets and a clean matching source checkout from the same
newer preview; this remains an unqualified disposable test path.

If startup fails, `openbao-pending.json` in the private root records the
project name and port, never a token. Inspect that marker and remove only its
named Docker project with the same Compose file and locked image environment.
Verify that no container or network with that project label remains before
discarding the disposable root. Do not remove the root while a bootstrap
container may still have its private state mounted; do not reuse a partly
initialized state directory. A failed `docker compose down` requires manual
operator cleanup of that exact project before any retry.
If Keycloak input staging fails after it has contacted OpenBao, do not rerun
it against that state: the provisioner may already have created its PKI mount,
keys or tokens. Remove the named OpenBao project, verify no labelled container
or network remains, discard the entire disposable root, and start with a new
stage and fresh OpenBao state. Its local output transfer rolls back files it
created, but cannot roll back OpenBao's remote mutations.

The disposable Keycloak and workload TLS credentials request eight-hour
lifetimes. Seven hours is an upper bound for those inputs, not a guaranteed
journey window: the custody signer and audit tokens expire within **one hour**
of issuance. Mint them immediately before the installed journey and leave
enough time for its image pull, build, startup, and public test. A slow run may
still fail on expiry; never extend token TTL or treat that failure as an
installed pass. The initial audit helper refuses to overwrite a token. Matching
source revisions with the evidence and audit AppRole helpers below can refresh
both one-hour tokens through their separate scoped identities, including after
root revocation; earlier released previews without those helpers require a new
disposable OpenBao state and private root after expiry.
Also check the effective expiry of workload TLS credentials, which OpenBao may cap,
and complete the journey before the earliest expiration. Do not keep the stack
running afterward. For this released-preview installer path, a new session
requires teardown and fresh disposable OpenBao state and secret roots. The
separate source-level [renewal procedure](selfhost-renewal-activation.md) can
stage Keycloak and workload TLS credentials into a new generation and recreate
an owned KMS-only project, but it is not yet an installed preview acceptance
or a supported cutover procedure.

New source revisions offer an optional `--with-operator-password` staging flag.
If the matching checkout's `stage_selfhost_disposable_preview.py --help` lists
it, append it to the initial staging command above. Released previews whose
matching source lacks the flag must use the separate helper below; do not
substitute a different source revision or restage an existing private root.
The flag uses the reviewed
credential helper to create `operator-password` (mode `0600`) in the fresh
private root, validating the matching source checkout's realm policy. It does
not provision an operator or qualify the stack. Without the flag, staging is
unchanged; generate the synthetic `11id` operator password separately, before
provisioning or starting the journey:

```bash
python3 "$source_root/scripts/generate_selfhost_disposable_credentials.py" \
  --operator-password-file "$private_root/operator-password"
```

Do not run the separate command if staging already created that file. Existing
private roots are never restaged, and existing password files are never replaced.

Have the operator secret runner read that file into `SELFHOST_TEST_PASSWORD`;
do not print it. This separate operator password guarantees the shipped realm's
length, uppercase, lowercase, digit and special-character requirements while
retaining 256 random bits. Arbitrary URL-safe tokens do not guarantee all those
classes. Existing service credentials keep their original hexadecimal format.
The helper refuses an existing output; never overwrite a previous attempt's
password or reuse its state. Journey input validation rejects an incompatible
operator password before Compose rendering, converter compilation or startup;
the fixture also rejects it before contacting Keycloak.

After provisioning, inspect the effective expirations without printing token
values. Run this from the clean release source checkout with its `scripts/`
directory on `PYTHONPATH`; `BAO_ADDR` must name the same locally controlled
HTTPS OpenBao used to provision the secrets. Repeat the check before a longer
test session, and stop before the earliest reported expiry. Set
`openbao_state_root` to that project's private state directory (the one
containing `root.token` and `tls/ca.crt`). Supply the exact started Compose
project and extracted locked install as well; the root token is mode 0400, so
the inspection needs `sudo` and verifies the live owner before reading it:

```bash
source_root=/path/to/clean/release-source
private_root=/path/to/private
secret_root="$private_root/secrets"
openbao_state_root="$private_root/openbao-state"
install_root="$private_root/install/selfhost-prepared"
openbao_project=${openbao_project:?Set the exact started OpenBao Compose project}
BAO_ADDR="https://127.0.0.1:${SELFHOST_OPENBAO_HOST_PORT:-18200}"
sudo env PYTHONPATH="$source_root/scripts" python3 - \
  "$secret_root" "$openbao_state_root" "$BAO_ADDR" \
  "$openbao_project" "$install_root" <<'PY'
from datetime import datetime, timezone
from pathlib import Path
import re
import subprocess
import sys
from passport_remote_tls import SELFHOST_CERT_FILES, SELFHOST_TOKEN_FILES
from provision_selfhost_disposable_tls import verified_openbao_owner, read_protected_root_token
from selfhost_openbao_client import Bao

secret_root, bao_state = map(Path, sys.argv[1:3])
address, project = sys.argv[3:5]
install = Path(sys.argv[5])
if not re.fullmatch(r"https://127\.0\.0\.1:[0-9]{2,5}", address):
    raise SystemExit("OpenBao endpoint must be loopback HTTPS")
verified_openbao_owner(project, bao_state, install, int(address.rsplit(":", 1)[1]))
client = Bao(address, bao_state / "tls/ca.crt",
             read_protected_root_token(bao_state / "root.token"))
expiries = []
for name in sorted(SELFHOST_CERT_FILES):
    result = subprocess.run(["openssl", "x509", "-enddate", "-noout",
                             "-in", str(secret_root / name)],
                            check=True, capture_output=True, text=True)
    value = result.stdout.strip().removeprefix("notAfter=")
    expiries.append(datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
                    .replace(tzinfo=timezone.utc))
for name in sorted(SELFHOST_TOKEN_FILES):
    token = (secret_root / name).read_text(encoding="ascii").strip()
    data = client.request("POST", "auth/token/lookup", {"token": token})["data"]
    expiries.append(datetime.fromisoformat(data["expire_time"].replace("Z", "+00:00")))
earliest = min(expiries)
if earliest <= datetime.now(timezone.utc):
    raise SystemExit("A workload TLS credential has expired")
print("Earliest workload TLS expiry (UTC):", earliest.isoformat())
PY
```

## Stage exact inputs

1. After the Stack release succeeds, check out its source tag in a clean
   `marty-ui` tree and confirm it peels to the source SHA in the preparation
   receipt. Before and after downloading, bind the successful first-attempt
   protected-main `cd.yml` run and both unique artifact IDs/digests with
   `check_selfhost_preparation_artifacts.py`; reject any changed binding.
   Take the four prepared files from its
   `selfhost-lock-preparation-unqualified-<RUN_ID>` Actions artifact. The public
   release does **not** contain this ZIP. Take `release-transaction.json` from
   the same run's `stack-release-qualified-<RUN_ID>` artifact, and verify the
   public release transaction and manifest attestations separately. The
   qualified transaction's SHA-256 must equal the preparation receipt's
   `transaction_sha256`; the public promoted transaction has different bytes
   and cannot replace it. Copy the qualified transaction into the private
   staging directory as `selfhost-preparation-transaction.json`. For the
   existing staging helper, write a local `SELFHOST-PREVIEW-README.md` stating
   that this is an unqualified Actions-artifact handoff, then generate and
   verify a six-file `SHA256SUMS` there. That checksum file protects the local
   staging copy; it is **not** a published signature or release asset. Finally,
   run `check_prepared_selfhost_consumer.py --verify-archive-only` against the
   ZIP, lock, qualified transaction, receipt, descriptor, source SHA and run
   ID before creating any private state. Keep the original four artifact
   files unchanged.

   ```bash
   set -euo pipefail
   run_id=39068340445 # v1.1.254 example; use the chosen successful release run
   tag=v1.1.254
   source_root=/absolute/path/to/clean/release-checkout
   prepared=/absolute/path/to/prepared-artifact
   qualified=/absolute/path/to/qualified-transaction-artifact
   public=/absolute/path/to/public-release-assets
   mkdir -p "$prepared" "$qualified" "$public"
   source_sha=$(git -C "$source_root" rev-parse HEAD)
   test "$(git -C "$source_root" rev-parse "$tag^{commit}")" = "$source_sha"
   verify_producer() {
     phase=$1
     gh api "repos/ElevenID/marty-ui/actions/runs/$run_id" \
       > "$public/producer-run-$phase.json"
     gh api "repos/ElevenID/marty-ui/actions/runs/$run_id/artifacts?name=selfhost-lock-preparation-unqualified-$run_id" \
       > "$public/bundle-artifacts-$phase.json"
     gh api "repos/ElevenID/marty-ui/actions/runs/$run_id/artifacts?name=stack-release-qualified-$run_id" \
       > "$public/transaction-artifacts-$phase.json"
     python3 "$source_root/scripts/check_selfhost_preparation_artifacts.py" \
       --run "$public/producer-run-$phase.json" \
       --bundle "$public/bundle-artifacts-$phase.json" \
       --transaction "$public/transaction-artifacts-$phase.json" \
       --run-id "$run_id" --source-sha "$source_sha" \
       --output "$public/producer-binding-$phase.json"
   }
   verify_producer before
   gh run download "$run_id" -R ElevenID/marty-ui \
     -n "selfhost-lock-preparation-unqualified-$run_id" -D "$prepared"
   gh run download "$run_id" -R ElevenID/marty-ui \
     -n "stack-release-qualified-$run_id" -D "$qualified"
   verify_producer after
   cmp "$public/producer-binding-before.json" \
     "$public/producer-binding-after.json"
   gh release download "$tag" -R ElevenID/marty-ui -D "$public" \
     -p release-transaction.json -p stack-manifest.json -p SHA256SUMS
   (cd "$public" && sha256sum -c --ignore-missing SHA256SUMS)
   for asset in release-transaction.json stack-manifest.json; do
     gh attestation verify "$public/$asset" -R ElevenID/marty-ui \
       --signer-workflow ElevenID/marty-ui/.github/workflows/cd.yml \
       --source-digest "$source_sha" --source-ref refs/heads/main \
       --deny-self-hosted-runners
   done
   cp "$qualified/release-transaction.json" \
     "$prepared/selfhost-preparation-transaction.json"
   test "$(sha256sum "$prepared/selfhost-preparation-transaction.json" | cut -d ' ' -f 1)" = \
     "$(jq -r .transaction_sha256 "$prepared/prepared-selfhost-bundle.json")"
   printf '%s\n' 'Private unqualified Actions-artifact handoff; not a public release asset.' \
     > "$prepared/SELFHOST-PREVIEW-README.md"
   (cd "$prepared" && sha256sum prepared-selfhost-bundle.zip \
     prepared-selfhost-images.json prepared-selfhost-bundle.json \
     prepared-selfhost-product-descriptor.json \
     selfhost-preparation-transaction.json SELFHOST-PREVIEW-README.md \
     > SHA256SUMS && sha256sum -c SHA256SUMS)
   python3 "$source_root/scripts/check_prepared_selfhost_consumer.py" \
     --archive "$prepared/prepared-selfhost-bundle.zip" \
     --image-lock "$prepared/prepared-selfhost-images.json" \
     --transaction "$prepared/selfhost-preparation-transaction.json" \
     --receipt "$prepared/prepared-selfhost-bundle.json" \
     --descriptor "$prepared/prepared-selfhost-product-descriptor.json" \
     --expected-source-sha "$source_sha" --expected-run-id "$run_id" \
     --verify-archive-only
   ```
2. Check out `ElevenID/marty-integration-tests` separately at
   `5b3ec6a802a5e13201be8883741889405a86d146`. The runner verifies that
   this is a clean protected-main ancestor and selects only the public
   `tests/oss_stack/selfhost_customer_journey.py` test.
3. Use the staging helper below to create a fresh private operator directory
   outside both repositories. It extracts the verified ZIP and creates the
   state directory and disposable scalar credentials. Provision the remaining
   files named by `LOCAL_SECRET_NAMES` in
   `scripts/run_selfhost_business_journey.py` before running the journey;
   the Compose env file is still operator supplied. Files explicitly marked
   `allow_empty` in the reviewed
   secret catalog may stay empty only when the rendered Compose settings show
   their integrations are disabled (for example, Google login is off); an
   enabled integration needs non-placeholder material. The
   runner does not start either Cloudflare tunnel, so their two token files
   are not required for this local journey. The full all-profile Compose
   secret declarations and service bindings are still checked unchanged.
   Set `SELFHOST_STATE_DIR`, `SELFHOST_SECRET_DIR`, `MARTY_ORG_ID`,
    `MARTY_ORG_ADMIN_EMAIL`, `MARTY_ORG_SLUG` (default `marty`), and
    `PUBLIC_DOMAIN` before rendering. Set both journey DIDs to
    `did:web:<PUBLIC_DOMAIN>:orgs:<MARTY_ORG_SLUG>`; the organization ID is
    still the seeded UUID. The admin
   email must be a synthetic `@selfhost.marty.invalid` address. Use disposable
   workload TLS material and scoped OpenBao tokens. Configure the same
   disposable external OpenBao for the installed `signing-keys` service and the
   audit hook; its audit token must meet the policy and TTL contract in
   [the synthetic fixture guide](selfhost-synthetic-fixture.md).
4. Supply the eight public journey `SELFHOST_*` values from the
   [integration contract](https://github.com/ElevenID/marty-integration-tests/blob/5b3ec6a802a5e13201be8883741889405a86d146/tests/oss_stack/SELFHOST_CUSTOMER_JOURNEY.md)
   through an operator secret runner. Supply a loopback HTTPS
   `SELFHOST_BAO_AUDIT_URL` for the same OpenBao port, stage its public CA as
   `openbao_tls_ca_cert` in the private secret root, and supply
   `SELFHOST_BAO_AUDIT_TOKEN_FILE` and
   `SELFHOST_CUSTODY_SIGNING_TOKEN_FILE` in the same process environment.
   Provision a fresh non-exportable Ed25519 Transit signer using
   [the synthetic fixture guide](selfhost-synthetic-fixture.md) after starting
   the disposable OpenBao project. Do not pin its per-install public digest in
   release source. The runner checks live key metadata through the scoped
   audit token and binds the HTTPS endpoint and CA to the owned, locked-image
   OpenBao container. The signer token stays outside source and installation;
   no signer private key file is generated or mounted.

The following commands use absolute, operator-owned paths and the reviewed
disposable provisioning helpers. The runner rejects missing inputs before it
can report a pass. Keep the original artifact names and use a new private root
for every attempt.

```bash
set -euo pipefail
source_root=/srv/qualification/marty-ui-release
integration_root=/srv/qualification/marty-integration-tests
prepared=/srv/qualification/prepared
private_parent=/absolute/path/to/operator-owned-private-parent
install -d -m 0700 "$private_parent"
private="$private_parent/new-run"
install_root="$private/install/selfhost-prepared"
state_root="$private/state"
secret_root="$private/secrets"
env_file="$private/selfhost.env"
openbao_state_root="$private/openbao-state"
source_sha=$(git -C "$source_root" rev-parse HEAD)
run_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_id"])' \
  "$prepared/prepared-selfhost-bundle.json")

python3 "$source_root/scripts/check_prepared_selfhost_consumer.py" \
  --archive "$prepared/prepared-selfhost-bundle.zip" \
  --image-lock "$prepared/prepared-selfhost-images.json" \
  --transaction "$prepared/selfhost-preparation-transaction.json" \
  --receipt "$prepared/prepared-selfhost-bundle.json" \
  --descriptor "$prepared/prepared-selfhost-product-descriptor.json" \
  --expected-source-sha "$source_sha" --expected-run-id "$run_id" \
  --verify-archive-only
python3 "$source_root/scripts/stage_selfhost_disposable_preview.py" \
  --assets-dir "$prepared" --source-checkout "$source_root" \
  --private-root "$private"
openbao_port=${SELFHOST_OPENBAO_HOST_PORT:-18200}
python3 "$source_root/scripts/start_selfhost_disposable_openbao.py" \
  --private-root "$private" --host-port "$openbao_port"
openbao_project=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["project"])' \
  "$private/openbao.json")
# First install and source the signed marty-deploy.lock matching this source/release.
sudo --preserve-env=MARTY_DEPLOY_BIN,MARTY_DEPLOY_BIN_SHA256,MARTY_DEPLOY_SOURCE_SHA,MARTY_DEPLOY_RELEASE_TAG python3 "$source_root/scripts/stage_selfhost_keycloak_inputs.py" \
  --private-root "$private"
sudo env PYTHONDONTWRITEBYTECODE=1 python3 "$install_root/scripts/provision_selfhost_disposable_tls.py" \
  --secret-root "$secret_root" --openbao-state-root "$openbao_state_root" \
  --openbao-project "$openbao_project"
project="marty-selfhost-qual-$(openssl rand -hex 8)"
fixture="$source_root/scripts/setup_selfhost_synthetic_fixture.py"
fixture_sha=$(sha256sum "$fixture" | cut -d ' ' -f 1)

# The operator secret runner exports the public-journey SELFHOST_* values and
# MARTY_ORG_ID and MARTY_ORG_SLUG (matching the Compose env file). The env file resolves Compose
# settings, including these same absolute
# state/secret roots and loopback published ports. The helpers below stage
# the scoped audit and signer tokens; do not copy a root token into the install.
docker compose --project-name "$project" --env-file "$env_file" \
  -f "$install_root/docker-compose.yml" --profile '*' config --format json \
  > "$private/compose-model.json"
# This no-external-integration preview stages six empty optional files only
# after the helper independently renders this exact install and proves each
# corresponding integration disabled. For an integration-enabled install,
# supply real credentials instead and omit this preview-only command.
python3 "$source_root/scripts/stage_selfhost_disabled_optional_secrets.py" \
  --secret-root "$secret_root" --install-root "$install_root" \
  --env-file "$env_file" --project-name "$project"
# The audit policy must target the same seeded organization as the fixture.
test "${MARTY_ORG_ID:?Set the migration organization ID}" = \
  "${SELFHOST_ORG_ID:?Set the matching journey organization ID}"
# Mint one-hour custody and audit tokens only after preparation is complete.
# Each helper verifies the locked, healthy OpenBao owner before reading its
# protected root token. Start the journey immediately; do not reuse expired
# audit inputs or extend their TTL to compensate for a slow installation.
sudo python3 "$source_root/scripts/provision_selfhost_custody_signer.py" \
  --endpoint "https://127.0.0.1:$openbao_port" \
  --state-root "$openbao_state_root" --output-root "$secret_root" \
  --project-name "$openbao_project"
evidence_identity_root="$(dirname "$openbao_state_root")/evidence-identity"
sudo install -d -m 700 "$evidence_identity_root"
sudo python3 "$source_root/scripts/provision_selfhost_evidence_identity.py" \
  --mode bootstrap --bao-addr "https://127.0.0.1:$openbao_port" \
  --bao-ca "$openbao_state_root/tls/ca.crt" \
  --root-token-file "$openbao_state_root/root.token" \
  --output "$evidence_identity_root"
# Later token refresh uses the evidence identity, even after root revocation:
# sudo python3 "$source_root/scripts/provision_selfhost_custody_signer.py" \
#   --endpoint "https://127.0.0.1:$openbao_port" \
#   --state-root "$openbao_state_root" --output-root "$secret_root" \
#   --project-name "$openbao_project" --refresh-token \
#   --identity-root "$evidence_identity_root"
sudo python3 "$source_root/scripts/provision_selfhost_audit_token.py" \
  --endpoint "https://127.0.0.1:$openbao_port" \
  --state-root "$openbao_state_root" --output-root "$secret_root" \
  --org-id "${MARTY_ORG_ID:?Set the seeded organization ID}" \
  --org-slug "${MARTY_ORG_SLUG:?Set the seeded organization slug}" \
  --did "${SELFHOST_ISSUER_DID:?Set the matching issuer DID}" \
  --project-name "$openbao_project"
audit_identity_root="$(dirname "$openbao_state_root")/audit-identity"
sudo install -d -m 700 "$audit_identity_root"
sudo python3 "$source_root/scripts/provision_selfhost_audit_identity.py" \
  --mode bootstrap --bao-addr "https://127.0.0.1:$openbao_port" \
  --bao-ca "$openbao_state_root/tls/ca.crt" \
  --root-token-file "$openbao_state_root/root.token" \
  --org-id "$MARTY_ORG_ID" --org-slug "$MARTY_ORG_SLUG" \
  --did "$SELFHOST_ISSUER_DID" --output "$audit_identity_root"
# Later audit token refresh requires --refresh-token --identity-root
# "$audit_identity_root" with the same org, slug, DID, state, output and project.
# Before retiring the bootstrap root, check_selfhost_root_retirement.py now
# requires --evidence-identity, --audit-identity and
# --snapshot-rotator-identity as well as the existing renewal and snapshot
# identities. Supply --audit-org-id "$MARTY_ORG_ID",
# --audit-org-slug "$MARTY_ORG_SLUG" and --audit-did "$SELFHOST_ISSUER_DID"
# so it checks the live audit role against the exact seeded read policy.
python3 "$source_root/scripts/run_selfhost_business_journey.py" \
  --archive "$prepared/prepared-selfhost-bundle.zip" \
  --image-lock "$prepared/prepared-selfhost-images.json" \
  --transaction "$prepared/selfhost-preparation-transaction.json" \
  --receipt "$prepared/prepared-selfhost-bundle.json" \
  --descriptor "$prepared/prepared-selfhost-product-descriptor.json" \
  --install-root "$install_root" --state-root "$state_root" \
  --openbao-state-root "$openbao_state_root" --openbao-project "$openbao_project" \
  --secret-root "$secret_root" --env-file "$env_file" \
  --source-checkout "$source_root" --integration-checkout "$integration_root" \
  --compose-model "$private/compose-model.json" \
  --source-sha "$source_sha" --run-id "$run_id" \
  --integration-sha 5b3ec6a802a5e13201be8883741889405a86d146 \
  --project-name "$project" --fixture-setup "$fixture" \
  --fixture-setup-sha256 "$fixture_sha" \
  --kms-custody-evidence "$private/custody.json" \
  --kms-custody-signature "$private/custody.sig" \
  --kms-custody-public-key "$private/custody.pub" \
  --output "$private/installed-journey.json" \
  --diagnostic-output "$private/installed-diagnostic.json"
```

The separate diagnostic file is written on success or ordinary runner failure
and contains fixed phase names, durations, the first failed phase, Linux-visible
CPU/RAM and initial free disk, and sampled host memory/swap high-water marks.
It contains no credentials or test payloads and is always **unqualified**.
Its `checks_result` describes the installed checks, not persistence of the
separate success report; only `installed-journey.json` records a completed
installed run. A diagnostic with passed checks alone is never a handoff pass.
The sampled values can miss short spikes; they do not measure per-container
memory or OOM kills. Retain independent Docker/host observations before
assessing a smaller hardware envelope. Never treat a diagnostic file as the
successful installed-journey report.

The run passes only when all local services reach the reviewed health states,
migrations finish, the KMS-backed synthetic issuer and verifier bind to their
managed keys, and the public test completes login, issue, present, verify,
revoke, and deny. The runner tears down its owned Compose project and volumes
on success or failure; retain the private report and signed custody files for
review. Do not publish a qualified descriptor or attach the ZIP to a public
release based solely on this component report. Signature/provenance checks,
public asset closure, independent consumer replay, and release publication
remain separate gates.
By default the runner builds `public-kms-jwk` from the clean, exact release
checkout into a fresh temporary Cargo home and target before startup. The host
needs access to the locked Rust dependencies; ambient Cargo/compiler overrides
and existing converter binaries are not accepted as custody evidence.

Every Stack release producer now retains the **already exercised**
release-mode converter and an exact-byte receipt with their two exact SLSA
bundles for seven days. This is a temporary producer bridge, not a qualified
public asset or proof of reproducible compilation. A local admission verifier
checks the protected producer run through the public GitHub API, both local
verified certificate run identities, the receipt, and the Ubuntu 24.04 loader
and dependencies plus a bounded smoke test. `--public-kms-helper-dir` is an
experimental opt-in for an exact four-file public preview companion alongside
the prepared assets. It copies only those four files into owned private scratch;
an invalid supplied companion fails rather than falling back to source build.
It does not turn the helper into a qualified release asset: the current public
release closure does not publish this companion, so ordinary testers still use
the default fresh build. Anonymous bundle verification needs network access;
the admission is limited to Ubuntu 24.04 amd64 and does not claim portable or
offline compatibility. Public preview publication must separately bind the
companion to the prepared source/run; never use an ambient binary.


### Immutable installer metadata endpoints

The consumer bootstrap leaves the original version release's exact asset set
unchanged. For version `vX.Y.Z` (including a nightly suffix), it downloads the
admission subject `installer-admission.json` and its `.sigstore.json` and
`.provenance.jsonl` sidecars from the separate GitHub Release tag
`installer-admission-vX.Y.Z`. The signed record still binds the original version,
inventory, operator, and successful staged/published acceptance. Payloads continue
to come from the original version release. Publishing these metadata releases is
not implemented by the consumer endpoint change.

Channel selection reads one unsigned routing pointer from
`https://raw.githubusercontent.com/ElevenID/marty-ui/installer-channel/nightly.json`
(or `stable.json`). The branch is `refs/heads/installer-channel`. Its closed JSON
fields are `schema` (`elevenid.installer-channel-pointer/v1`), `repository`
(`ElevenID/marty-ui`), `channel`, positive integer `generation` below 2^53, and
`record_sha256` (lowercase SHA-256 of the exact signed channel record bytes).
The consumer derives the metadata release tag
`installer-channel-<channel>-<generation>` and downloads `installer-channel.json`
and its two signature/provenance sidecars from that immutable release. No URL
from pointer content is followed.

The pointer grants no authority. Channel signatures, exact promotion invocation,
expiry, channel/version tier, generation, record hash, admission hash, and source
binding remain required. The bootstrap reads the pointer again before executing
the authenticated operator and refuses if its exact bytes changed. Publishers
must upload and verify immutable channel metadata first, then compare-and-swap
the branch commit containing the pointer; they must never replace release assets.
A failed compare-and-swap requires reconciliation rather than overwriting a newer
pointer. No pointer branch or metadata release is created by this implementation.
A fresh consumer cannot infer the globally newest generation from an unsigned
pointer alone: replay of an older correctly signed, still-valid channel remains
bounded by its expiry. This change does not claim global rollback prevention.

The protected `installer-publish-admission.yml` workflow publishes only the
separate admission metadata release after the gate archives its verified
triplet. Before any release write, it requires immutable releases to be enabled.
The `stack-release` environment must provide
`INSTALLER_REPOSITORY_POLICY_TOKEN` with repository Administration:read solely
for that fixed policy GET; the workflow token handles metadata release writes.
An interrupted draft is retained for review and is never automatically adopted
or overwritten. This publisher does not create channel metadata or update the
pointer. Creating its tag at the original promotion commit may require GitHub
Workflows permission if that commit's workflow files differ from current main;
a refusal must be investigated rather than changing the tag target or widening
credentials silently.


### Mandatory version promotion and channel publication

Once a channel has a published signed admission and has passed post-promotion
one-line qualification, the intended Linux amd64 command is:

```sh
curl -fsSL https://raw.githubusercontent.com/ElevenID/marty-ui/main/install.sh | sh -s -- --channel nightly
```

Use `--channel stable` for the stable channel. This command is a release target,
not a claim that either channel is ready today; the bootstrap refuses missing or
unqualified GitHub metadata. It checks a terminal marker so a truncated piped
download cannot start an installation.

An installer version is not promoted by a successful build or candidate-grant workflow. The required sequence is the exact version's real staged installed acceptance and anonymous published replay (all 23 cases and the 32 GiB host policy), signed admission through `installer-promote.yml` operation `admission`, publication of its separate immutable admission release, then `installer-promote.yml` operation `channel`, followed by `installer-publish-channel.yml`. The channel operation only consumes authenticated published admission and cannot create one. Existing version payload releases are never modified.

The channel signing archive contains the channel triplet and a separately signed publication-context triplet. The context fixes the observed `installer-channel` branch commit and prior pointer hash. The publisher revalidates admission, predecessor signatures and invocation identities, publishes only the three channel files to immutable `installer-channel-<channel>-<generation>`, and creates a single-parent Git commit preserving the other channel pointer. Reference publication uses non-force update (or exclusive initial creation); a changed head, failed update or uncertain response retains immutable metadata and recovery evidence. Do not force, automatically retry, adopt a draft, or regenerate an older expected-head context. Same-version freshness renewal is deliberately not wired: it requires a separately reviewed fresh public replay.

Before enabling publication, an administrator must configure effective branch rules for `installer-channel` prohibiting deletion and non-fast-forward updates while permitting the authorized publisher's normal fast-forward writes. The publisher reads effective rules and refuses if either restriction is missing. The protected `stack-release` environment and existing read-only `INSTALLER_REPOSITORY_POLICY_TOKEN` remain required; the helper does not change repository policy. Published immutable releases protect their metadata tags and assets; matching metadata-tag update/deletion rules may add defense in depth. No policy, secret or release is configured by this implementation.

These are implemented publication gates, not evidence that a real version has passed acceptance or a channel has been published. The published pre-admission replay path still requires an explicitly acceptance-only authenticated public-fetch execution path: the normal one-line consumer requires admission and cannot be used to produce its own prerequisite report. Grant-only runs must continue to fail admission. After admission, normal one-line consumption requires its own qualification. A 4 GiB engineering VM cannot satisfy the 32 GiB release gate.


### Opt-in real controller probe checkpoints

`installer-acceptance.yml` keeps grant-only behavior by default. With `execute: true`, the same invocation archives its signed execution grants, waits for the approved numeric controller principal to return `installer-acceptance-checkpoint.json` on the existing owned draft transport, verifies its exact run/attempt/nonce/guest/Engine/inventory/consumption binding, and signs a distinct checkpoint triplet. The artifact is named `installer-incomplete-checkpoint-<run>-<attempt>`, never either accepted staged/published report name. The job then fails explicitly because installed acceptance is incomplete. No checkpoint is accepted by the admission gate.

The controller runs `scripts/installer_acceptance_runner.py` with the same explicit private inputs and pinned SSH options as `installer_candidate_dispatch.py`, plus a fresh private `--output` directory. It performs the real signature/provenance checks, sends the reviewed standalone read-only host probe to guest Python without a source checkout or controller credentials, requires the exact Engine and initial empty Docker state with at least 32 GiB guest-visible/daemon RAM and 20 GiB Docker-filesystem space, then invokes the existing native candidate dispatch. Host observations are preserved before dispatch. They do not establish exhaustive source/credential absence. A 4 GiB VM is refused before installation and produces an incomplete checkpoint.

The runner always exits nonzero after preserving its checkpoint; a native zero exit still cannot imply that the unimplemented browser/business/restart/cleanup probes passed. All 23 case entries are fixed by code, with only actual cryptographic artifact verification implemented as passed. Do not replace blocked entries manually. Upload only the nonsecret checkpoint to the descriptor's exact draft using the already approved controller identity; preserve local host observations and all guest recovery data. The transport records the approved uploader and exact bytes before signing, does not create a new authorization, does not retry dispatch, and does not delete remote or guest resources.

This first runnable path is staged-only. Anonymous pre-admission published acquisition and all remaining fixed installed probes are outstanding. The normal one-line consumer is a separate post-admission qualification; it cannot supply its own prerequisite report. A full acceptance schema/report is deliberately not emitted by these helpers.

### Read-only public trust information

After the native application startup has written a complete locked local receipt, `marty-deploy trust-info --install-dir ABSOLUTE_PATH` can print a JSON record containing the fixed localhost HTTPS origin, public CA certificate, DER SHA-256 fingerprint, expiry times and hashes of the retained startup evidence. It validates the recorded generation selection, original public certificate bytes, certificate chain/SANs and exact startup identities before output. The command makes no network or Docker call, imports nothing into a host/browser trust store and does not resume provisioning. `runtime_observed`, `host_trust_observed`, `host_trust_modified` and `installation_ready` remain false; browser trust, business journey, renewal/root retirement and recovery are still pending. Use the fingerprint to review the public CA before any explicit trust decision. An incomplete or expired local record is refused, not repaired automatically.

The controller's incomplete acceptance checkpoint v2 may retain `installer-status-observation.json` and `installer-trust-info-observation.json` after candidate dispatch. It invokes the pinned operator over the already authenticated SSH route, binds the acceptance-only journal and guest nonce-consumption digest to the exact candidate, and requires identical status bytes before and after the public trust export. The checkpoint hashes both records only when the native inspection succeeds; otherwise it records `trust_inspection: unavailable`. These are historical, read-only startup and certificate observations. They do not prove live TLS, browser trust or login and cannot satisfy any of the blocked installed-journey cases.

Native `fetch_published_inputs` is a library-only preparation stage for an acceptance-only published replay. It requires a signed published-phase authorization, then anonymously downloads the exact version's inventory, four installer payloads and their ten signature/provenance sidecars over the fixed GitHub release transport. It binds every original download receipt to the same private bytes used for verification and retains partial files on failure. No published dispatch calls it yet. The future guest bootstrap must itself acquire and authenticate the operator from GitHub before execution, persist acquisition intent and receipts, and run the existing candidate verifier against the downloaded files; a copied operator that merely downloads matching bytes is not bootstrap qualification. This stage grants no admission, installed acceptance or Ready state.
