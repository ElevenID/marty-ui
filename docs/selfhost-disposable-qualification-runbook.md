# Disposable self-host clean-install rehearsal

This procedure runs the exact prepared ZIP on an isolated Linux amd64 host. It
does not qualify or publish the bundle: the runner writes an **unqualified**
component report. Run it only after a signed Stack release was dispatched with
`prepare_selfhost_lock=true` and its independent image digests. The public
release must already identify the same source commit. Do not use production
credentials, a real CSCA/DSC, or a customer organization.

Use a host with at least 32 GiB RAM and 20 GiB free disk for all locked images and
fresh database state, Docker Compose, Python 3.12 with the pinned integration
test dependencies, Rust 1.95.0 with locked Cargo dependencies, OpenSSL, and
anonymous registry access. The host must have
no existing qualification project. Canvas qualification may use the same host
sequentially, after its Docker project and state have been removed. The local
Windows Docker/WSL configuration is not a suitable 32 GiB qualifier.

The 32 GiB figure is the current qualification target, not a memory check in
the installer. A smaller disposable host may be used for an exploratory run
of this same ZIP and journey, but record its physical/VM RAM, CPU, free disk,
peak container and host memory, swap activity, OOM kills, and any failed
health or business step. Keep the result **unqualified** until the complete
journey and custody checks pass, the lower-memory operating envelope is
reviewed, and this qualification target is updated. A Compose render or image
pull alone does not establish a smaller supported minimum.

## Experimental preview installer path

The [v1.1.250 experimental tester preview](https://github.com/ElevenID/marty-ui/releases/tag/v1.1.250-selfhost-preview.1)
has a Linux-only staging helper that verifies all downloaded checksums,
the exact source/receipt lineage and the extracted ZIP, then creates a new
operator-private root with disposable scalar credentials. From a **clean,
matching source checkout**, use an operator-owned `0700` parent and a fresh
child path:

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
sudo python3 scripts/stage_selfhost_keycloak_inputs.py \
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
installed pass. The audit helper does not overwrite an existing token, so
retrying after expiry requires a new disposable OpenBao state and private root.
Also check the effective expiry of workload TLS credentials, which OpenBao may cap,
and complete the journey before the earliest expiration. Do not keep the stack
running afterward. A new session requires teardown and
fresh disposable OpenBao state and secret roots, followed by a new install and
bootstrap. The current helpers deliberately do not rotate live Keycloak or
workload TLS files in place.

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

1. For an external tester, anonymously download all seven assets from the
   [v1.1.250 experimental prerelease](https://github.com/ElevenID/marty-ui/releases/tag/v1.1.250-selfhost-preview.1)
   into one directory: `prepared-selfhost-bundle.zip`,
   `prepared-selfhost-images.json`, `prepared-selfhost-bundle.json`,
   `prepared-selfhost-product-descriptor.json`,
   `selfhost-preparation-transaction.json`, `SELFHOST-PREVIEW-README.md`, and
   `SHA256SUMS`. Keep the original bytes and verify `sha256sum -c SHA256SUMS`
   there. The staging helper checks the same exact set. Release operators may
   separately retain the matching `stack-release-qualified-<RUN_ID>` Actions
   artifact for internal evidence; testers do not need Actions artifact access.
   Its promoted `release-transaction.json` is **not** a substitute for the
   original preparation transaction bound to this ZIP and receipt.
2. Check out the `v1.1.250` source tag in a clean `marty-ui` tree and confirm that
   `git rev-parse HEAD` equals the source commit in the preparation receipt.
   Check out `ElevenID/marty-integration-tests` separately at
   `9c63609250274dc1edcf747827a29728ddd15d4a`. The runner verifies that
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
   [integration contract](https://github.com/ElevenID/marty-integration-tests/blob/9c63609250274dc1edcf747827a29728ddd15d4a/tests/oss_stack/SELFHOST_CUSTOMER_JOURNEY.md)
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
sudo python3 "$source_root/scripts/stage_selfhost_keycloak_inputs.py" \
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
sudo python3 "$source_root/scripts/provision_selfhost_audit_token.py" \
  --endpoint "https://127.0.0.1:$openbao_port" \
  --state-root "$openbao_state_root" --output-root "$secret_root" \
  --org-id "${MARTY_ORG_ID:?Set the seeded organization ID}" \
  --org-slug "${MARTY_ORG_SLUG:?Set the seeded organization slug}" \
  --did "${SELFHOST_ISSUER_DID:?Set the matching issuer DID}" \
  --project-name "$openbao_project"
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
  --integration-sha 9c63609250274dc1edcf747827a29728ddd15d4a \
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
The runner builds `public-kms-jwk` from the clean, exact release checkout into
a fresh temporary Cargo home and target before startup. The host needs access
to the locked Rust dependencies; ambient Cargo/compiler overrides and existing
converter binaries are not accepted as custody evidence.
