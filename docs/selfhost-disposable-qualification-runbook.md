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

## Next-preview installer work in progress

The next preview's Linux-only staging helper verifies all downloaded checksums,
the exact source/receipt lineage and the extracted ZIP, then creates a new
operator-private root with disposable scalar credentials. From a **clean,
matching source checkout**, use an operator-owned `0700` parent and a fresh
child path:

```bash
python3 scripts/stage_selfhost_disposable_preview.py \
  --assets-dir /absolute/path/to/next-preview-assets \
  --source-checkout /absolute/path/to/matching-clean-source \
  --private-root /absolute/path/to/operator-private/new-run
python3 scripts/start_selfhost_disposable_openbao.py \
  --private-root /absolute/path/to/operator-private/new-run \
  --host-port 18200
sudo python3 scripts/stage_selfhost_keycloak_inputs.py \
  --private-root /absolute/path/to/operator-private/new-run
```

The OpenBao helper renders and checks the three-service Compose model before
starting a fresh project. It uses only the locked plugin image, an isolated
state directory and a selected loopback port. The Keycloak bridge runs the
existing remote-key provisioner in a root-owned temporary directory, then
transfers only its seven scoped/public outputs to the private secret root;
the root token remains in the OpenBao state directory. These steps do not
qualify the stack or complete workload TLS, custody or the installed business
journey.
The bridge verifies that the locked, healthy OpenBao container owns the exact
loopback port before contacting it. The Linux host must expose the **same
rootful Docker daemon** to the non-root starter and `sudo` bridge; rootless
Docker contexts are not yet supported by this installer path.
These helpers do **not** make the older `v1.1.247-selfhost-preview.2` image
installable; obtain a newly prepared preview with matching source and images.

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
lifetimes. Seven hours is an upper bound, not a guaranteed operating window:
check the effective expiry of workload TLS credentials, which OpenBao may cap,
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
containing `root.token` and `tls/ca.crt`). Set all four paths/address for
your isolated install; the root token is mode 0400, so the inspection needs
`sudo`:

```bash
source_root=/path/to/clean/release-source
secret_root=/path/to/private/selfhost-secrets
openbao_state_root=/path/to/private/openbao-state
BAO_ADDR="https://127.0.0.1:${SELFHOST_OPENBAO_HOST_PORT:-18200}"
sudo env PYTHONPATH="$source_root/scripts" python3 - "$secret_root" "$openbao_state_root" "$BAO_ADDR" <<'PY'
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
from passport_remote_tls import SELFHOST_CERT_FILES, SELFHOST_TOKEN_FILES
from selfhost_openbao_client import Bao

secret_root, bao_state = map(Path, sys.argv[1:3])
address = sys.argv[3]
if not address.startswith("https://"):
    raise SystemExit("OpenBao endpoint must use HTTPS")
client = Bao(address, bao_state / "tls/ca.crt",
             (bao_state / "root.token").read_text(encoding="ascii").strip())
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

1. From the successful Stack release run, download the unique
   `selfhost-lock-preparation-unqualified-<RUN_ID>` artifact. Keep its original
   `prepared-selfhost-bundle.zip`, `prepared-selfhost-images.json`,
   `prepared-selfhost-bundle.json`, and
   `prepared-selfhost-product-descriptor.json` bytes. Download the matching
   `stack-release-qualified-<RUN_ID>` transaction artifact. A later promoted
   public transaction is **not** a substitute for these preparation bytes.
2. Check out the release tag in a clean `marty-ui` source tree and confirm that
   `git rev-parse HEAD` equals the source commit in the preparation receipt.
   Check out `ElevenID/marty-integration-tests` separately at
   `9c63609250274dc1edcf747827a29728ddd15d4a`. The runner verifies that
   this is a clean protected-main ancestor and selects only the public
   `tests/oss_stack/selfhost_customer_journey.py` test.
3. In a private operator directory outside both repositories, create an empty
   state directory, a secret directory containing every file named by
   `LOCAL_SECRET_NAMES` in `scripts/run_selfhost_business_journey.py`, and a
   Compose env file. Files explicitly marked `allow_empty` in the reviewed
   secret catalog may stay empty only when the rendered Compose settings show
   their integrations are disabled (for example, Google login is off); an
   enabled integration needs non-placeholder material. The
   runner does not start either Cloudflare tunnel, so their two token files
   are not required for this local journey. The full all-profile Compose
   secret declarations and service bindings are still checked unchanged.
   Set `SELFHOST_STATE_DIR`, `SELFHOST_SECRET_DIR`, `MARTY_ORG_ID`,
   `MARTY_ORG_ADMIN_EMAIL`, and `PUBLIC_DOMAIN` before rendering. The admin
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
   `SELFHOST_CUSTODY_SIGNING_KEY_FILE` in the same process environment. The
   Ed25519 private key and token stay outside source and installation; its
   public PEM digest must appear in the **prepared source commit's** reviewed
   `deploy-config/selfhost-kms-custody-trust-roots.json`.

The following commands use absolute, operator-owned paths. They deliberately
leave credential creation and OpenBao bootstrap to the operator; the runner
rejects missing inputs before it can report a pass. Keep the original artifact
names and do not reuse an old state directory.

```bash
set -euo pipefail
source_root=/srv/qualification/marty-ui-release
integration_root=/srv/qualification/marty-integration-tests
prepared=/srv/qualification/prepared
private=/srv/qualification/private
install_root="$private/install/selfhost-prepared"
state_root="$private/state"
secret_root="$private/secrets"
env_file="$private/selfhost.env"
source_sha=$(git -C "$source_root" rev-parse HEAD)
run_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_id"])' \
  "$prepared/prepared-selfhost-bundle.json")

python3 "$source_root/scripts/check_prepared_selfhost_consumer.py" \
  --archive "$prepared/prepared-selfhost-bundle.zip" \
  --image-lock "$prepared/prepared-selfhost-images.json" \
  --transaction "$prepared/release-transaction.json" \
  --receipt "$prepared/prepared-selfhost-bundle.json" \
  --descriptor "$prepared/prepared-selfhost-product-descriptor.json" \
  --expected-source-sha "$source_sha" --expected-run-id "$run_id" \
  --verify-archive-only
mkdir -p "$private/install" "$state_root" "$secret_root"
unzip -q "$prepared/prepared-selfhost-bundle.zip" -d "$private/install"
project="marty-selfhost-qual-$(openssl rand -hex 8)"
fixture="$source_root/scripts/setup_selfhost_synthetic_fixture.py"
fixture_sha=$(sha256sum "$fixture" | cut -d ' ' -f 1)

# The operator secret runner supplies all SELFHOST_* values and the external
# OpenBao audit inputs here. The env file resolves Compose settings, including
# the same absolute state/secret roots and loopback published ports.
docker compose --project-name "$project" --env-file "$env_file" \
  -f "$install_root/docker-compose.yml" --profile '*' config --format json \
  > "$private/compose-model.json"
python3 "$source_root/scripts/run_selfhost_business_journey.py" \
  --archive "$prepared/prepared-selfhost-bundle.zip" \
  --image-lock "$prepared/prepared-selfhost-images.json" \
  --transaction "$prepared/release-transaction.json" \
  --receipt "$prepared/prepared-selfhost-bundle.json" \
  --descriptor "$prepared/prepared-selfhost-product-descriptor.json" \
  --install-root "$install_root" --state-root "$state_root" \
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
