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
   `71a34c96f4bff2911919ebd3a41644ec2631ee07`. The runner verifies that
   this is a clean protected-main ancestor and selects only the public
   `tests/oss_stack/selfhost_customer_journey.py` test.
3. In a private operator directory outside both repositories, create an empty
   state directory, a secret directory containing every non-placeholder secret
   named by `EXPECTED_SECRET_NAMES` in
   `scripts/check_selfhost_installed_runtime_plan.py`, and a Compose env file.
   Set `SELFHOST_STATE_DIR`, `SELFHOST_SECRET_DIR`, `MARTY_ORG_ID`,
   `MARTY_ORG_ADMIN_EMAIL`, and `PUBLIC_DOMAIN` before rendering. The admin
   email must be a synthetic `@selfhost.marty.invalid` address. Use disposable
   workload TLS material and scoped OpenBao tokens. Configure the same
   disposable external OpenBao for the installed `signing-keys` service and the
   audit hook; its audit token must meet the policy and TTL contract in
   [the synthetic fixture guide](selfhost-synthetic-fixture.md).
4. Supply the eight public journey `SELFHOST_*` values from the
   [integration contract](https://github.com/ElevenID/marty-integration-tests/blob/71a34c96f4bff2911919ebd3a41644ec2631ee07/tests/oss_stack/SELFHOST_CUSTOMER_JOURNEY.md)
   through an operator secret runner. Supply `SELFHOST_BAO_AUDIT_URL`,
   `SELFHOST_BAO_AUDIT_TOKEN_FILE`, and
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
  --integration-sha 71a34c96f4bff2911919ebd3a41644ec2631ee07 \
  --project-name "$project" --fixture-setup "$fixture" \
  --fixture-setup-sha256 "$fixture_sha" \
  --kms-custody-evidence "$private/custody.json" \
  --kms-custody-signature "$private/custody.sig" \
  --kms-custody-public-key "$private/custody.pub" \
  --output "$private/installed-journey.json"
```

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
