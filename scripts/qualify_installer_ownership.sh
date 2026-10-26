#!/usr/bin/env bash
# Source-based component qualification, not clean-host installer acceptance.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $(uname -s) != Linux || $(id -u) == 0 ]]; then
  echo 'Run as an unprivileged Linux developer with passwordless sudo for the test binary.' >&2
  exit 1
fi
build_record=$(mktemp)
trap 'rm -f -- "$build_record"' EXIT
cargo test --offline --locked --manifest-path rust/Cargo.toml \
  -p marty-deployment-catalog --lib --no-run --message-format=json > "$build_record"
python3 - "$build_record" <<'PY'
import json
import pathlib
import subprocess
import sys

records = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
executables = [record["executable"] for record in records
               if record.get("reason") == "compiler-artifact"
               and record.get("executable")
               and record.get("target", {}).get("name") == "marty_deployment_catalog"
               and record.get("profile", {}).get("test")]
if len(executables) != 1:
    raise SystemExit("Expected exactly one compiled library test executable")
test_name = "installer_renewal_bootstrap::tests::root_transfer_enforces_real_recipient_and_other_user_access"
listed = subprocess.run([executables[0], "--exact", test_name, "--ignored", "--list"],
                        check=True, capture_output=True, text=True)
if listed.stdout.splitlines().count(f"{test_name}: test") != 1:
    raise SystemExit("Expected ownership qualification test is missing")
subprocess.run([
    "sudo", "-n", "--", executables[0], "--exact", test_name,
    "--ignored",
], check=True)
PY
