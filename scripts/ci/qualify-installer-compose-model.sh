#!/usr/bin/env bash
# Source-package/config-only gate. No daemon access, image pulls or release
# authentication. Keep this installer 5.6.1 pin separate from other renderers.
set -euo pipefail
[[ $# == 1 && "$1" == /* && -d "${RUNNER_TEMP:?RUNNER_TEMP is required}" ]]
installer_target_dir="$1"
installer_source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$installer_source_root"
umask 077
installer_gate_dir="$(mktemp -d "$RUNNER_TEMP/installer-compose-gate.XXXXXXXX")"
printf 'Installer Compose config evidence: %s\n' "$installer_gate_dir"
case "$(uname -s):$(uname -m)" in
  Linux:x86_64)
    installer_compose_arch=x86_64
    installer_compose_sha=47737f4236e6d3ccea7291995203f8f018058783b4c3a9469119811a0b5db8c0
    ;;
  Linux:aarch64)
    installer_compose_arch=aarch64
    installer_compose_sha=42cfa75f51ad0ccf290bad37899e0038a8c10a0069e85233ecc1d53e3ff1347d
    ;;
  *) echo 'Unsupported installer Compose gate platform' >&2; exit 1 ;;
esac
installer_compose="$installer_gate_dir/docker-compose"
curl --fail --location --silent --show-error --retry 3 \
  --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 120 \
  --output "$installer_compose" \
  "https://github.com/docker/compose/releases/download/v5.6.1/docker-compose-linux-$installer_compose_arch"
printf '%s  %s\n' "$installer_compose_sha" "$installer_compose" | sha256sum --check --strict
chmod 700 "$installer_compose"
installer_compose_version="$("$installer_compose" version --short)"
[[ "${installer_compose_version#v}" == 5.6.1 ]]
export MARTY_INSTALLER_COMPOSE_EXECUTABLE="$installer_compose"
export CARGO_TERM_COLOR=never
for installer_case in \
  native_filtering_merge_and_restart_layer_semantics \
  packaged_source_installer_layers_keep_native_dependencies_and_exclude_setup_on_restart; do
  installer_log="$installer_gate_dir/$installer_case.log"
  set +e
  cargo test --locked --manifest-path rust/Cargo.toml --target-dir "$installer_target_dir" \
    -p marty-deployment-catalog --test installer_compose_native -- \
    --ignored --exact "$installer_case" --test-threads=1 --color never 2>&1 | tee "$installer_log"
  installer_status=("${PIPESTATUS[@]}")
  set -e
  [[ "${installer_status[0]}" == 0 && "${installer_status[1]}" == 0 ]] || exit 1
  # Cargo/libtest exits zero for an unknown exact filter. Require this case and
  # exactly one passing, nonignored test, independently for both invocations.
  python3 - "$installer_log" "$installer_case" <<'PY'
import re
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
if lines.count(f"test {sys.argv[2]} ... ok") != 1:
    raise SystemExit("required native case did not pass")
summaries = [line for line in lines if line.startswith("test result: ")]
if len(summaries) != 1 or not re.fullmatch(
    r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; "
    r"\d+ filtered out; finished in .+", summaries[0]
):
    raise SystemExit("native case selection was empty or incomplete")
PY
done
