"""Exercise actual PowerShell/native argv and expected-failure handling."""
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('mode', ['ready', 'reject'])
def test_readiness_preserves_ca_argument_and_nonzero_probe_does_not_throw(tmp_path, mode):
    shell = shutil.which('powershell') or shutil.which('pwsh')
    if not shell:
        pytest.skip('PowerShell is unavailable')
    child = tmp_path / 'controlled.py'
    child.write_text("import json,sys\nprint(json.dumps(sys.argv[1:]))\n"
                     "if sys.argv[1]=='reject':\n print('expected startup failure',file=sys.stderr)\n sys.exit(9)\n",
                     encoding='utf8')

    def quote(path):
        return "'" + str(path).replace("'", "''") + "'"

    harness = tmp_path / 'run.ps1'
    harness.write_text(f"""$ErrorActionPreference='Stop'
. {quote(ROOT / 'scripts/beta-native-probes.ps1')}
function docker {{ & {quote(sys.executable)} {quote(child)} @args }}
$probe=Invoke-BetaDockerReadinessProbe -Arguments @('{mode}', '-address=https://127.0.0.1:8200', '-ca-cert=/tmp/bao-tls/vault-ca.pem')
if ($ErrorActionPreference -cne 'Stop') {{ throw 'Probe changed caller error policy' }}
$probe | ConvertTo-Json -Depth 5
""", encoding='utf8')
    result = subprocess.run([shell, '-NoProfile', '-File', str(harness)],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    probe = json.loads(result.stdout)
    assert probe['exit_code'] == (9 if mode == 'reject' else 0)
    argv = next(json.loads(line) for line in probe['output'] if line.startswith('['))
    assert argv == [mode, '-address=https://127.0.0.1:8200', '-ca-cert=/tmp/bao-tls/vault-ca.pem']
