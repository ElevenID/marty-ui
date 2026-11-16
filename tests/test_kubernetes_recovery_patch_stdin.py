"""Exercise the patch helpers through real pipes and ordinary patch-file reads.

The offline child mirrors kubectl's os.ReadFile(PatchFile) boundary. It does not
contact Kubernetes or treat a literal '-' filename as standard input.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import bootstrap_kubernetes_openbao as bootstrap
import recover_kubernetes_legacy_credentials as recovery
import reload_kubernetes_legacy_workloads as reload


pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux private recovery transport")

FILE_READING_CLIENT = '''\
import json
from pathlib import Path
import sys
import time

record, response, *arguments = sys.argv[1:]
with Path(record).open("a", encoding="utf-8") as output:
    output.write(json.dumps(arguments) + "\\n")
patch_file, = [argument.split("=", 1)[1] for argument in arguments if argument.startswith("--patch-file=")]
try:
    patch = Path(patch_file).read_bytes()
except OSError:
    sys.stderr.write("synthetic patch-file open failed")
    raise SystemExit(1)
assert isinstance(json.loads(patch), list)
if response != "success":
    sys.stdout.buffer.write(b"PRIVATE_PARTIAL_PATCH_REPLY")
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(b"PRIVATE_PATCH_DIAGNOSTIC_AFTER_READ")
    sys.stderr.buffer.flush()
    if response == "timeout":
        time.sleep(10)
    raise SystemExit(7)
sys.stdout.buffer.write(patch)
sys.stderr.buffer.write(b"PRIVATE_SUCCESS_DIAGNOSTIC")
'''


def patch_process(tmp_path: Path, owner: str, response: str = "success") -> SimpleNamespace:
    client = tmp_path / "file-reading-kubectl.py"
    client.write_text(FILE_READING_CLIENT)
    invocations = tmp_path / "invocations.jsonl"
    base = [sys.executable, str(client), str(invocations), response,
            "--kubeconfig", "/synthetic/private/kubeconfig", "--namespace", "retained-test"]
    marker = "PRIVATE_PATCH_VALUE_" + owner
    patch = [{"op": "test", "path": "/metadata/uid", "value": "retained-uid"},
             {"op": "test", "path": "/metadata/resourceVersion", "value": "123"}]
    if owner == "secret":
        old_data = {"token": base64.b64encode(b"PRIVATE_OLD_TOKEN").decode()}
        patch.extend([{"op": "test", "path": "/data", "value": old_data},
                      {"op": "replace", "path": "/data/token", "value": base64.b64encode(marker.encode()).decode()}])
        output = tmp_path / "evidence"
        bootstrap.private_directory(output)
        destination = output / "response.json"
        transport = SimpleNamespace(base=base)

        def invoke():
            return recovery.capture_patch(transport, "retained-secret", patch, destination, 1 if response == "timeout" else 5)
    else:
        patch.extend([{"op": "test", "path": "/spec/template", "value": {"metadata": {"annotations": {}}}},
                      {"op": "add", "path": "/spec/template/metadata/annotations/recovery", "value": marker}])
        budget = reload.Budget()
        evidence = reload.Evidence(tmp_path / "evidence", budget)
        transport = SimpleNamespace(base=base, budget=budget, evidence=evidence)
        destination = evidence.output / "patch-response-00.json"

        def invoke():
            return reload.captured_patch(transport, "retained-workload", patch, 0, lambda: 1 if response == "timeout" else 5)

    return SimpleNamespace(invoke=invoke, destination=destination, invocations=invocations,
                           payload=bootstrap.encoded(patch), marker=marker)


def assert_private_capture(item, capsys):
    invocations = [json.loads(line) for line in item.invocations.read_text().splitlines()]
    assert len(invocations) == 1
    arguments = invocations[0]
    assert item.marker not in repr(arguments)
    assert base64.b64encode(item.marker.encode()).decode() not in repr(arguments)
    assert not any(argument == "-p" or argument == "--patch" or argument.startswith("--patch=") for argument in arguments)
    assert stat.S_IMODE(item.destination.stat().st_mode) == 0o600
    assert capsys.readouterr() == ("", "")
    return json.loads(item.destination.read_bytes())


@pytest.mark.parametrize("owner", ["secret", "deployment"])
def test_patch_file_reads_exact_stdin_bytes_in_a_real_subprocess(tmp_path, monkeypatch, capsys, owner):
    monkeypatch.chdir(tmp_path)
    item = patch_process(tmp_path, owner)
    existing_files = {path for path in tmp_path.rglob("*") if path.is_file()}

    assert item.invoke() == item.payload

    response = assert_private_capture(item, capsys)
    assert response == {"completed": True, "exitCode": 0, "bounded": True,
                        "stdoutBase64": base64.b64encode(item.payload).decode(),
                        "stderrBase64": base64.b64encode(b"PRIVATE_SUCCESS_DIAGNOSTIC").decode()}
    # Only the call record and the owner's existing opaque response journal are written.
    assert {path for path in tmp_path.rglob("*") if path.is_file()} - existing_files == {
        item.invocations, item.destination,
    }


@pytest.mark.parametrize("owner", ["secret", "deployment"])
@pytest.mark.parametrize("outcome", ["nonzero", "timeout"])
def test_patch_file_failure_retains_opaque_evidence_without_retry(tmp_path, monkeypatch, capsys, owner, outcome):
    monkeypatch.chdir(tmp_path)
    item = patch_process(tmp_path, owner, outcome)

    with pytest.raises(bootstrap.BootstrapError, match="preserve private"):
        item.invoke()

    response = assert_private_capture(item, capsys)
    assert response == {"completed": outcome != "timeout", "exitCode": None if outcome == "timeout" else 7,
                        "bounded": True,
                        "stdoutBase64": base64.b64encode(b"PRIVATE_PARTIAL_PATCH_REPLY").decode(),
                        "stderrBase64": base64.b64encode(b"PRIVATE_PATCH_DIAGNOSTIC_AFTER_READ").decode()}
