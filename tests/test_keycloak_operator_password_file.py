"""Exercise the real setup functions with no Keycloak or network access."""
import os
from pathlib import Path
import subprocess
import sys
import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux secret mount permissions")


def run(tmp_path, body, **env):
    source = (ROOT / "scripts/setup-keycloak.sh").read_text()
    assert source.rstrip().endswith('main "$@"')
    source = source.rsplit('main "$@"', 1)[0] + body
    script = tmp_path / "setup.sh"
    script.write_text(source)
    return subprocess.run(["bash", "-x", str(script)], env={"PATH": os.environ["PATH"], **env}, capture_output=True, text=True, timeout=5)


def secret(tmp_path, data=b'Strong-operator-password!\n', mode=0o444):
    path = tmp_path / "password"
    path.write_bytes(data)
    path.chmod(mode)
    return path


def test_file_password_not_exported_or_traced(tmp_path):
    path = secret(tmp_path)
    result = run(tmp_path, '''load_org_admin_password_file
[[ "$MARTY_ORG_ADMIN_PASSWORD" == 'Strong-operator-password!' ]]
! export -p | grep -q MARTY_ORG_ADMIN_PASSWORD=
''', MARTY_ORG_ADMIN_EMAIL="operator@localhost", MARTY_ORG_ADMIN_PASSWORD_FILE=str(path))
    assert result.returncode == 0, result.stderr
    assert "Strong-operator-password" not in result.stdout + result.stderr


@pytest.mark.parametrize("data", [b"", b"a\nb", b"a\n\n", b"a\x00b", b"a\rb", b"a\tb", b"a" * 4097])
def test_invalid_bytes_refused_before_network(tmp_path, data):
    path = secret(tmp_path, data)
    result = run(tmp_path, 'main\n', MARTY_ORG_ADMIN_EMAIL="operator@localhost", MARTY_ORG_ADMIN_PASSWORD_FILE=str(path))
    assert result.returncode != 0
    assert "Keycloak Setup Starting" not in result.stdout


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "writable", "executable", "conflict", "noemail"])
def test_unsafe_file_and_ambiguous_request_refused(tmp_path, kind):
    path = secret(tmp_path)
    env = {"MARTY_ORG_ADMIN_EMAIL": "operator@localhost"}
    if kind == "symlink":
        link = tmp_path / "link"
        link.symlink_to(path)
        path = link
    elif kind == "hardlink":
        os.link(path, tmp_path / "link")
    elif kind == "fifo":
        path.unlink()
        os.mkfifo(path)
    elif kind == "writable":
        path.chmod(0o666)
    elif kind == "executable":
        path.chmod(0o744)
    elif kind == "conflict":
        env["MARTY_ORG_ADMIN_PASSWORD"] = "conflicting-direct-value"
    elif kind == "noemail":
        env.clear()
    result = run(tmp_path, 'main\n', MARTY_ORG_ADMIN_PASSWORD_FILE=str(path), **env)
    assert result.returncode != 0
    assert "Keycloak Setup Starting" not in result.stdout


@pytest.mark.parametrize("exit_code", [0, 1])
def test_password_reset_uses_private_file_and_removes_it(tmp_path, exit_code):
    path = secret(tmp_path)
    stub = tmp_path / "kcadm"
    record = tmp_path / "record"
    stub.write_text('''#!/usr/bin/env bash
for arg in "$@"; do
    [[ "$arg" != *Strong-operator-password* ]] || exit 90
done
while [[ "$1" != -f ]]; do shift; done
shift
[[ "$(stat -c %a "$1")" == 600 ]] || exit 91
grep -q 'Strong-operator-password!' "$1" || exit 92
printf '%s' "$1" > "$RECORD"
cat "$1"
cat "$1" >&2
exit "$STUB_EXIT"
''')
    stub.chmod(0o700)
    result = run(tmp_path, '''load_org_admin_password_file
find_user_id_by_email() { echo owned-user; }
grant_realm_role_to_user() { :; }
ensure_marty_org_admin_user
''', MARTY_ORG_ADMIN_EMAIL="operator@localhost", MARTY_ORG_ADMIN_PASSWORD_FILE=str(path), KCADM_PATH=str(stub), RECORD=str(record), STUB_EXIT=str(exit_code))
    assert result.returncode == exit_code, result.stderr
    assert "Strong-operator-password" not in result.stdout + result.stderr
    assert not Path(record.read_text()).exists()


def test_absent_file_preserves_direct_password(tmp_path):
    result = run(tmp_path, 'load_org_admin_password_file\n[[ "$MARTY_ORG_ADMIN_PASSWORD" == existing ]]\n', MARTY_ORG_ADMIN_PASSWORD="existing")
    assert result.returncode == 0
