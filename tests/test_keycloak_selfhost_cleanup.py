"""Production demo cleanup must target exact Keycloak email records."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def shell_path(path):
    path = Path(path).resolve()
    if os.name == "nt":
        return "/" + path.drive[0].lower() + path.as_posix()[2:]
    return str(path)


def bash_executable():
    override = os.environ.get("BASH_EXECUTABLE")
    if override:
        return override
    if os.name == "nt":
        git = shutil.which("git")
        candidates = ([Path(git).resolve().parent.parent / "bin/bash.exe"] if git else [])
        candidates.append(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe")
        for candidate in candidates:
            if candidate.is_file():
                return str(candidate)
        raise unittest.SkipTest("Git Bash is required for this shell test on Windows")
    return "bash"

class ProductionDemoCleanupTest(unittest.TestCase):
    def run_cleanup(self, bad_lookup=False, fail_lookup=False, invalid_id=False, extra_field=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "load-secrets-env.sh").write_text("require_secret_var() { :; }\n", encoding="utf-8")
            setup = scripts / "setup-keycloak.sh"
            setup.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            setup.chmod(0o700)
            wrapper = scripts / "wrapper.sh"
            wrapper.write_text(
                (ROOT / "scripts/setup-keycloak-selfhost-production.sh").read_text(encoding="utf-8")
                .replace("/scripts/", shell_path(scripts) + "/"),
                encoding="utf-8",
            )
            stub = scripts / "kcadm.sh"
            stub.write_text("""#!/usr/bin/env bash
set -eu
printf '%s\\n' "$*" >> "$TEST_CALLS"
if [[ "$1" == get ]]; then
    [[ " $* " == *' exact=true '* ]] || exit 71
    [[ "${TEST_FAIL_LOOKUP:-false}" == true ]] && exit 72
    case " $* " in
        *' email=admin@marty.demo '*)
            if [[ "${TEST_INVALID_ID:-false}" == true ]]; then
                echo '------------------------------------,admin@marty.demo'
            elif [[ "${TEST_EXTRA_FIELD:-false}" == true ]]; then
                echo 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa,admin@marty.demo,'
            elif [[ "${TEST_BAD_LOOKUP:-false}" == true ]]; then
                echo 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa,canvas.admin@marty.demo'
            else
                echo 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa,admin@marty.demo'
            fi ;;
        *' email=canvas.admin@marty.demo '*)
            echo 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb,canvas.admin@marty.demo' ;;
    esac
fi
""", encoding="utf-8")
            stub.chmod(0o700)
            calls = root / "calls.txt"
            env = dict(os.environ,
                KCADM_PATH=shell_path(stub),
                KEYCLOAK_ADMIN_PASSWORD="fixture-admin",
                KEYCLOAK_SETUP_STRICT="true",
                MARTY_API_CLIENT_SECRET="fixture-client",
                TEST_CALLS=shell_path(calls),
                TEST_BAD_LOOKUP="true" if bad_lookup else "false",
                TEST_FAIL_LOOKUP="true" if fail_lookup else "false",
                TEST_INVALID_ID="true" if invalid_id else "false",
                TEST_EXTRA_FIELD="true" if extra_field else "false",
            )
            result = subprocess.run([bash_executable(), shell_path(wrapper)],
                                    env=env, capture_output=True, text=True, timeout=15, check=False)
            return result, calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []

    def test_exact_lookup_deletes_both_colliding_demo_emails(self):
        result, calls = self.run_cleanup()
        self.assertEqual(result.returncode, 0, result.stderr)
        deletes = [line for line in calls if line.startswith("delete ")]
        self.assertEqual(len(deletes), 2)
        self.assertIn("users/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", deletes[0])
        self.assertIn("users/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", deletes[1])
        self.assertTrue(all("exact=true" in line for line in calls if line.startswith("get ")))

    def test_lookup_failure_fails_before_delete(self):
        result, calls = self.run_cleanup(fail_lookup=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(line.startswith("delete ") for line in calls))
        self.assertIn("Keycloak demo-user lookup failed", result.stderr)

    def test_invalid_csv_id_or_extra_field_fails_before_delete(self):
        for settings in ({"invalid_id": True}, {"extra_field": True}):
            with self.subTest(settings=settings):
                result, calls = self.run_cleanup(**settings)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(line.startswith("delete ") for line in calls))

    def test_mismatched_lookup_fails_before_delete(self):
        result, calls = self.run_cleanup(bad_lookup=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(line.startswith("delete ") for line in calls))
        self.assertIn("Unexpected Keycloak demo-user lookup result", result.stderr)


if __name__ == "__main__":
    unittest.main()
